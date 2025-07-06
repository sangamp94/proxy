from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context, send_from_directory
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ottnavigator', 'test']

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
init_db()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == 'admin':
            session['admin'] = True
            return redirect('/admin')
        return 'Invalid credentials'
    return '''
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect('/login')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            if 'add_token' in request.form:
                token = request.form['token'].strip()
                days = int(request.form['days'])
                expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
                c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'admin'))
            elif 'add_channel' in request.form:
                name = request.form['name']
                stream = request.form['stream']
                logo = request.form['logo']
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, stream, logo))
            conn.commit()

        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        return f'''
        <h2>Tokens</h2>
        {token_data}<br><br>
        <form method="post">
            Token: <input name="token"> Days: <input name="days" value="30"><input type="submit" name="add_token" value="Add Token">
        </form>
        <h2>Channels</h2>
        {channels}<br><br>
        <form method="post">
            Name: <input name="name"> URL: <input name="stream"> Logo: <input name="logo">
            <input type="submit" name="add_channel" value="Add Channel">
        </form>
        <h2>Logs</h2>
        {logs}
        '''

@app.route('/media/<path:filename>')
def serve_media(filename):
    return send_from_directory('media', filename)

def is_sniffer(ip, ua):
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

def rewrite_master_playlist(content, base_url):
    lines = []
    for line in content.splitlines():
        if line.strip().endswith('.m3u8'):
            lines.append(f"/stream_sub/{line.strip()}")
        else:
            lines.append(line)
    return '\n'.join(lines)

def rewrite_media_playlist(content, base_url):
    lines = []
    for line in content.splitlines():
        if line.startswith("#"):
            lines.append(line)
        elif line.strip().endswith(".ts"):
            lines.append(f"/segment_proxy/{line.strip()}")
        else:
            lines.append(line)
    return '\n'.join(lines)

def is_master_playlist(content):
    return '#EXT-X-STREAM-INF' in content

def fetch_and_rewrite(url, depth=0):
    if depth > 3:
        return "#EXTM3U\n#EXTINF:0,Too many redirects"
    try:
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        content = res.text
        if is_master_playlist(content):
            return rewrite_master_playlist(content, url)
        else:
            return rewrite_media_playlist(content, url)
    except:
        return "#EXTM3U\n#EXTINF:0,Fetch error"

@app.route('/stream_sub/<path:filename>')
def stream_sub(filename):
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return 'Blocked', 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, request.referrer or '')
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            return 'Blocked', 403

    original_url = f"http://localhost:5000/media/{filename}"
    try:
        res = requests.get(original_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        content = res.text
        return Response(rewrite_media_playlist(content, original_url), mimetype='application/x-mpegURL')
    except Exception as e:
        print(f"[ERROR] Could not fetch sub-playlist: {e}")
        return abort(404)

@app.route('/segment_proxy/<path:name>')
def segment_proxy(name):
    try:
        real_segment_url = f"http://localhost:5000/media/{name}"
        res = requests.get(real_segment_url, headers={'User-Agent': 'Mozilla/5.0'}, stream=True, timeout=10)
        return Response(stream_with_context(res.iter_content(1024)), content_type=res.headers.get('Content-Type'))
    except Exception as e:
        print(f"[ERROR] Segment fetch failed: {e}")
        return abort(500)

@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return 'Blocked', 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            return 'Blocked', 403

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403, 'Invalid or banned token')

        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
        proxy = f"http://{request.host}/stream/{uid}?token={token}"
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(proxy)

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

@app.route('/stream/<uuid:channel_id>')
def stream(channel_id):
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return 'Blocked', 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, request.referrer or '')
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            return 'Blocked', 403

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403, 'Invalid or banned token')

        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                rewritten = fetch_and_rewrite(url)
                return Response(rewritten, content_type='application/vnd.apple.mpegurl')
        return abort(404, 'Stream not found')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
