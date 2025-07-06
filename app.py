from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ottnavigator', 'test', 'vlc', 'tivimate']

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
init_db()

def is_sniffer(ip, ua):
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

def validate_token(c, token, ip):
    row = c.execute("SELECT expiry, banned FROM tokens WHERE token = ?", (token,)).fetchone()
    if not row:
        return False, "Token not found"
    expiry, banned = row
    if banned:
        return False, "Token banned"
    if datetime.fromisoformat(expiry) < datetime.utcnow():
        return False, "Token expired"
    if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
        count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0]
        if count >= MAX_DEVICES:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            return False, "Device limit exceeded"
        c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
    return True, "Valid"

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
    return render_template('login.html')

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
            elif 'm3u_url' in request.form:
                try:
                    res = requests.get(request.form['m3u_url'].strip(), headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
                    if res.status_code == 200:
                        parse_m3u_lines(res.text.splitlines(), c)
                except Exception as e:
                    print(f"[ERROR] M3U fetch failed: {e}")
            conn.commit()

        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_token/<token>')
@login_required
def delete_token(token):
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM tokens WHERE token = ?", (token,))
        conn.execute("DELETE FROM token_ips WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/unban/<token>')
@login_required
def unban_token(token):
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE tokens SET banned = 0 WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/delete_channel/<int:id>')
@login_required
def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

def parse_m3u_lines(lines, c):
    name, logo = None, ''
    for line in lines:
        if line.startswith('#EXTINF:'):
            try:
                parts = line.split(',', 1)
                name = parts[1].strip()
                logo = line.split('tvg-logo="')[1].split('"')[0] if 'tvg-logo="' in line else ''
            except:
                continue
        elif line.startswith('http'):
            url = line.strip()
            if name and url:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, url, logo))
                name, logo = None, ''

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
            return render_template('sniffer_blocked.html'), 403
        elif row:
            c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        valid, reason = validate_token(c, token, ip)
        if not valid:
            conn.commit()
            return abort(403, reason)

        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
        proxy = f"https://{request.host}/stream/{uid}?token={token}"
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
            return render_template('sniffer_blocked.html'), 403
        elif row:
            c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, request.referrer or '')
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        valid, reason = validate_token(c, token, ip)
        if not valid:
            conn.commit()
            return abort(403, reason)

        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                try:
                    res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
                    content_type = res.headers.get('Content-Type', '')
                    if '.m3u8' in url or 'application/vnd.apple.mpegurl' in content_type:
                        playlist_text = res.text
                        new_lines = []
                        for line in playlist_text.splitlines():
                            if line.strip().endswith('.ts'):
                                segment = line.strip().split('/')[-1]
                                proxied = f"https://{request.host}/segment/{channel_id}/{segment}?token={token}"
                                new_lines.append(proxied)
                            elif line.strip().startswith('#') or '.m3u8' not in line:
                                new_lines.append(line)
                            elif line.strip().endswith('.m3u8'):
                                nested = line.strip().split('/')[-1]
                                new_lines.append(f"https://{request.host}/stream/{channel_id}/{nested}?token={token}")
                            else:
                                new_lines.append(line)
                        return Response('\n'.join(new_lines), mimetype='application/x-mpegURL')
                    return Response(res.content, content_type=content_type)
                except:
                    return abort(500, 'Error fetching stream')
        return abort(404, 'Stream not found')

@app.route('/segment/<uuid:channel_id>/<path:segment>')
def segment_proxy(channel_id, segment):
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403
        elif row:
            c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, request.referrer or '')
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        valid, reason = validate_token(c, token, ip)
        if not valid:
            conn.commit()
            return abort(403, reason)

        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                try:
                    base_url = url.rsplit('/', 1)[0]
                    segment_url = f"{base_url}/{segment}"
                    res = requests.get(segment_url, headers={'User-Agent': 'Mozilla/5.0'}, stream=True, timeout=10)
                    return Response(stream_with_context(res.iter_content(1024)), content_type=res.headers.get('Content-Type'))
                except:
                    return abort(500, 'Segment fetch error')
        return abort(404, 'Segment not found')

@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    token = None
    if request.method == 'POST':
        token = uuid.uuid4().hex[:12]
        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
        with sqlite3.connect(DB) as conn:
            conn.execute('INSERT INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'user'))
            conn.commit()
    return render_template('unlock.html', token=token)

@app.route('/not-allowed')
def not_allowed():
    return render_template('not_allowed.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
