# FULL IPTV APP WITH TOKEN, DEVICE LIMIT, SNIFFER DETECTION, HLS+DASH PROXY
from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ott', 'navigator', 'ott navigator', 'ottnavigator', 'tivimate', 'linux', 'android', 'test']

# ---------------- INIT DB ---------------- #
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (
            token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY, unblock_time REAL)''')
init_db()

# ---------------- AUTH ---------------- #
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrap

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

# ---------------- ADMIN PANEL ---------------- #
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
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (
                    request.form['name'], request.form['stream'], request.form['logo']))
            elif 'upload_m3u' in request.form and 'm3ufile' in request.files:
                m3ufile = request.files['m3ufile']
                if m3ufile.filename.endswith('.m3u'):
                    parse_m3u_lines(m3ufile.read().decode('utf-8').splitlines(), c)
            elif 'm3u_url' in request.form:
                try:
                    url = request.form['m3u_url'].strip()
                    res = requests.get(url, headers={'User-Agent': 'Mozilla'}, timeout=10, verify=False)
                    if res.ok:
                        parse_m3u_lines(res.text.splitlines(), c)
                except Exception as e:
                    print('[M3U URL ERROR]', e)
        conn.commit()
        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        logs = c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').fetchall()
        channels = c.execute('SELECT * FROM channels').fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_channel/<int:id>')
@login_required
def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

# ---------------- PARSER ---------------- #
def parse_m3u_lines(lines, c):
    name, logo = None, ''
    for line in lines:
        if line.startswith('#EXTINF:'):
            try:
                parts = line.split(',', 1)
                name = parts[1].strip()
                logo_part = line.split('tvg-logo="')
                logo = logo_part[1].split('"')[0] if len(logo_part) > 1 else ''
            except:
                continue
        elif line.startswith('http'):
            url = line.strip()
            if name and url:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, url, logo))
                name, logo = None, ''

# ---------------- SECURITY ---------------- #
def is_sniffer(ip, ua):
    ua = ua.lower()
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_block(c, ip, token, ua, ref):
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, time.time() + BLOCK_DURATION))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

# ---------------- PLAYLIST ---------------- #
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if c.execute("SELECT 1 FROM blocked_ips WHERE ip=? AND unblock_time > ?", (ip, time.time())).fetchone():
            return render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403
        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403)
        if not c.execute('SELECT 1 FROM token_ips WHERE token=? AND ip=?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token=?', (token,))
                return abort(403, 'Max devices reached')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        channels = c.execute('SELECT name, stream_url, logo_url FROM channels').fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
        proxy = f'https://{request.host}/stream?token={token}&channelid={uid}'
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(proxy)

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

# ---------------- STREAM ---------------- #
@app.route('/stream')
def stream():
    token = request.args.get('token')
    channelid = request.args.get('channelid')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if c.execute("SELECT 1 FROM blocked_ips WHERE ip=? AND unblock_time > ?", (ip, time.time())).fetchone():
            return render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, request.referrer or '')
            conn.commit()
            return render_template('sniffer_blocked.html'), 403
        row = c.execute('SELECT expiry, banned FROM tokens WHERE token=?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403)
        if not c.execute('SELECT 1 FROM token_ips WHERE token=? AND ip=?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token=?', (token,))
                return abort(403)
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
        c.execute('SELECT name, stream_url FROM channels')
        for name, url in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url)) == channelid:
                try:
                    base_url = url.rsplit('/', 1)[0]
                    r = requests.get(url, headers={'User-Agent': 'Mozilla'}, timeout=10)
                    r.raise_for_status()
                    output = []
                    for line in r.text.splitlines():
                        if line.startswith('#'):
                            output.append(line)
                        elif line.strip().endswith(('.m3u8', '.ts', '.mpd', '.m4s')):
                            full_url = f'{base_url}/{line}' if not line.startswith('http') else line
                            proxy = f'/segment?token={token}&channelid={channelid}&url={full_url}'
                            output.append(proxy)
                        else:
                            output.append(line)
                    return Response('\n'.join(output), mimetype='application/vnd.apple.mpegurl')
                except Exception as e:
                    print('[Stream Proxy Error]', e)
                    return abort(500)
        return abort(404)

# ---------------- SEGMENT ---------------- #
@app.route('/segment')
def segment():
    url = request.args.get('url')
    if not url:
        return abort(400)
    try:
        r = requests.get(url, headers={'User-Agent': 'Mozilla'}, stream=True, timeout=10)
        ctype = r.headers.get('Content-Type', 'application/octet-stream')
        if url.endswith('.mpd'):
            ctype = 'application/dash+xml'
        elif url.endswith('.m4s'):
            ctype = 'video/iso.segment'
        return Response(stream_with_context(r.iter_content(4096)), content_type=ctype)
    except Exception as e:
        print('[Segment Proxy Error]', e)
        return abort(500)

# ---------------- UNLOCK ---------------- #
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
