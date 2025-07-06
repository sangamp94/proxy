from flask import Flask, request, redirect, render_template, session, abort, Response, send_file
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time
from cryptography.fernet import Fernet
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # seconds
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['dalvik', 'ott', 'navigator', 'ott navigator', 'ott-navigator', 'ottnavigator', 'tivimate', 'test']

# ---------------- DB INIT ---------------- #
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            expiry TEXT,
            banned INTEGER DEFAULT 0,
            created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (
            token TEXT,
            ip TEXT,
            UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT,
            ip TEXT,
            token TEXT,
            user_agent TEXT,
            referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            stream_url TEXT,
            logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            unblock_time REAL)''')
init_db()

# -------------- Helpers -------------- #
def is_sniffer(ip, ua):
    ua = ua.lower()
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

def parse_m3u(lines, c):
    name, logo = None, ''
    for line in lines:
        if line.startswith('#EXTINF:'):
            parts = line.split(',', 1)
            name = parts[1].strip()
            logo_part = line.split('tvg-logo="')
            logo = logo_part[1].split('"')[0] if len(logo_part) > 1 else ''
        elif line.startswith('http'):
            url = line.strip()
            if name and url:
                encrypted_url = fernet.encrypt(url.encode()).decode()
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, encrypted_url, logo))
                name, logo = None, ''

# ---------------- Admin routes ---------------- #
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
def admin():
    if 'admin' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            if 'add_token' in request.form:
                token = request.form['token'].strip()
                days = int(request.form['days'])
                expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
                c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'admin'))
            elif 'delete_token' in request.form:
                c.execute('DELETE FROM tokens WHERE token = ?', (request.form['delete_token'],))
            elif 'add_channel' in request.form:
                name = request.form['name']
                stream = request.form['stream']
                logo = request.form['logo']
                encrypted_url = fernet.encrypt(stream.encode()).decode()
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, encrypted_url, logo))
            elif 'm3u_url' in request.form:
                try:
                    url = request.form['m3u_url'].strip()
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    res = requests.get(url, headers=headers, timeout=10, verify=False)
                    if res.status_code == 200 and '#EXTM3U' in res.text:
                        parse_m3u(res.text.splitlines(), c)
                except Exception as e:
                    print("[ERROR]", e)
        conn.commit()
        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_channel/<int:id>')
def delete_channel(id):
    if 'admin' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

# ---------------- Token unlock ---------------- #
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

# ---------------- Playlist generation ---------------- #
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').strip().lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        # Check block
        row = c.execute('SELECT unblock_time FROM blocked_ips WHERE ip = ?', (ip,)).fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403)

        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403)
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)', (datetime.utcnow().isoformat(), ip, token, ua, ref))

        channels = c.execute('SELECT name, stream_url, logo_url FROM channels').fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, encrypted_url, logo in channels:
        try:
            url = fernet.decrypt(encrypted_url.encode()).decode()
            uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
            proxy_url = f'https://{request.host}/stream?token={token}&channelid={uid}'
            lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
            lines.append(proxy_url)
        except:
            continue

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

# ---------------- Proxy stream ---------------- #
@app.route('/stream')
def stream():
    token = request.args.get('token', '').strip()
    channelid = request.args.get('channelid', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        # Block check
        row = c.execute('SELECT unblock_time FROM blocked_ips WHERE ip = ?', (ip,)).fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403)

        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403)
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)', (datetime.utcnow().isoformat(), ip, token, ua, ref))

        # Find channel url by channelid
        for row in c.execute('SELECT stream_url FROM channels'):
            try:
                url = fernet.decrypt(row[0].encode()).decode()
                if str(uuid.uuid5(uuid.NAMESPACE_URL, url)) == channelid:
                    # Proxy the remote stream (handle .m3u8 and .ts)
                    # Detect segment requests
                    if request.query_string:
                        # Pass query strings
                        proxied_url = url + '?' + request.query_string.decode()
                    else:
                        proxied_url = url

                    headers = {'User-Agent': 'Mozilla/5.0'}
                    r = requests.get(proxied_url, headers=headers, stream=True, timeout=10)
                    def generate():
                        for chunk in r.iter_content(chunk_size=4096):
                            if chunk:
                                yield chunk
                    content_type = r.headers.get('Content-Type', 'application/vnd.apple.mpegurl')
                    return Response(generate(), content_type=content_type)
            except:
                continue

    return abort(404)

# ---------------- Run app ---------------- #
if __name__ == '__main__':
    app.run(debug=True, port=5000)
