from flask import Flask, request, redirect, render_template, session, abort, Response
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # seconds
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ott', 'navigator', 'ott navigator', 'ottnavigator', 'test']

# ------------------------ DB INIT ------------------------ #
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

# ------------------------ LOGIN ------------------------ #
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

# ------------------------ ADMIN ------------------------ #
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
                encrypted_url = fernet.encrypt(stream.encode()).decode()
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, encrypted_url, logo))
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
@login_required
def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

# ------------------------ SECURITY ------------------------ #
def is_sniffer(ip, ua):
    if any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS):
        return True
    headers = request.headers
    if 'x-forwarded-for' in headers or 'via' in headers:
        return True
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if any(org in res.text.lower() for org in ['amazon', 'google', 'microsoft', 'ovh']):
            return True
    except:
        pass
    return False

def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

# ------------------------ PLAYLIST ------------------------ #
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').strip().lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
            time.sleep(5)
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403
        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403, 'Invalid or banned token')
        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)', (datetime.utcnow().isoformat(), ip, token, ua, ref))
        channels = c.execute('SELECT name, stream_url, logo_url FROM channels').fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, encrypted_url, logo in channels:
        try:
            url = fernet.decrypt(encrypted_url.encode()).decode()
            uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
            sig = uuid.uuid5(uuid.NAMESPACE_DNS, token + str(int(time.time()) // 300)).hex
            proxy = f'https://{request.host}/stream?token={token}&channelid={uid}&sig={sig}'
            lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
            lines.append(proxy)
        except:
            continue

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

# ------------------------ STREAM ------------------------ #
@app.route('/stream')
def stream():
    token = request.args.get('token', '').strip()
    channelid = request.args.get('channelid', '').strip()
    sig = request.args.get('sig', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()

    expected = uuid.uuid5(uuid.NAMESPACE_DNS, token + str(int(time.time()) // 300)).hex
    if sig != expected:
        return abort(403, 'Invalid or expired signature')

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
            time.sleep(5)
            log_block(c, ip, token, ua, request.referrer or '')
            conn.commit()
            return render_template('sniffer_blocked.html'), 403
        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403, 'Invalid or banned token')
        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
        c.execute('SELECT name, stream_url FROM channels')
        for name, encrypted_url in c.fetchall():
            try:
                url = fernet.decrypt(encrypted_url.encode()).decode()
                if str(uuid.uuid5(uuid.NAMESPACE_URL, url)) == channelid:
                    return redirect(url)
            except:
                continue
        return abort(404, 'Stream not found')

# ------------------------ UNLOCK PAGE ------------------------ #
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
