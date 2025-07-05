from flask import Flask, request, redirect, render_template, session, abort, Response
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time, urllib.parse

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300

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

# ------------------------ AUTH DECORATOR ------------------------ #
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper

# ------------------------ LOGIN ------------------------ #
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

# ------------------------ ADMIN PANEL ------------------------ #
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            if 'add_token' in request.form:
                token = request.form['token']
                days = int(request.form['days'])
                expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
                c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)',
                          (token, expiry, 'admin'))
                conn.commit()
            elif 'add_channel' in request.form:
                stream = request.form['stream']
                proxy_url = f"/stream?channel={urllib.parse.quote(stream)}&ua=Denver1769"
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)',
                          (request.form['name'], proxy_url, request.form['logo']))
                conn.commit()
            elif 'upload_m3u' in request.form and 'm3ufile' in request.files:
                m3ufile = request.files['m3ufile']
                if m3ufile.filename.endswith('.m3u'):
                    lines = m3ufile.read().decode('utf-8').splitlines()
                    parse_m3u_lines(lines, c)
                    conn.commit()
            elif 'm3u_url' in request.form:
                try:
                    res = requests.get(request.form['m3u_url'])
                    if res.status_code == 200:
                        lines = res.text.splitlines()
                        parse_m3u_lines(lines, c)
                        conn.commit()
                except: pass

        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = []
        for t in tokens:
            c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (t[0],))
            ip_count = c.fetchone()[0]
            token_data.append((t[0], t[1], ip_count, t[2], t[3]))
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

# ------------------------ M3U PARSER ------------------------ #
def parse_m3u_lines(lines, c):
    name, logo, url = None, '', ''
    for line in lines:
        if line.startswith('#EXTINF:'):
            try:
                parts = line.split(',', 1)
                name = parts[1].strip()
                logo_part = line.split('tvg-logo="')
                if len(logo_part) > 1:
                    logo = logo_part[1].split('"')[0]
                else:
                    logo = ''
            except: continue
        elif line.startswith('http'):
            url = line.strip()
            proxy_url = f"/stream?channel={urllib.parse.quote(url)}&ua=Denver1769"
            if name and url:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, proxy_url, logo))
                name, logo, url = None, '', ''

# ------------------------ STREAM PROXY ------------------------ #
@app.route('/stream')
def stream():
    channel_url = request.args.get('channel')
    user_agent = request.args.get('ua')
    token = request.args.get('token')
    ua = request.headers.get('User-Agent')

    if not channel_url or not token:
        return abort(403)

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,))
        result = c.fetchone()
        if not result:
            return abort(403)
        expiry, banned = result
        if banned or datetime.utcnow() > datetime.fromisoformat(expiry):
            return abort(403)
        c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, request.remote_addr))
        if not c.fetchone():
            c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,))
            if c.fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403)
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, request.remote_addr))
        conn.commit()

    try:
        headers = {'User-Agent': user_agent or ua or 'Mozilla/5.0'}
        r = requests.get(channel_url, headers=headers, stream=True, timeout=10)
        return Response(r.iter_content(chunk_size=1024), content_type=r.headers.get('Content-Type', 'application/octet-stream'))
    except:
        return abort(502)

# ------------------------ UNLOCK ------------------------ #
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
