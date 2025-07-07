# main.py (Full Fixed IPTV Proxy App with Admin Panel Features)

from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time, io

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # seconds

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
        conn.commit()


init_db()


def is_sniffer(ip, ua):
    ua = ua.lower()
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
            elif 'renew_token' in request.form:
                token = request.form['renew_token'].strip()
                new_expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
                c.execute('UPDATE tokens SET expiry = ? WHERE token = ?', (new_expiry, token))
            elif 'delete_ip' in request.form:
                ip = request.form['delete_ip'].strip()
                c.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
            elif 'add_channel' in request.form:
                name = request.form['name']
                stream = request.form['stream']
                logo = request.form['logo']
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, stream, logo))
        conn.commit()

        tokens = c.execute('SELECT * FROM tokens').fetchall()
        token_data = []
        for t in tokens:
            token_str, expiry, banned, created_by = t
            device_count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token_str,)).fetchone()[0]
            token_data.append((token_str, expiry, device_count, banned, created_by))

        logs = c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50').fetchall()
        channels = c.execute('SELECT * FROM channels').fetchall()
        blocked_ips = c.execute('SELECT * FROM blocked_ips').fetchall()

    return render_template('admin.html', tokens=token_data, logs=logs, channels=channels, blocked_ips=blocked_ips)


@app.route('/admin/download_playlist')
@login_required
def download_playlist():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
    m3u = ['#EXTM3U']
    for name, url, logo in channels:
        m3u.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        m3u.append(url)
    return Response('\n'.join(m3u), mimetype='application/x-mpegURL',
                    headers={"Content-Disposition": "attachment; filename=playlist.m3u"})


@app.route('/admin/unban/<token>')
@login_required
def unban_token(token):
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE tokens SET banned = 0 WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')


@app.route('/admin/delete_token/<token>')
@login_required
def delete_token(token):
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM tokens WHERE token = ?", (token,))
        conn.execute("DELETE FROM token_ips WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')


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
        conn.commit()
        if not valid:
            return abort(403, reason)

        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()

    m3u = ['#EXTM3U']
    for name, url, logo in channels:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip()))
        proxy_url = f"https://{request.host}/stream/{uid}?token={token}"
        m3u.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        m3u.append(proxy_url)
    return Response('\n'.join(m3u), mimetype='application/x-mpegURL')


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
