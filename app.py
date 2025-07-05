from flask import Flask, request, redirect, render_template, session, abort, Response
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time, urllib.parse

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # 5 minutes

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

# ------------------------ IPTV PLAYLIST ------------------------ #
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    ref = request.referrer or ''
    now = datetime.utcnow()

    sniffers = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman']

    if ua != "test":
        return abort(403, "Unauthorized User-Agent")

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,))
        row = c.fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403

        if any(tool in ua.lower() for tool in sniffers):
            unblock_at = time.time() + BLOCK_DURATION
            c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_at))
            c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                      (now.isoformat(), ip, token or 'unknown', ua, ref))
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,))
        result = c.fetchone()
        if not result:
            return abort(403, 'Invalid Token')
        expiry, banned = result

        try:
            expiry_time = datetime.fromisoformat(expiry)
        except ValueError:
            return abort(500, 'Invalid expiry format')

        if banned:
            return abort(403, 'Token Banned')

        c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,))
        count = c.fetchone()[0]
        c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip))
        exists = c.fetchone()
        if not exists:
            if count >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                return abort(403, 'Device limit exceeded. Token banned.')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (now.isoformat(), ip, token, ua, ref))
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(url)

    return ('\n'.join(lines), 200, {
        'Content-Type': 'application/x-mpegURL',
        'Content-Disposition': f'inline; filename="{token}.m3u"'
    })

@app.route('/logs')
@login_required
def show_logs():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT timestamp, ip, token, user_agent, referrer FROM logs ORDER BY timestamp DESC LIMIT 200')
        rows = c.fetchall()
    return render_template('logs.html', logs=rows)

if __name__ == '__main__':
    app.run(debug=False, port=5000)
