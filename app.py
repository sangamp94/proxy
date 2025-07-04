# app.py
from flask import Flask, request, redirect, render_template, session, url_for, send_file, abort
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os
import logging

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change in production
DB = 'database.db'
MAX_DEVICES = 4

logging.basicConfig(level=logging.INFO)

# ----- DB SETUP -----
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
                        token TEXT PRIMARY KEY,
                        expiry TEXT,
                        banned INTEGER DEFAULT 0
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (
                        token TEXT,
                        ip TEXT,
                        UNIQUE(token, ip)
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
                        timestamp TEXT,
                        ip TEXT,
                        token TEXT,
                        user_agent TEXT,
                        referrer TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        stream_url TEXT,
                        logo_url TEXT
                    )''')

init_db()

# ----- AUTH -----
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

# ----- ADMIN PANEL -----
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
                c.execute('INSERT OR REPLACE INTO tokens(token, expiry) VALUES (?, ?)', (token, expiry))
                conn.commit()
            elif 'add_channel' in request.form:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)',
                          (request.form['name'], request.form['stream'], request.form['logo']))
                conn.commit()

        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = []
        for t in tokens:
            c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (t[0],))
            ip_count = c.fetchone()[0]
            token_data.append((t[0], t[1], ip_count, t[2]))
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/action/<token>/<action>')
@login_required
def token_action(token, action):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if action == 'delete':
            c.execute('DELETE FROM tokens WHERE token = ?', (token,))
            c.execute('DELETE FROM token_ips WHERE token = ?', (token,))
        elif action == 'reset':
            c.execute('DELETE FROM token_ips WHERE token = ?', (token,))
        elif action == 'renew':
            new_expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
            c.execute('UPDATE tokens SET expiry = ? WHERE token = ?', (new_expiry, token))
        elif action == 'ban':
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/delete_channel/<int:id>')
@login_required
def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

# ----- PLAYLIST -----
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    ref = request.referrer or ''
    now = datetime.utcnow()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,))
        result = c.fetchone()
        if not result:
            return abort(403, 'Invalid Token')
        expiry, banned = result
        try:
            expiry_time = datetime.fromisoformat(expiry)
        except ValueError:
            return abort(500, 'Invalid expiry format')

        if banned or expiry_time < now:
            return abort(403, 'Token Expired or Banned')

        # Device limit check
        c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,))
        count = c.fetchone()[0]
        c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip))
        exists = c.fetchone()
        if not exists:
            if count >= MAX_DEVICES:
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        # Log access
        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (now.isoformat(), ip, token, ua, ref))

        # Fetch channels
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        conn.commit()

    # Generate playlist
    lines = ['#EXTM3U']
    for name, url, logo in channels:
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(url)
    return '\n'.join(lines), 200, {'Content-Type': 'application/x-mpegURL'}

@app.route('/unlock', methods=['GET'])
def unlock():
    return render_template('unlock.html')

if __name__ == '__main__':
    # Avoid debug=True for environments that may not support multiprocessing (e.g. sandboxed or minimal containers)
    app.run(debug=False, port=5000)
