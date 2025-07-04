from flask import Flask, request, redirect, render_template, session, abort, flash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace in production
DB = 'database.db'
MAX_DEVICES = 4

# ----- DB SETUP -----
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
                        token TEXT PRIMARY KEY,
                        expiry TEXT,
                        banned INTEGER DEFAULT 0,
                        created_by TEXT DEFAULT 'admin'
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
                c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'admin'))
                conn.commit()

            elif 'add_channel' in request.form:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)',
                          (request.form['name'], request.form['stream'], request.form['logo']))
                conn.commit()

            elif 'upload_m3u' in request.form and 'm3ufile' in request.files:
                m3ufile = request.files['m3ufile']
                if m3ufile.filename.endswith('.m3u'):
                    lines = m3ufile.read().decode('utf-8').splitlines()
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
                            except:
                                continue
                        elif line.startswith('http'):
                            url = line.strip()
                            if name and url:
                                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)',
                                          (name, url, logo))
                                name, logo, url = None, '', ''
                    conn.commit()

            elif 'upload_m3u_url' in request.form:
                m3u_url = request.form.get('m3u_url')
                if m3u_url:
                    try:
                        response = requests.get(m3u_url)
                        if response.status_code == 200:
                            lines = response.text.splitlines()
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
                                    except:
                                        continue
                                elif line.startswith('http'):
                                    url = line.strip()
                                    if name and url:
                                        c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)',
                                                  (name, url, logo))
                                        name, logo, url = None, '', ''
                            conn.commit()
                    except Exception as e:
                        flash(f"Failed to load URL: {e}", "danger")

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

# ----- NOT ALLOWED PAGE -----
@app.route('/not-allowed')
def not_allowed():
    return render_template('not_allowed.html'), 403

# ----- PLAYLIST -----
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''
    now = datetime.utcnow()

    # Redirect browser-based clients
    browser_keywords = ['mozilla', 'chrome', 'safari', 'edge', 'firefox']
    if any(keyword in ua for keyword in browser_keywords):
        return redirect('/not-allowed')

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

    return (
        '\n'.join(lines),
        200,
        {
            'Content-Type': 'application/x-mpegURL',
            'Content-Disposition': f'attachment; filename="{token}.m3u"'
        }
    )

# ----- UNLOCK PAGE -----
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
    app.run(debug=False, port=5000)
