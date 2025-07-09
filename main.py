from flask import Flask, request, redirect, render_template, session, abort, Response
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4

# SNIFFER and ALLOWED_AGENTS lists have been removed.

# ------------------------ INIT DB ------------------------ #
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
        # The 'blocked_ips' table and related logic have been removed.
init_db()

# ------------------------ AUTH ------------------------ #
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

# ------------------------ ADMIN PANEL ------------------------ #
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

            elif 'upload_m3u' in request.form and 'm3ufile' in request.files:
                m3ufile = request.files['m3ufile']
                if m3ufile.filename.endswith('.m3u'):
                    lines = m3ufile.read().decode('utf-8').splitlines()
                    parse_m3u_lines(lines, c)

            elif 'upload_m3u_url' in request.form:
                try:
                    url = request.form['m3u_url'].strip()
                    res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
                    if res.status_code == 200:
                        parse_m3u_lines(res.text.splitlines(), c)
                except Exception as e:
                    print("M3U Fetch Error:", e) # Log the error for debugging

        conn.commit()
        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT id, name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_channel/<int:id>')
@login_required
def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/delete_all_channels', methods=['POST'])
@login_required
def delete_all_channels():
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels')
        conn.commit()
    return redirect('/admin')

# ------------------------ ADMIN ACTIONS FOR TOKENS ------------------------ #
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
            # Renew for 30 days, adjust as needed
            new_expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
            c.execute('UPDATE tokens SET expiry = ?, banned = 0 WHERE token = ?', (new_expiry, token))
        elif action == 'ban':
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
        elif action == 'unban':
            c.execute('UPDATE tokens SET banned = 0 WHERE token = ?', (token,))
        conn.commit()
    return redirect('/admin')

# ------------------------ M3U PARSER ------------------------ #
def parse_m3u_lines(lines, c):
    name, logo = None, ''
    for line in lines:
        if line.startswith('#EXTINF:'):
            try:
                parts = line.split(',', 1)
                name = parts[1].strip()
                logo_part = line.split('tvg-logo="')
                logo = logo_part[1].split('"')[0] if len(logo_part) > 1 else ''
            except IndexError: # Handle cases where split might fail
                name = None # Reset name to skip this line if parsing fails
                logo = ''
                continue
        elif line.startswith('http'):
            url = line.strip()
            if name and url:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, url, logo))
                name, logo = None, '' # Reset for next channel

# ------------------------ SECURITY (Sniffer related removed) ------------------------ #
# The 'is_sniffer' and 'log_block' functions have been removed.

# ------------------------ M3U PLAYLIST ------------------------ #
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        # Sniffer and blocked IP checks have been completely removed.

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]: # Token not found or is banned
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token or 'invalid/banned', ua, ref))
            conn.commit()
            return abort(403, 'Invalid or banned token')

        # Check token expiry
        expiry_time = datetime.fromisoformat(row[0])
        if datetime.utcnow() > expiry_time:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,)) # Ban expired token
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token + ' (expired)', ua, ref))
            conn.commit()
            return abort(403, 'Token expired')

        # Device limit check
        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                          (datetime.utcnow().isoformat(), ip, token + ' (device limit exceeded)', ua, ref))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        # Log this successful playlist access
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

# ------------------------ STREAM REDIRECT ------------------------ #
@app.route('/stream')
def stream():
    token = request.args.get('token', '').strip()
    channelid = request.args.get('channelid', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or '' # Capture referrer for stream requests

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        # Sniffer and blocked IP checks have been completely removed.

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]: # Token not found or is banned
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token or 'invalid/banned', ua, ref))
            conn.commit()
            return abort(403, 'Invalid or banned token')

        # Check token expiry
        expiry_time = datetime.fromisoformat(row[0])
        if datetime.utcnow() > expiry_time:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,)) # Ban expired token
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token + ' (expired)', ua, ref))
            conn.commit()
            return abort(403, 'Token expired')

        # Device limit check (only add if not present, don't re-count for existing streams from same IP)
        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                          (datetime.utcnow().isoformat(), ip, token + ' (device limit exceeded)', ua, ref))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        # Log stream access (optional, uncomment if you want very verbose logging for every stream segment)
        # c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
        #           (datetime.utcnow().isoformat(), ip, token + ' (stream)', ua, ref))

        for name, url in c.execute('SELECT name, stream_url FROM channels').fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url)) == channelid:
                conn.commit() # Commit any pending changes before redirect
                return redirect(url)
        conn.commit() # Commit if no channel found before aborting
        return abort(404, 'Stream not found')

# ------------------------ USER UNLOCK PAGE ------------------------ #
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
    # This route and its template ('not_allowed.html') were likely used for sniffer blocking.
    # Since sniffer blocking is removed, this page might no longer serve a direct purpose
    # in the current logic. You might consider removing it if it's completely unneeded.
    return render_template('not_allowed.html')

if __name__ == '__main__':
    # Ensure debug is False in production
    app.run(debug=True, port=5000)
