from flask import Flask, request, redirect, render_template, session, abort, Response
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4

ALLOWED_AGENTS = ['ott', 'tivimate','playtv']

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
        # --- MODIFIED: Add new columns for MPD specific properties ---
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            stream_url TEXT,
            logo_url TEXT,
            kodip_license_type TEXT DEFAULT NULL,
            kodip_license_key TEXT DEFAULT NULL,
            extvlcopts TEXT DEFAULT NULL,
            exthttp_headers TEXT DEFAULT NULL
        )''')
        conn.commit() # Commit schema changes
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
                # --- MODIFIED: Get new fields from form ---
                kodip_license_type = request.form.get('kodip_license_type', '').strip()
                kodip_license_key = request.form.get('kodip_license_key', '').strip()
                extvlcopts = request.form.get('extvlcopts', '').strip()
                exthttp_headers = request.form.get('exthttp_headers', '').strip()

                c.execute('''INSERT INTO channels(name, stream_url, logo_url, 
                                                  kodip_license_type, kodip_license_key, 
                                                  extvlcopts, exthttp_headers) 
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (name, stream, logo,
                           kodip_license_type, kodip_license_key,
                           extvlcopts, exthttp_headers))

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
                    print("M3U Fetch Error:", e)

        conn.commit()
        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        # --- MODIFIED: Select all new columns for channels ---
        c.execute('SELECT id, name, stream_url, logo_url, kodip_license_type, kodip_license_key, extvlcopts, exthttp_headers FROM channels')
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
            new_expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
            c.execute('UPDATE tokens SET expiry = ?, banned = 0 WHERE token = ?', (new_expiry, token))
        elif action == 'ban':
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
        elif action == 'unban':
            c.execute('UPDATE tokens SET banned = 0 WHERE token = ?', (token,))
        conn.commit()
    return redirect('/admin')

# ------------------------ M3U PARSER ------------------------ #
# --- MODIFIED: To parse custom M3U tags ---
def parse_m3u_lines(lines, c):
    name, logo = None, ''
    kodip_license_type = ''
    kodip_license_key = ''
    extvlcopts = ''
    exthttp_headers = ''
    
    lines_iter = iter(lines)
    for line in lines_iter:
        if line.startswith('#EXTINF:'):
            # Reset values for each new channel
            name, logo = None, ''
            kodip_license_type = ''
            kodip_license_key = ''
            extvlcopts = ''
            exthttp_headers = ''

            try:
                parts = line.split(',', 1)
                name = parts[1].strip()
                logo_part = line.split('tvg-logo="')
                logo = logo_part[1].split('"')[0] if len(logo_part) > 1 else ''
            except IndexError:
                continue

            url = None # Initialize URL to None for this block
            # Try to parse custom KODIPROP, EXTVLCOPT, EXTHTTP lines
            while True:
                try:
                    next_line = next(lines_iter)
                    if next_line.startswith('#KODIPROP:inputstream.adaptive.license_type='):
                        kodip_license_type = next_line.split('=', 1)[1].strip()
                    elif next_line.startswith('#KODIPROP:inputstream.adaptive.license_key='):
                        kodip_license_key = next_line.split('=', 1)[1].strip()
                    elif next_line.startswith('#EXTVLCOPT:'):
                        extvlcopts = next_line.split(':', 1)[1].strip()
                    elif next_line.startswith('#EXTHTTP:'):
                        exthttp_headers = next_line.split(':', 1)[1].strip()
                    elif next_line.startswith('http'): # This is the stream URL
                        url = next_line.strip()
                        break # Found URL, exit inner loop
                    else: # Unrecognized line, break to avoid infinite loop
                        break
                except StopIteration:
                    break # End of file

            if name and url: # If we successfully parsed EXTINF and found a URL
                c.execute('''INSERT INTO channels(name, stream_url, logo_url, 
                                                  kodip_license_type, kodip_license_key, 
                                                  extvlcopts, exthttp_headers) 
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (name, url, logo,
                           kodip_license_type, kodip_license_key,
                           extvlcopts, exthttp_headers))
        elif line.startswith('http') and name: # Fallback for simple M3U with no custom tags
            # This handles cases where EXTINF was parsed, but no custom tags followed,
            # and the http line is the very next line in the outer loop.
            # Make sure `name` is still set from a previous EXTINF.
            url = line.strip()
            c.execute('''INSERT INTO channels(name, stream_url, logo_url, 
                                              kodip_license_type, kodip_license_key, 
                                              extvlcopts, exthttp_headers) 
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (name, url, logo,
                       kodip_license_type, kodip_license_key,
                       extvlcopts, exthttp_headers))
            name, logo = None, '' # Reset for next channel
            kodip_license_type = '' # Reset custom properties
            kodip_license_key = ''
            extvlcopts = ''
            exthttp_headers = ''


# ------------------------ USER-AGENT FILTERING ------------------------ #
def is_allowed_user_agent(user_agent):
    ua_lower = user_agent.lower()
    for agent in ALLOWED_AGENTS:
        if agent in ua_lower:
            return True
    return False

# ------------------------ M3U PLAYLIST ------------------------ #
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        if not is_allowed_user_agent(ua):
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token or 'unknown', ua + ' (UA_BANNED)', ref))
            conn.commit()
            return abort(403, 'Access denied: Unsupported client application.')

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token or 'invalid/banned', ua, ref))
            conn.commit()
            return abort(403, 'Invalid or banned token')

        expiry_time = datetime.fromisoformat(row[0])
        if datetime.utcnow() > expiry_time:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token + ' (expired)', ua, ref))
            conn.commit()
            return abort(403, 'Token expired')

        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                          (datetime.utcnow().isoformat(), ip, token + ' (device limit exceeded)', ua, ref))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        
        # --- MODIFIED: Fetch all new columns from channels ---
        channels = c.execute('''SELECT name, stream_url, logo_url,
                                    kodip_license_type, kodip_license_key,
                                    extvlcopts, exthttp_headers
                               FROM channels''').fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    # --- MODIFIED: Loop through extended channel data ---
    for name, stream_url, logo, kodip_license_type, kodip_license_key, extvlcopts, exthttp_headers in channels:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, stream_url))
        proxy = f'https://{request.host}/stream?token={token}&channelid={uid}'

        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        
        # --- MODIFIED: Add custom properties to M3U output if they exist ---
        if kodip_license_type and kodip_license_key:
            lines.append(f'#KODIPROP:inputstream.adaptive.license_type={kodip_license_type}')
            lines.append(f'#KODIPROP:inputstream.adaptive.license_key={kodip_license_key}')
        if extvlcopts:
            lines.append(f'#EXTVLCOPT:{extvlcopts}')
        if exthttp_headers:
            lines.append(f'#EXTHTTP:{exthttp_headers}')
            
        lines.append(proxy)

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

# ------------------------ STREAM REDIRECT ------------------------ #
@app.route('/stream')
def stream():
    token = request.args.get('token', '').strip()
    channelid = request.args.get('channelid', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        if not is_allowed_user_agent(ua):
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token or 'unknown', ua + ' (UA_BANNED)', ref))
            conn.commit()
            return abort(403, 'Access denied: Unsupported client application.')

        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token or 'invalid/banned', ua, ref))
            conn.commit()
            return abort(403, 'Invalid or banned token')

        expiry_time = datetime.fromisoformat(row[0])
        if datetime.utcnow() > expiry_time:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                      (datetime.utcnow().isoformat(), ip, token + ' (expired)', ua, ref))
            conn.commit()
            return abort(403, 'Token expired')

        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                          (datetime.utcnow().isoformat(), ip, token + ' (device limit exceeded)', ua, ref))
                conn.commit()
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))

        # IMPORTANT: The stream redirect simply returns the URL.
        # The custom M3U tags (KODIPROP, EXTVLCOPT, EXTHTTP) are for the client
        # to use when it *then* requests this URL. Your server doesn't proxy them.
        for name, stream_url, logo, kodip_license_type, kodip_license_key, extvlcopts, exthttp_headers in c.execute('''SELECT name, stream_url, logo_url, kodip_license_type, kodip_license_key, extvlcopts, exthttp_headers FROM channels''').fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, stream_url)) == channelid:
                conn.commit()
                return redirect(stream_url) # Redirect to the actual MPD URL
        conn.commit()
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
    return render_template('not_allowed.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
