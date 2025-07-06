from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time, subprocess, threading
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # seconds

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ottnavigator', 'test']

# ------------------------ HELPER FUNCTIONS ------------------------ #
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT, original_url TEXT, is_restreamed INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS restream_processes (channel_id INTEGER PRIMARY KEY, pid INTEGER)''')

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper

def is_sniffer(ip, ua):
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

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

def start_restream(channel_id, original_url, restream_url):
    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute('UPDATE channels SET original_url = ?, is_restreamed = 1 WHERE id = ?', 
                     (original_url, channel_id))
            conn.commit()

        cmd = [
            'ffmpeg',
            '-i', original_url,
            '-c', 'copy',
            '-f', 'mpegts',
            restream_url
        ]
        
        process = subprocess.Popen(cmd)
        with sqlite3.connect(DB) as conn:
            conn.execute('INSERT OR REPLACE INTO restream_processes(channel_id, pid) VALUES (?, ?)', 
                        (channel_id, process.pid))
            conn.commit()
            
    except Exception as e:
        print(f"Restream failed for channel {channel_id}: {e}")

def stop_restream(channel_id):
    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute('SELECT pid FROM restream_processes WHERE channel_id = ?', (channel_id,))
            row = c.fetchone()
            if row:
                pid = row[0]
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
                
            c.execute('SELECT original_url FROM channels WHERE id = ?', (channel_id,))
            original_url = c.fetchone()[0]
            if original_url:
                c.execute('UPDATE channels SET stream_url = ?, is_restreamed = 0 WHERE id = ?', 
                         (original_url, channel_id))
            
            c.execute('DELETE FROM restream_processes WHERE channel_id = ?', (channel_id,))
            conn.commit()
            
    except Exception as e:
        print(f"Error stopping restream for channel {channel_id}: {e}")

# ------------------------ ROUTES ------------------------ #
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

            elif 'add_channel' in request.form:
                name = request.form['name']
                stream = request.form['stream']
                logo = request.form['logo']
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, stream, logo))

            elif 'm3u_url' in request.form:
                m3u_url = request.form['m3u_url'].strip()
                try:
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    res = requests.get(m3u_url, headers=headers, timeout=10, verify=False)
                    if res.status_code == 200:
                        lines = res.text.splitlines()
                        parse_m3u_lines(lines, c)
                except Exception as e:
                    print(f"[ERROR] M3U fetch failed: {e}")

            conn.commit()

        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT id, name, stream_url, logo_url, is_restreamed FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_channel/<int:id>')
@login_required
def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/restream/<int:channel_id>')
@login_required
def restream_channel(channel_id):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT id, name, stream_url FROM channels WHERE id = ?', (channel_id,))
        channel = c.fetchone()
        if not channel:
            return abort(404, 'Channel not found')
        
        restream_url = f"http://{request.host}/restream/{channel_id}"
        threading.Thread(target=start_restream, args=(channel_id, channel[2], restream_url), daemon=True).start()
        c.execute('UPDATE channels SET stream_url = ? WHERE id = ?', (restream_url, channel_id))
        conn.commit()
        
    return redirect('/admin')

@app.route('/admin/stop_restream/<int:channel_id>')
@login_required
def stop_restream_channel(channel_id):
    stop_restream(channel_id)
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
        if is_sniffer(ip, ua):
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

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        conn.commit()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
        proxy = f"https://{request.host}/stream/{uid}?token={token}"
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(proxy)

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

@app.route('/stream/<uuid:channel_id>')
def stream(channel_id):
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            return render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
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

        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                try:
                    res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, stream=True, timeout=10)
                    return Response(stream_with_context(res.iter_content(1024)), content_type=res.headers.get('Content-Type'))
                except:
                    return abort(500, 'Error fetching stream')
        return abort(404, 'Stream not found')

@app.route('/restream/<int:channel_id>')
def serve_restream(channel_id):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT original_url FROM channels WHERE id = ? AND is_restreamed = 1', (channel_id,))
        row = c.fetchone()
        if not row:
            return abort(404, 'Restream not found')
        
        original_url = row[0]
        try:
            res = requests.get(original_url, stream=True, timeout=10)
            return Response(stream_with_context(res.iter_content(1024)), 
                          content_type=res.headers.get('Content-Type'))
        except Exception as e:
            return abort(502, f'Restream proxy error: {str(e)}')

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

# ------------------------ INITIALIZATION ------------------------ #
init_db()

if __name__ == '__main__':
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM restream_processes')
        conn.execute('UPDATE channels SET is_restreamed = 0')
        conn.commit()
    app.run(debug=True, port=5000)
