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

# Persist Fernet key to file so encryption survives restarts
if os.path.exists('fernet.key'):
    with open('fernet.key', 'rb') as f:
        FERNET_KEY = f.read()
else:
    FERNET_KEY = Fernet.generate_key()
    with open('fernet.key', 'wb') as f:
        f.write(FERNET_KEY)

fernet = Fernet(FERNET_KEY)

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['dalvik', 'ott', 'navigator', 'ott navigator', 'ott-navigator', 'ottnavigator', 'tivimate', 'test']

# -------------- DB INIT -------------- #
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

def check_token_and_ip(c, token, ip):
    row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
    if not row or row[1]:
        return False
    if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
        if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            return False
        c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
    return True

# -------------- Playlist generation -------------- #
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

        if not check_token_and_ip(c, token, ip):
            conn.commit()
            return abort(403)

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))

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

# -------------- Proxy stream (playlist and .ts segment proxy) -------------- #
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

        if not check_token_and_ip(c, token, ip):
            conn.commit()
            return abort(403)

        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))

        # Find channel url by channelid
        url = None
        for row in c.execute('SELECT stream_url FROM channels'):
            try:
                decrypted_url = fernet.decrypt(row[0].encode()).decode()
                if str(uuid.uuid5(uuid.NAMESPACE_URL, decrypted_url)) == channelid:
                    url = decrypted_url
                    break
            except:
                continue

    if not url:
        return abort(404)

    # Proxy the remote stream (handle .m3u8 and .ts)
    # Detect if this is a playlist file
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        proxied_url = url
        if request.query_string:
            proxied_url += '?' + request.query_string.decode()

        r = requests.get(proxied_url, headers=headers, timeout=10)
    except Exception:
        return abort(502)

    content_type = r.headers.get('Content-Type', '').lower()
    if 'application/vnd.apple.mpegurl' in content_type or proxied_url.endswith('.m3u8'):
        # Rewrite playlist contents to proxy .ts segment requests
        playlist_text = r.text

        def rewrite_line(line):
            line = line.strip()
            if line and not line.startswith('#') and line.endswith('.ts'):
                # Convert relative or absolute segment URLs into proxy URLs
                # If segment URL is absolute, strip scheme+host and keep path only
                segment = line
                if segment.startswith('http://') or segment.startswith('https://'):
                    from urllib.parse import urlparse
                    p = urlparse(segment)
                    segment = p.path.lstrip('/')
                return f'https://{request.host}/segment?token={token}&channelid={channelid}&segment={segment}'
            return line

        new_playlist = '\n'.join(rewrite_line(line) for line in playlist_text.splitlines())
        return Response(new_playlist, content_type='application/vnd.apple.mpegurl')

    def generate():
        for chunk in r.iter_content(chunk_size=4096):
            if chunk:
                yield chunk

    return Response(generate(), content_type=content_type or 'application/octet-stream')

# -------------- Proxy .ts segments -------------- #
@app.route('/segment')
def segment():
    token = request.args.get('token', '').strip()
    channelid = request.args.get('channelid', '').strip()
    segment = request.args.get('segment', '').strip()
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

        if not check_token_and_ip(c, token, ip):
            conn.commit()
            return abort(403)

        # Find the base stream URL for the channelid
        url = None
        for row in c.execute('SELECT stream_url FROM channels'):
            try:
                decrypted_url = fernet.decrypt(row[0].encode()).decode()
                if str(uuid.uuid5(uuid.NAMESPACE_URL, decrypted_url)) == channelid:
                    url = decrypted_url
                    break
            except:
                continue

    if not url:
        return abort(404)

    # Compose full URL of the segment
    # Remove trailing slash if present, then add '/'
    segment_url = url.rstrip('/') + '/' + segment.lstrip('/')

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(segment_url, headers=headers, stream=True, timeout=10)
    except Exception:
        return abort(502)

    def generate():
        for chunk in r.iter_content(chunk_size=4096):
            if chunk:
                yield chunk

    content_type = r.headers.get('Content-Type', 'video/mp2t')
    return Response(generate(), content_type=content_type)

# ---------------- Run app ---------------- #
if __name__ == '__main__':
    app.run(debug=True, port=5000)
