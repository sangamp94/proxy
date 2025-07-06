from flask import Flask, request, abort, Response, render_template
from functools import wraps
from datetime import datetime
import sqlite3
import os
import uuid
import requests
import time
from cryptography.fernet import Fernet
from urllib.parse import urljoin, urlparse
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')  # Use environment variable
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # seconds
REQUEST_TIMEOUT = 15  # seconds for upstream requests

# Persist Fernet key
if os.path.exists('fernet.key'):
    with open('fernet.key', 'rb') as f:
        FERNET_KEY = f.read()
else:
    FERNET_KEY = Fernet.generate_key()
    with open('fernet.key', 'wb') as f:
        f.write(FERNET_KEY)

fernet = Fernet(FERNET_KEY)

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['dalvik', 'ott', 'navigator', 'ott navigator', 'ott-navigator', 'ottnavigator', 'tivimate', 'test', 'vlc', 'kodi']

# Database initialization
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
            referrer TEXT,
            path TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            stream_url TEXT,
            logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            unblock_time REAL)''')
        conn.commit()
init_db()

# Helper functions
def is_sniffer(ua):
    if not ua:
        return True
    ua = ua.lower()
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_request(c, ip, token, ua, ref, path):
    c.execute('''INSERT INTO logs(timestamp, ip, token, user_agent, referrer, path) 
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref, path))

def log_block(c, ip, token, ua, ref, path):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute('''INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) 
                 VALUES (?, ?)''', (ip, unblock_time))
    log_request(c, ip, token, ua, ref, path)

def check_token_and_ip(c, token, ip):
    if not token:
        return False
        
    row = c.execute('''SELECT expiry, banned FROM tokens 
                       WHERE token = ?''', (token,)).fetchone()
    if not row or row[1]:  # Token doesn't exist or is banned
        return False
        
    # Check if IP is already associated with token
    if c.execute('''SELECT 1 FROM token_ips 
                    WHERE token = ? AND ip = ?''', (token, ip)).fetchone():
        return True
        
    # Check device limit
    device_count = c.execute('''SELECT COUNT(*) FROM token_ips 
                               WHERE token = ?''', (token,)).fetchone()[0]
    if device_count >= MAX_DEVICES:
        c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
        return False
        
    # Add new IP association
    c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
    return True

def get_channel_url(c, channelid):
    for row in c.execute('SELECT stream_url FROM channels'):
        try:
            decrypted_url = fernet.decrypt(row[0].encode()).decode()
            if str(uuid.uuid5(uuid.NAMESPACE_URL, decrypted_url)) == channelid:
                return decrypted_url
        except:
            continue
    return None

# Middleware to check blocked IPs and sniffers
@app.before_request
def before_request():
    if request.path.startswith('/segment') or request.path.startswith('/stream'):
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '')
        ref = request.referrer or ''
        token = request.args.get('token', '').strip()
        
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            
            # Check if IP is blocked
            row = c.execute('''SELECT unblock_time FROM blocked_ips 
                              WHERE ip = ?''', (ip,)).fetchone()
            if row and time.time() < row[0]:
                log_request(c, ip, token, ua, ref, request.path)
                conn.commit()
                return render_template('sniffer_blocked.html'), 403
                
            # Check for sniffers
            if is_sniffer(ua):
                log_block(c, ip, token, ua, ref, request.path)
                conn.commit()
                return render_template('sniffer_blocked.html'), 403
                
            # Validate token
            if not check_token_and_ip(c, token, ip):
                log_request(c, ip, token, ua, ref, request.path)
                conn.commit()
                return abort(403)
                
            log_request(c, ip, token, ua, ref, request.path)
            conn.commit()

# Routes
@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        channels = c.execute('SELECT name, stream_url, logo_url FROM channels').fetchall()

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

@app.route('/stream')
def stream():
    channelid = request.args.get('channelid', '').strip()
    if not channelid:
        return abort(400)
        
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        url = get_channel_url(c, channelid)
        
    if not url:
        return abort(404)

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        }
        proxied_url = f"{url}?{request.query_string.decode()}" if request.query_string else url
        
        r = requests.get(proxied_url, headers=headers, timeout=REQUEST_TIMEOUT, stream=True)
        r.raise_for_status()
    except requests.RequestException:
        return abort(502)

    content_type = r.headers.get('Content-Type', '').lower()
    if 'application/vnd.apple.mpegurl' in content_type or proxied_url.endswith('.m3u8'):
        def rewrite_playlist(content):
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and (line.endswith('.ts') or '.ts?' in line):
                    segment = line.split('/')[-1] if '/' in line else line
                    yield f'https://{request.host}/segment?token={request.args.get("token")}&channelid={channelid}&segment={segment}\n'
                else:
                    yield f'{line}\n'
                    
        return Response(rewrite_playlist(r.text), content_type='application/vnd.apple.mpegurl')
    
    def generate():
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                yield chunk
                
    return Response(generate(), content_type=content_type or 'video/MP2T')

@app.route('/segment')
def segment():
    channelid = request.args.get('channelid', '').strip()
    segment = request.args.get('segment', '').strip()
    if not channelid or not segment:
        return abort(400)
        
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        base_url = get_channel_url(c, channelid)
        
    if not base_url:
        return abort(404)

    # Construct proper segment URL
    try:
        segment_url = urljoin(base_url + '/' if not base_url.endswith('/') else base_url, segment)
        
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        }
        r = requests.get(segment_url, headers=headers, timeout=REQUEST_TIMEOUT, stream=True)
        r.raise_for_status()
    except requests.RequestException:
        return abort(502)

    def generate():
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                yield chunk
                
    return Response(
        generate(),
        content_type=r.headers.get('Content-Type', 'video/MP2T'),
        headers={
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    )

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
