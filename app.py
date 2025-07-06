from flask import Flask, request, abort, Response, render_template, redirect, url_for, flash
from functools import wraps
from datetime import datetime
import sqlite3
import os
import uuid
import requests
import time
from cryptography.fernet import Fernet
from urllib.parse import urljoin

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # seconds
REQUEST_TIMEOUT = 15

# Generate or load Fernet key
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

# Database init

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            expiry TEXT,
            banned INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (
            token TEXT,
            ip TEXT,
            UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT, ip TEXT, token TEXT,
            user_agent TEXT, referrer TEXT, path TEXT)''')
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

# Utils

def is_sniffer(ua):
    if not ua:
        return True
    ua = ua.lower()
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_request(c, ip, token, ua, ref, path):
    c.execute('INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)',
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref, path))

def log_block(c, ip, token, ua, ref, path):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute('INSERT OR REPLACE INTO blocked_ips VALUES (?, ?)', (ip, unblock_time))
    log_request(c, ip, token, ua, ref, path)

def check_token_and_ip(c, token, ip):
    if not token:
        return False
    row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
    if not row or row[1]:
        return False
    if c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
        return True
    if c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0] >= MAX_DEVICES:
        c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
        return False
    c.execute('INSERT INTO token_ips VALUES (?, ?)', (token, ip))
    return True

def get_channel_url(c, channelid):
    for row in c.execute('SELECT stream_url FROM channels'):
        try:
            decrypted = fernet.decrypt(row[0].encode()).decode()
            if str(uuid.uuid5(uuid.NAMESPACE_URL, decrypted)) == channelid:
                return decrypted
        except:
            continue
    return None

# Middleware
@app.before_request
def before():
    if request.path.startswith('/stream') or request.path.startswith('/segment'):
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '')
        token = request.args.get('token', '').strip()
        ref = request.referrer or ''
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            row = c.execute('SELECT unblock_time FROM blocked_ips WHERE ip = ?', (ip,)).fetchone()
            if row and time.time() < row[0]:
                return render_template('sniffer_blocked.html'), 403
            if is_sniffer(ua):
                log_block(c, ip, token, ua, ref, request.path)
                conn.commit()
                return render_template('sniffer_blocked.html'), 403
            if not check_token_and_ip(c, token, ip):
                log_request(c, ip, token, ua, ref, request.path)
                conn.commit()
                return abort(403)
            log_request(c, ip, token, ua, ref, request.path)
            conn.commit()

# Routes
@app.route('/')
def index():
    return redirect(url_for('admin'))

@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        channels = c.execute('SELECT name, stream_url, logo_url FROM channels').fetchall()
    lines = ['#EXTM3U']
    for name, enc_url, logo in channels:
        try:
            url = fernet.decrypt(enc_url.encode()).decode()
            uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
            proxy = f'https://{request.host}/stream?token={token}&channelid={uid}'
            lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
            lines.append(proxy)
        except:
            continue
    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

@app.route('/stream')
def stream():
    channelid = request.args.get('channelid')
    token = request.args.get('token')
    if not channelid:
        return abort(400)
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        url = get_channel_url(c, channelid)
    if not url:
        return abort(404)
    try:
        qs = '&'.join([q for q in request.query_string.decode().split('&') if not q.startswith('token=') and not q.startswith('channelid=')])
        full_url = f"{url}?{qs}" if qs else url
        r = requests.get(full_url, headers={'User-Agent': 'Mozilla'}, timeout=REQUEST_TIMEOUT, stream=True)
        r.raise_for_status()
    except:
        return abort(502)

    if 'application/vnd.apple.mpegurl' in r.headers.get('Content-Type', ''):
        content = r.content.decode(errors='ignore')
        def rewrite():
            for line in content.splitlines():
                if line and not line.startswith('#') and '.ts' in line:
                    segment = line.split('/')[-1]
                    yield f"https://{request.host}/segment?token={token}&channelid={channelid}&segment={segment}\n"
                else:
                    yield line + '\n'
        return Response(rewrite(), content_type='application/vnd.apple.mpegurl')

    return Response(r.iter_content(8192), content_type=r.headers.get('Content-Type', 'video/MP2T'))

@app.route('/segment')
def segment():
    cid = request.args.get('channelid')
    seg = request.args.get('segment')
    if not cid or not seg:
        return abort(400)
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        base_url = get_channel_url(c, cid)
    if not base_url:
        return abort(404)
    try:
        seg_url = urljoin(base_url + '/' if not base_url.endswith('/') else base_url, seg)
        r = requests.get(seg_url, headers={'User-Agent': 'Mozilla'}, timeout=REQUEST_TIMEOUT, stream=True)
        r.raise_for_status()
    except:
        return abort(502)
    return Response(r.iter_content(8192), content_type=r.headers.get('Content-Type', 'video/MP2T'))

# Admin panel
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            name = request.form.get('name')
            logo = request.form.get('logo')
            url = request.form.get('url')

            if not url or not name or not logo:
                flash('All fields are required.', 'danger')
                return redirect(url_for('admin'))

            encrypted = fernet.encrypt(url.encode()).decode()
            c.execute('INSERT INTO channels (name, stream_url, logo_url) VALUES (?, ?, ?)', (name, encrypted, logo))
            conn.commit()
            flash('Channel added.')
            return redirect(url_for('admin'))
        channels = c.execute('SELECT id, name FROM channels').fetchall()
        tokens = c.execute('SELECT token, banned FROM tokens').fetchall()
    return render_template('admin.html', channels=channels, tokens=tokens)

@app.route('/delete_channel/<int:cid>')
def delete_channel(cid):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (cid,))
        conn.commit()
    return redirect(url_for('admin'))

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def notfound(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
