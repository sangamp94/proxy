from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time
from urllib.parse import urljoin, urlparse

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ottnavigator', 'test']


def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
init_db()


def is_sniffer(ip, ua):
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)


def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))


def rewrite_media_playlist(content, base_url):
    lines = []
    for line in content.splitlines():
        if line.strip().startswith("#"):
            lines.append(line)
        elif line.strip():
            full_url = urljoin(base_url, line.strip())
            proxied = f"/segment?token={request.args.get('token')}&url={full_url}"
            lines.append(proxied)
    return '\n'.join(lines)


def rewrite_master_playlist(content, base_url):
    lines = []
    for line in content.splitlines():
        if line.strip().endswith('.m3u8'):
            filename = os.path.basename(line.strip())
            lines.append(f"/stream_sub/{filename}?token={request.args.get('token')}")
        else:
            lines.append(line)
    return '\n'.join(lines)


def is_master_playlist(content):
    return '#EXT-X-STREAM-INF' in content


def fetch_and_rewrite(url, depth=0):
    if depth > 3:
        return "#EXTM3U\n#EXTINF:0,Too many redirects"
    try:
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        content = res.text
        if is_master_playlist(content):
            return rewrite_master_playlist(content, url)
        else:
            return rewrite_media_playlist(content, url)
    except Exception as e:
        return f"#EXTM3U\n#EXTINF:0,Failed to fetch\n# {e}"


@app.route('/segment')
def segment():
    url = request.args.get('url')
    try:
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, stream=True, timeout=10)
        return Response(stream_with_context(res.iter_content(1024)), content_type=res.headers.get('Content-Type'))
    except Exception as e:
        print(f"[ERROR] Segment fetch failed: {e}")
        return abort(500, 'Failed to fetch segment')


@app.route('/stream_sub/<path:filename>')
def stream_sub(filename):
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
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

    ref = request.referrer
    if not ref:
        return abort(400, "Missing referrer")

    parsed = urlparse(ref)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = os.path.dirname(parsed.path)
    original_url = f"{base_url}{path}/{filename}"

    try:
        res = requests.get(original_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        content = res.text
        return Response(rewrite_media_playlist(content, original_url), mimetype='application/x-mpegURL')
    except Exception as e:
        print(f"[ERROR] Could not fetch sub-playlist: {e}")
        return abort(404)


@app.route('/stream/<path:raw_url>')
def stream(raw_url):
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
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
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
        conn.commit()

    decoded_url = requests.utils.unquote(raw_url)
    return Response(fetch_and_rewrite(decoded_url), mimetype='application/x-mpegURL')


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


@app.route('/')
def index():
    return redirect('/unlock')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
