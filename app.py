# FULL IPTV APP WITH TOKEN, DEVICE LIMIT, SNIFFER DETECTION, HLS+DASH PROXY (ASYNC QUART VERSION)
from quart import Quart, request, redirect, render_template, session, abort, Response
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, aiohttp, asyncio, time

app = Quart(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ott', 'navigator', 'ott navigator', 'ottnavigator', 'tivimate', 'test']

# ---------------- INIT DB ---------------- #
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (
            token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY, unblock_time REAL)''')
init_db()

# ---------------- AUTH ---------------- #
def login_required(f):
    @wraps(f)
    async def wrap(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return await f(*args, **kwargs)
    return wrap

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        form = await request.form
        if form['username'] == 'admin' and form['password'] == 'admin':
            session['admin'] = True
            return redirect('/admin')
        return 'Invalid credentials'
    return await render_template('login.html')

@app.route('/logout')
async def logout():
    session.pop('admin', None)
    return redirect('/login')

# ---------------- ADMIN PANEL ---------------- #
@app.route('/admin', methods=['GET', 'POST'])
@login_required
async def admin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            form = await request.form
            if 'add_token' in form:
                token = form['token'].strip()
                days = int(form['days'])
                expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
                c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'admin'))
            elif 'add_channel' in form:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (
                    form['name'], form['stream'], form['logo']))
            elif 'upload_m3u' in form:
                files = await request.files
                m3ufile = files['m3ufile']
                if m3ufile.filename.endswith('.m3u'):
                    content = (await m3ufile.read()).decode('utf-8')
                    parse_m3u_lines(content.splitlines(), c)
            elif 'm3u_url' in form:
                try:
                    url = form['m3u_url'].strip()
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers={'User-Agent': 'Mozilla'}) as res:
                            if res.status == 200:
                                text = await res.text()
                                parse_m3u_lines(text.splitlines(), c)
                except Exception as e:
                    print('[M3U URL ERROR]', e)
        conn.commit()
        tokens = c.execute('SELECT * FROM tokens').fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        logs = c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').fetchall()
        channels = c.execute('SELECT * FROM channels').fetchall()
        return await render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_channel/<int:id>')
@login_required
async def delete_channel(id):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/delete_all_channels', methods=['POST'])
@login_required
async def delete_all_channels():
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels')
        conn.commit()
    return redirect('/admin')

# ---------------- PARSER ---------------- #
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

# ---------------- SECURITY ---------------- #
def is_sniffer(ip, ua):
    ua = ua.lower()
    return any(s in ua for s in SNIFFERS) or not any(agent in ua for agent in ALLOWED_AGENTS)

def log_block(c, ip, token, ua, ref):
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, time.time() + BLOCK_DURATION))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

# ---------------- PLAYLIST ---------------- #
@app.route('/iptvplaylist.m3u')
async def playlist():
    token = request.args.get('token', '').strip()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.headers.get('Referer', '')

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if c.execute("SELECT 1 FROM blocked_ips WHERE ip=? AND unblock_time > ?", (ip, time.time())).fetchone():
            return await render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return await render_template('sniffer_blocked.html'), 403
        row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403)
        if not c.execute('SELECT 1 FROM token_ips WHERE token=? AND ip=?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token=?', (token,))
                return abort(403, 'Max devices reached')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
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

    return Response('\n'.join(lines), content_type='application/x-mpegURL')

# ---------------- STREAM ---------------- #
@app.route('/stream')
async def stream():
    token = request.args.get('token')
    channelid = request.args.get('channelid')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', '').lower()

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if c.execute("SELECT 1 FROM blocked_ips WHERE ip=? AND unblock_time > ?", (ip, time.time())).fetchone():
            return await render_template('sniffer_blocked.html'), 403
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, request.headers.get('Referer', ''))
            conn.commit()
            return await render_template('sniffer_blocked.html'), 403
        row = c.execute('SELECT expiry, banned FROM tokens WHERE token=?', (token,)).fetchone()
        if not row or row[1]:
            return abort(403)
        if not c.execute('SELECT 1 FROM token_ips WHERE token=? AND ip=?', (token, ip)).fetchone():
            if c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token,)).fetchone()[0] >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token=?', (token,))
                return abort(403)
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
        c.execute('SELECT name, stream_url FROM channels')
        for name, url in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url)) == channelid:
                try:
                    base_url = url.rsplit('/', 1)[0]
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers={'User-Agent': 'Mozilla'}) as res:
                            content = await res.text()
                            output = []
                            for line in content.splitlines():
                                if line.lstrip().startswith('#'):
                                    output.append(line)
                                elif line.strip().endswith(('.m3u8', '.ts', '.mpd', '.m4s')):
                                    full_url = f'{base_url}/{line}' if not line.startswith('http') else line
                                    proxy = f'/segment?token={token}&channelid={channelid}&url={full_url}'
                                    output.append(proxy)
                                else:
                                    output.append(line)
                            return Response('\n'.join(output), content_type='application/vnd.apple.mpegurl')
                except Exception as e:
                    print('[Stream Proxy Error]', e)
                    return abort(500)
        return abort(404)

# ---------------- SEGMENT ---------------- #
@app.route('/segment')
async def segment():
    url = request.args.get('url')
    if not url:
        return abort(400)
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers={'User-Agent': 'Mozilla', 'Connection': 'keep-alive'}) as res:
                ctype = res.headers.get('Content-Type', 'application/octet-stream')
                if url.endswith('.mpd'):
                    ctype = 'application/dash+xml'
                elif url.endswith('.m4s'):
                    ctype = 'video/iso.segment'

                async def stream():
                    try:
                        async for chunk in res.content.iter_chunked(4096):
                            yield chunk
                    except Exception as e:
                        print("[Segment Streaming Error]", e)

                return Response(stream(), content_type=ctype)
    except Exception as e:
        print('[Segment Proxy Error]', e)
        return abort(500)

# ---------------- UNLOCK ---------------- #
@app.route('/unlock', methods=['GET', 'POST'])
async def unlock():
    token = None
    if request.method == 'POST':
        token = uuid.uuid4().hex[:12]
        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
        with sqlite3.connect(DB) as conn:
            conn.execute('INSERT INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'user'))
            conn.commit()
    return await render_template('unlock.html', token=token)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
