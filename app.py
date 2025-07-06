from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time, re
import logging # Import logging module for better error reporting

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'supersecretkey_change_this_in_production' # IMPORTANT: Change this for production!
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300 # 5 minutes

SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
ALLOWED_AGENTS = ['ottnavigator', 'test'] # Consider more specific user agents for production apps

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
    logging.info("Database initialized.")
init_db()

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
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin': # IMPORTANT: Hardcoded credentials, change for production!
            session['admin'] = True
            logging.info(f"Admin logged in from {request.remote_addr}")
            return redirect('/admin')
        logging.warning(f"Failed login attempt from {request.remote_addr} (User: {username})")
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin', None)
    logging.info(f"Admin logged out from {request.remote_addr}")
    return redirect('/login')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            if 'add_token' in request.form:
                token = request.form['token'].strip()
                try:
                    days = int(request.form['days'])
                    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
                    c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'admin'))
                    conn.commit()
                    logging.info(f"Token '{token}' added/updated by admin.")
                except ValueError:
                    logging.error("Invalid number of days for token expiry.")
            elif 'add_channel' in request.form:
                name = request.form['name'].strip()
                stream = request.form['stream'].strip()
                logo = request.form['logo'].strip()
                if name and stream:
                    c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, stream, logo))
                    conn.commit()
                    logging.info(f"Channel '{name}' added by admin.")
                else:
                    logging.warning("Attempted to add channel with missing name or stream URL.")
            elif 'm3u_url' in request.form:
                m3u_url = request.form['m3u_url'].strip()
                try:
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    # IMPORTANT: verify=False disables SSL certificate verification. Use with caution in production.
                    # It's recommended to ensure the M3U source uses valid SSL or handle certificates properly.
                    res = requests.get(m3u_url, headers=headers, timeout=10, verify=False)
                    res.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                    lines = res.text.splitlines()
                    parse_m3u_lines(lines, c)
                    conn.commit()
                    logging.info(f"M3U playlist fetched and parsed from {m3u_url}")
                except requests.exceptions.RequestException as req_e:
                    logging.error(f"[ERROR] M3U fetch failed for {m3u_url}: {req_e}")
                except Exception as e:
                    logging.error(f"[ERROR] M3U parsing or database error for {m3u_url}: {e}")

        # Fetch data for rendering
        c.execute('SELECT * FROM tokens')
        tokens_db = c.fetchall()
        token_data = []
        for t in tokens_db:
            token = t[0]
            expiry = t[1]
            banned = t[2]
            created_by = t[3]
            device_count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token,)).fetchone()[0]
            token_data.append((token, expiry, device_count, banned, created_by))

        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_channel/<int:channel_id_to_delete>') # Renamed parameter for clarity
@login_required
def delete_channel(channel_id_to_delete):
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (channel_id_to_delete,))
        conn.commit()
        logging.info(f"Channel with ID {channel_id_to_delete} deleted by admin.")
    return redirect('/admin')

def parse_m3u_lines(lines, c):
    name, logo = None, ''
    for line in lines:
        line = line.strip() # Strip whitespace from the line
        if line.startswith('#EXTINF:'):
            try:
                # Use regex for more robust parsing of EXTINF attributes
                extinf_match = re.search(r'#EXTINF:(-?\d+)\s*(.*?),\s*(.*)', line)
                if extinf_match:
                    # duration = extinf_match.group(1) # You can use this if needed
                    attributes_str = extinf_match.group(2)
                    name = extinf_match.group(3).strip()

                    logo_match = re.search(r'tvg-logo="([^"]*)"', attributes_str)
                    logo = logo_match.group(1) if logo_match else ''
                else:
                    # Fallback for simpler #EXTINF lines if regex fails
                    parts = line.split(',', 1)
                    name = parts[1].strip() if len(parts) > 1 else 'Unknown Channel'
                    logo = '' # No logo if regex didn't find tvg-logo
            except Exception as e:
                logging.warning(f"Error parsing EXTINF line: {line} - {e}")
                name, logo = None, '' # Reset to avoid incorrect association
                continue
        elif line.startswith('http'):
            url = line
            if name and url:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, url, logo))
                name, logo = None, '' # Reset for the next channel
            else:
                logging.warning(f"Skipping URL '{url}' as no preceding #EXTINF tag was parsed correctly.")

def is_sniffer(ip, ua):
    # Check for known sniffer tools in User-Agent
    if any(s in ua for s in SNIFFERS):
        return True
    # Check if User-Agent is not among the allowed agents
    # This might be too restrictive; consider allowing other common browser UAs if needed.
    if not any(agent in ua for agent in ALLOWED_AGENTS):
        logging.info(f"User-Agent '{ua}' not in ALLOWED_AGENTS.")
        return True
    return False

def log_block(c, ip, token, ua, ref):
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))
    logging.warning(f"IP {ip} blocked. Sniffer detected or suspicious activity for token {token}. UA: {ua}, Ref: {ref}")


def rewrite_playlist(content, base_url):
    lines = []
    for line in content.splitlines():
        # Only strip leading/trailing whitespace for content lines, not internal tags
        stripped_line = line.strip()
        if stripped_line.startswith("#"):
            lines.append(line) # Keep original line for tags
        elif stripped_line:
            # Construct full URL using requests.compat.urljoin for robust URL joining
            full_url = requests.compat.urljoin(base_url, stripped_line)
            # Proxy the segment requests through our /segment endpoint
            proxied = f"/segment?token={request.args.get('token', '')}&url={full_url}"
            lines.append(proxied)
    return '\n'.join(lines)

def is_master_playlist(content):
    return '#EXT-X-STREAM-INF' in content

def fetch_and_rewrite(url, depth=0):
    if depth > 3: # Prevent infinite recursion for malformed playlists
        logging.error(f"Max recursion depth reached for URL: {url}")
        return "#EXTM3U\n#EXTINF:0,Too many redirects"
    try:
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        res.raise_for_status() # Raise an exception for bad status codes
        content = res.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching playlist from {url}: {e}")
        return f"#EXTM3U\n#EXTINF:0,Error fetching playlist: {e}"

    if is_master_playlist(content):
        # This is a master playlist, which points to other .m3u8 playlists (variants)
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                lines.append(line)
            elif line.endswith(".m3u8"):
                next_url = requests.compat.urljoin(url, line)
                # Recursively fetch and rewrite the variant playlist
                rewritten_variant = fetch_and_rewrite(next_url, depth + 1)
                lines.append(rewritten_variant)
            else:
                # Handle other potential non-m3u8 URLs in master playlist if any (rare)
                # For now, just append as is or raise a warning
                lines.append(line)
        return '\n'.join(lines)
    else:
        # This is a media playlist (contains segments), rewrite its segment URLs
        return rewrite_playlist(content, base_url=url)

@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        # Check for IP block
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            logging.warning(f"Blocked IP {ip} attempted to access playlist. Remaining block time: {row[0] - time.time():.2f}s")
            return render_template('sniffer_blocked.html'), 403

        # Sniffer detection
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            # Ban the token immediately if sniffer detected
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            logging.warning(f"Sniffer detected for IP {ip}, token '{token}' banned.")
            return render_template('sniffer_blocked.html'), 403

        # Token validation
        token_row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not token_row:
            logging.warning(f"Attempt to access with non-existent token '{token}' from IP {ip}.")
            return abort(403, 'Invalid token')
        
        expiry_str, banned_status = token_row
        if banned_status:
            logging.warning(f"Attempt to access with banned token '{token}' from IP {ip}.")
            return abort(403, 'Invalid or banned token')
        
        if datetime.utcnow().isoformat() > expiry_str:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            logging.warning(f"Expired token '{token}' used by IP {ip}. Token banned.")
            return abort(403, 'Token expired')

        # Device limit check
        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            current_devices = c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0]
            if current_devices >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                logging.warning(f"Device limit exceeded for token '{token}' by IP {ip}. Token banned.")
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
            conn.commit() # Commit the new IP registration
            logging.info(f"New device (IP: {ip}) registered for token '{token}'. Total devices: {current_devices + 1}")

        # Log the access
        c.execute('INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)',
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        
        # Fetch channels
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        conn.commit() # Commit the log entry

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        # Use a stable UUID for the channel based on its URL
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip()))
        # Construct the proxy URL for the stream
        proxy = f"https://{request.host}/stream/{uid}?token={token}"
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(proxy)

    response_content = '\n'.join(lines)
    logging.info(f"Generated playlist for token '{token}' to IP {ip}.")
    return Response(response_content, mimetype='application/x-mpegURL')

@app.route('/stream/<uuid:channel_id>')
def stream(channel_id):
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or '' # Capture referrer for stream requests too

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        
        # Check for IP block
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() < row[0]:
            logging.warning(f"Blocked IP {ip} attempted to access stream. Remaining block time: {row[0] - time.time():.2f}s")
            return render_template('sniffer_blocked.html'), 403
        
        # Sniffer detection
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref) # Log with referrer
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            logging.warning(f"Sniffer detected during stream access for IP {ip}, token '{token}' banned.")
            return render_template('sniffer_blocked.html'), 403

        # Token validation (redundant from playlist but good for direct stream access attempts)
        token_row = c.execute('SELECT expiry, banned FROM tokens WHERE token = ?', (token,)).fetchone()
        if not token_row:
            logging.warning(f"Attempt to stream with non-existent token '{token}' from IP {ip}.")
            return abort(403, 'Invalid token')
        
        expiry_str, banned_status = token_row
        if banned_status:
            logging.warning(f"Attempt to stream with banned token '{token}' from IP {ip}.")
            return abort(403, 'Invalid or banned token')
        
        if datetime.utcnow().isoformat() > expiry_str:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
            conn.commit()
            logging.warning(f"Expired token '{token}' used for stream by IP {ip}. Token banned.")
            return abort(403, 'Token expired')

        # Device limit check (redundant from playlist but good for direct stream access attempts)
        if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
            current_devices = c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0]
            if current_devices >= MAX_DEVICES:
                c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,))
                conn.commit()
                logging.warning(f"Device limit exceeded for token '{token}' during stream access by IP {ip}. Token banned.")
                return abort(403, 'Device limit exceeded')
            c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
            conn.commit() # Commit the new IP registration
            logging.info(f"New device (IP: {ip}) registered for token '{token}' during stream access. Total devices: {current_devices + 1}")

        # Find the channel URL based on UUID
        original_stream_url = None
        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                original_stream_url = url.strip()
                break
        
        if not original_stream_url:
            logging.warning(f"Stream not found for channel ID {channel_id} (requested by token '{token}', IP {ip}).")
            return abort(404, 'Stream not found')

        logging.info(f"Proxying stream for channel ID {channel_id} (token: {token}, IP: {ip})")
        # Fetch and rewrite the content of the actual stream playlist (master or media)
        rewritten_content = fetch_and_rewrite(original_stream_url)
        return Response(rewritten_content, content_type='application/vnd.apple.mpegurl')

@app.route('/segment')
def segment():
    url = request.args.get('url')
    if not url:
        logging.warning(f"Segment request with missing URL from IP {request.remote_addr}.")
        return abort(400, 'Segment URL missing')
    try:
        # Pass User-Agent to the upstream server
        headers = {'User-Agent': request.headers.get('User-Agent', 'Mozilla/5.0')}
        res = requests.get(url, headers=headers, stream=True, timeout=10)
        res.raise_for_status() # Raise an exception for bad status codes
        
        # Stream the content directly to the client
        # Use res.headers.get('Content-Type') to preserve the original content type
        logging.debug(f"Streaming segment from {url} to {request.remote_addr}")
        return Response(stream_with_context(res.iter_content(chunk_size=8192)), # Increased chunk size for efficiency
                        content_type=res.headers.get('Content-Type', 'application/octet-stream'))
    except requests.exceptions.Timeout:
        logging.error(f"Timeout fetching segment from {url} for IP {request.remote_addr}.")
        return abort(504, 'Segment fetch timed out')
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch segment from {url} for IP {request.remote_addr}: {e}")
        return abort(500, f'Failed to fetch segment: {e}')
    except Exception as e:
        logging.critical(f"An unexpected error occurred in segment proxy for {url}: {e}")
        return abort(500, 'An unexpected error occurred')


@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    token = None
    if request.method == 'POST':
        # Generate a unique token
        token = uuid.uuid4().hex[:12] # Generate a 12-character hex string
        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat() # 30-day expiry
        with sqlite3.connect(DB) as conn:
            conn.execute('INSERT INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'user'))
            conn.commit()
        logging.info(f"New user token '{token}' generated and added.")
    return render_template('unlock.html', token=token)

@app.route('/not-allowed')
def not_allowed():
    return render_template('not_allowed.html')

if __name__ == '__main__':
    # It's recommended to run Flask apps with a production WSGI server (e.g., Gunicorn, uWSGI)
    # instead of app.run() for production deployments.
    # Also, ensure HTTPS is configured in production, typically via a reverse proxy.
    logging.info("Starting Flask application...")
    app.run(debug=True, host='0.0.0.0', port=5000) # Listen on all interfaces for easier testing
