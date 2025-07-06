from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey' # IMPORTANT: Change this to a strong, random key in production!
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300 # seconds (5 minutes)

# User-Agents or keywords commonly associated with sniffers/rippers
SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
# User-Agents commonly associated with allowed IPTV players
ALLOWED_AGENTS = ['ottnavigator', 'test', 'vlc', 'Tivimate'] # 'test' included based on your logs, but consider if it's a real player

def init_db():
    """Initializes the SQLite database tables if they don't exist."""
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
        conn.commit()
init_db()

def is_sniffer(ip, ua):
    """
    Checks if the user agent indicates a sniffer or an disallowed agent.
    Returns True if it's a sniffer or not an allowed agent.
    """
    # Check for known sniffer keywords
    if any(s in ua for s in SNIFFERS):
        return True
    # Check if the user agent is NOT one of the allowed agents
    if not any(agent in ua for agent in ALLOWED_AGENTS):
        return True
    return False

def log_block(c, ip, token, ua, ref):
    """Logs the blocking of an IP and sets its unblock time."""
    unblock_time = time.time() + BLOCK_DURATION
    c.execute("INSERT OR REPLACE INTO blocked_ips(ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
    c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), ip, token or 'unknown', ua, ref))

def validate_token(c, token, ip):
    """
    Validates a given token and manages device access.
    Returns (True, "Valid") if token is valid, otherwise (False, "Reason").
    """
    row = c.execute("SELECT expiry, banned FROM tokens WHERE token = ?", (token,)).fetchone()
    if not row:
        return False, "Token not found"
    expiry, banned = row
    if banned:
        return False, "Token banned"
    if datetime.fromisoformat(expiry) < datetime.utcnow():
        return False, "Token expired"

    # Check device limit
    # First, ensure this IP is associated with the token
    if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
        count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0]
        if count >= MAX_DEVICES:
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,)) # Ban the token if device limit exceeded
            return False, "Device limit exceeded for this token"
        c.execute('INSERT INTO token_ips(token, ip) VALUES (?, ?)', (token, ip))
    return True, "Valid"

def login_required(f):
    """Decorator to protect admin routes."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login route."""
    if request.method == 'POST':
        # IMPORTANT: Hardcoded credentials for simplicity. Use a secure method (e.g., environment variables, config file, database) in production.
        if request.form['username'] == 'admin' and request.form['password'] == 'admin':
            session['admin'] = True
            return redirect('/admin')
        return 'Invalid credentials'
    # Assuming you have a templates/login.html
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Admin logout route."""
    session.pop('admin', None)
    return redirect('/login')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    """Admin panel for managing tokens, channels, and viewing logs."""
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
                    # Note: verify=False is used here. In production, consider proper SSL verification.
                    res = requests.get(m3u_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
                    res.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                    parse_m3u_lines(res.text.splitlines(), c)
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] M3U fetch failed: {e}")
                except Exception as e:
                    print(f"[ERROR] M3U parsing error: {e}")
            conn.commit()

        # Fetch data for rendering the admin page
        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        # Include current device count and ban status for each token
        token_data = []
        for t in tokens:
            token_str, expiry, banned, created_by = t[0], t[1], t[2], t[3]
            device_count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token_str,)).fetchone()[0]
            token_data.append((token_str, expiry, device_count, banned, created_by))

        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
    # Assuming you have a templates/admin.html
    return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

@app.route('/admin/delete_token/<token>')
@login_required
def delete_token(token):
    """Deletes a token and its associated IPs."""
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM tokens WHERE token = ?", (token,))
        conn.execute("DELETE FROM token_ips WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/unban/<token>')
@login_required
def unban_token(token):
    """Unbans a token."""
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE tokens SET banned = 0 WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/delete_channel/<int:id>')
@login_required
def delete_channel(id):
    """Deletes a channel."""
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM channels WHERE id = ?', (id,))
        conn.commit()
    return redirect('/admin')

def parse_m3u_lines(lines, c):
    """Parses M3U lines and inserts channels into the database."""
    name, logo = None, ''
    for line in lines:
        if line.startswith('#EXTINF:'):
            try:
                parts = line.split(',', 1)
                name = parts[1].strip()
                # Extract tvg-logo if present
                logo_match = [part for part in parts[0].split() if part.startswith('tvg-logo=')]
                if logo_match:
                    logo = logo_match[0].split('=', 1)[1].strip('"')
                else:
                    logo = ''
            except IndexError:
                # Handle cases where EXTINF line might be malformed
                print(f"[WARNING] Malformed #EXTINF line: {line}")
                name, logo = None, '' # Reset to avoid using partial data
                continue
        elif line.startswith('http'):
            url = line.strip()
            if name and url:
                c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, url, logo))
                name, logo = None, '' # Reset for the next channel

@app.route('/iptvplaylist.m3u')
def playlist():
    """Generates the main M3U playlist with proxied URLs."""
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        # Check for IP block
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row:
            unblock_time = row[0]
            if time.time() < unblock_time:
                return render_template('sniffer_blocked.html'), 403
            else:
                # IP block has expired, remove it
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        # Sniffer detection
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit() # Ensure block is recorded immediately
            return render_template('sniffer_blocked.html'), 403

        # Token validation
        valid, reason = validate_token(c, token, ip)
        conn.commit() # Commit token_ips changes or banned status
        if not valid:
            return abort(403, reason)

        # Fetch channels
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()
        # No need to commit here as no changes were made to channels

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        # Generate a unique UUID for each channel's stream URL
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip()))
        # Construct the proxied URL for the client
        proxy = f"https://{request.host}/stream/{uid}?token={token}"
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(proxy)

    return Response('\n'.join(lines), mimetype='application/x-mpegURL')

@app.route('/stream/<uuid:channel_id>')
def stream(channel_id):
    """Proxies the main stream or nested HLS playlists."""
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row:
            unblock_time = row[0]
            if time.time() < unblock_time:
                return render_template('sniffer_blocked.html'), 403
            else:
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        valid, reason = validate_token(c, token, ip)
        conn.commit()
        if not valid:
            return abort(403, reason)

        # Find the original stream URL corresponding to the channel_id UUID
        original_stream_url = None
        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                original_stream_url = url.strip()
                break

        if not original_stream_url:
            return abort(404, 'Stream not found for this channel ID')

        try:
            # Fetch the actual stream from the source
            # Note: verify=False is used here. In production, consider proper SSL verification.
            res = requests.get(original_stream_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, stream=True, verify=False)
            res.raise_for_status() # Raise an exception for HTTP errors

            content_type = res.headers.get('Content-Type', '')

            # If it's an HLS playlist (m3u8), rewrite segment/nested playlist URLs
            if '.m3u8' in original_stream_url or 'application/vnd.apple.mpegurl' in content_type:
                playlist_text = res.text
                new_lines = []
                base_url = original_stream_url.rsplit('/', 1)[0] # Get the base URL for relative paths

                for line in playlist_text.splitlines():
                    line_strip = line.strip()
                    if line_strip.endswith('.ts'):
                        # Rewrite .ts segments to go through our proxy
                        segment_name = line_strip.split('/')[-1]
                        proxied_segment_url = f"https://{request.host}/segment/{channel_id}/{segment_name}?token={token}"
                        new_lines.append(proxied_segment_url)
                    elif line_strip.startswith('#'):
                        # Keep HLS directives as is
                        new_lines.append(line_strip)
                    elif '.m3u8' in line_strip:
                        # Rewrite nested m3u8 playlists (e.g., for different resolutions)
                        # Assumes nested m3u8 paths are relative to the original stream URL
                        nested_playlist_name = line_strip.split('/')[-1]
                        proxied_nested_url = f"https://{request.host}/stream/{channel_id}/{nested_playlist_name}?token={token}"
                        new_lines.append(proxied_nested_url)
                    else:
                        # For other lines (e.g., absolute URLs that are not .ts or .m3u8, or relative paths that are not .ts)
                        # Attempt to resolve relative URLs to absolute if they are not already.
                        if not line_strip.startswith('http') and '/' in line_strip:
                            # Heuristic: if it's a path, assume it's relative to the original base URL
                            new_lines.append(f"{base_url}/{line_strip}")
                        else:
                            new_lines.append(line_strip)

                return Response('\n'.join(new_lines), mimetype='application/x-mpegURL')
            else:
                # For non-HLS streams (e.g., direct video files)
                def generate():
                    for chunk in res.iter_content(chunk_size=1024):
                        yield chunk
                return Response(generate(), content_type=content_type)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Error fetching stream for channel {channel_id} from {original_stream_url}: {e}")
            return abort(500, 'Error fetching stream from source')
        except Exception as e:
            print(f"[ERROR] Unexpected error in stream route: {e}")
            return abort(500, 'Internal server error during stream processing')

    return abort(404, 'Stream not found') # Should ideally be caught by original_stream_url check


@app.route('/stream/<uuid:channel_id>/<path:nested_playlist_name>')
def stream_nested(channel_id, nested_playlist_name):
    """Handles requests for nested HLS playlists."""
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row:
            unblock_time = row[0]
            if time.time() < unblock_time:
                return render_template('sniffer_blocked.html'), 403
            else:
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        valid, reason = validate_token(c, token, ip)
        conn.commit()
        if not valid:
            return abort(403, reason)

        original_stream_url = None
        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                original_stream_url = url.strip()
                break

        if not original_stream_url:
            return abort(404, 'Stream not found for this channel ID')

        # Construct the full URL for the nested playlist
        base_url = original_stream_url.rsplit('/', 1)[0]
        full_nested_url = f"{base_url}/{nested_playlist_name}"

        try:
            res = requests.get(full_nested_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, stream=True, verify=False)
            res.raise_for_status()
            content_type = res.headers.get('Content-Type', '')

            playlist_text = res.text
            new_lines = []
            # The base URL for segments relative to this nested playlist might be different
            nested_base_url = full_nested_url.rsplit('/', 1)[0]

            for line in playlist_text.splitlines():
                line_strip = line.strip()
                if line_strip.endswith('.ts'):
                    segment_name = line_strip.split('/')[-1]
                    proxied_segment_url = f"https://{request.host}/segment/{channel_id}/{segment_name}?token={token}"
                    new_lines.append(proxied_segment_url)
                elif line_strip.startswith('#'):
                    new_lines.append(line_strip)
                elif '.m3u8' in line_strip:
                    # If there are even deeper nested playlists, handle them
                    deeper_nested_playlist_name = line_strip.split('/')[-1]
                    proxied_deeper_url = f"https://{request.host}/stream/{channel_id}/{deeper_nested_playlist_name}?token={token}"
                    new_lines.append(proxied_deeper_url)
                else:
                    # Attempt to resolve other relative URLs (e.g., keys, other manifest files)
                    if not line_strip.startswith('http') and '/' in line_strip:
                        new_lines.append(f"{nested_base_url}/{line_strip}")
                    else:
                        new_lines.append(line_strip)

            return Response('\n'.join(new_lines), mimetype='application/x-mpegURL')

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Error fetching nested playlist for channel {channel_id} from {full_nested_url}: {e}")
            return abort(500, 'Error fetching nested stream')
        except Exception as e:
            print(f"[ERROR] Unexpected error in stream_nested route: {e}")
            return abort(500, 'Internal server error during nested stream processing')

    return abort(404, 'Nested stream not found')


@app.route('/segment/<uuid:channel_id>/<path:segment>')
def segment_proxy(channel_id, segment):
    """Proxies individual HLS segments (.ts files)."""
    token = request.args.get('token', '').strip()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    ref = request.referrer or ''

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row:
            unblock_time = row[0]
            if time.time() < unblock_time:
                return render_template('sniffer_blocked.html'), 403
            else:
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html'), 403

        valid, reason = validate_token(c, token, ip)
        conn.commit()
        if not valid:
            return abort(403, reason)

        original_stream_url = None
        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                original_stream_url = url.strip()
                break

        if not original_stream_url:
            return abort(404, 'Original stream URL not found for this channel ID')

        try:
            # Determine the base URL for the segments
            # This logic assumes the segment is relative to the *last* known M3U playlist's URL.
            # This is a common pattern in HLS.
            # You might need to refine this if your source M3U uses complex relative paths.
            base_url = original_stream_url.rsplit('/', 1)[0]
            segment_url = f"{base_url}/{segment}"

            # Make the request to the original segment URL
            # Note: verify=False is used here. In production, consider proper SSL verification.
            res = requests.get(segment_url, headers={'User-Agent': 'Mozilla/5.0'}, stream=True, timeout=10, verify=False)
            res.raise_for_status()

            # Stream the content back to the client
            return Response(stream_with_context(res.iter_content(1024)), content_type=res.headers.get('Content-Type'))
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Segment fetch error for channel {channel_id}, segment {segment}: {e}")
            return abort(500, 'Segment fetch error from source')
        except Exception as e:
            print(f"[ERROR] Unexpected error in segment_proxy route: {e}")
            return abort(500, 'Internal server error during segment proxy')
    return abort(404, 'Segment not found')


@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    """Allows users to generate a temporary token."""
    token = None
    if request.method == 'POST':
        token = uuid.uuid4().hex[:12] # Generate a short, random token
        # This token is set to expire in 30 days
        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
        with sqlite3.connect(DB) as conn:
            conn.execute('INSERT INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'user'))
            conn.commit()
    # Assuming you have a templates/unlock.html
    return render_template('unlock.html', token=token)

@app.route('/not-allowed')
def not_allowed():
    """Generic not allowed page (not directly used by your current logic, but good to have)."""
    # Assuming you have a templates/not_allowed.html
    return render_template('not_allowed.html')

if __name__ == '__main__':
    # For production, do NOT use debug=True.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, port=5000)
