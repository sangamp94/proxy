from flask import Flask, request, redirect, render_template, session, abort, Response, stream_with_context, url_for
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
# IMPORTANT: Change this to a strong, random key in production!
# For production, consider getting this from an environment variable:
# app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_long_and_random_fallback_key_that_is_also_secret')
app.secret_key = 'supersecretkey' # REMEMBER TO CHANGE THIS!

DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300 # seconds (5 minutes)

# User-Agents or keywords commonly associated with sniffers/rippers
SNIFFERS = ['httpcanary', 'fiddler', 'charles', 'mitm', 'wireshark', 'packet', 'debugproxy', 'curl', 'python', 'wget', 'postman', 'reqable']
# User-Agents commonly associated with allowed IPTV players
ALLOWED_AGENTS = ['ottnavigator', 'test', 'vlc', 'tivimate'] # 'test' included based on your logs, but consider if it's a real player

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
    # Convert UA to lowercase once for all checks
    ua_lower = ua.lower()
    
    # Check for known sniffer keywords
    if any(s in ua_lower for s in SNIFFERS):
        return True
    
    # Check if the user agent is NOT one of the allowed agents
    # This means if it doesn't contain ANY of the ALLOWED_AGENTS, it's considered disallowed.
    if not any(agent in ua_lower for agent in ALLOWED_AGENTS):
        return True
    
    return False

def log_block(c, ip, token, ua, ref):
    """Logs the blocking of an IP and sets its unblock time."""
    unblock_time = time.time() + BLOCK_DURATION
    # Use INSERT OR REPLACE to update unblock_time if IP is already blocked
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
    expiry_str, banned = row
    
    if banned:
        return False, "Token banned"
    
    try:
        # Parse expiry from ISO format string to datetime object
        expiry_dt = datetime.fromisoformat(expiry_str)
    except ValueError:
        # Handle malformed expiry dates, consider banning token or logging
        print(f"[ERROR] Malformed expiry date for token {token}: {expiry_str}")
        return False, "Invalid token expiry data"
    
    if expiry_dt < datetime.utcnow():
        # Token has expired, optionally mark as banned or delete
        # c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,)) # Or just return expired
        return False, "Token expired"

    # Check device limit
    # First, ensure this IP is associated with the token
    if not c.execute('SELECT 1 FROM token_ips WHERE token = ? AND ip = ?', (token, ip)).fetchone():
        count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token = ?', (token,)).fetchone()[0]
        if count >= MAX_DEVICES:
            # Ban the token if device limit exceeded for a new device trying to connect
            c.execute('UPDATE tokens SET banned = 1 WHERE token = ?', (token,)) 
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
        # IMPORTANT: Hardcoded credentials. Use hashed passwords in a DB for production!
        if request.form['username'] == 'admin' and request.form['password'] == 'admin':
            session['admin'] = True
            return redirect('/admin')
        return render_template('login.html', error='Invalid credentials')
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
    message = None
    error = None

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            if 'add_token' in request.form:
                token = request.form['token'].strip()
                try:
                    days = int(request.form['days'])
                    if days <= 0:
                        raise ValueError("Days must be positive.")
                    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
                    c.execute('INSERT OR REPLACE INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'admin'))
                    conn.commit()
                    message = f"Token '{token}' added/renewed successfully, expiring in {days} days."
                except ValueError as e:
                    error = f"Error adding/renewing token: {e}"
                except sqlite3.Error as e:
                    error = f"Database error adding token: {e}"

            elif 'add_channel' in request.form:
                name = request.form['name'].strip()
                stream = request.form['stream'].strip()
                logo = request.form['logo'].strip()
                if not name or not stream:
                    error = "Channel Name and Stream URL are required."
                else:
                    try:
                        c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, stream, logo))
                        conn.commit()
                        message = f"Channel '{name}' added successfully."
                    except sqlite3.Error as e:
                        error = f"Database error adding channel: {e}"
            
            elif 'm3u_url_import' in request.form: # Changed button name to avoid conflict with m3u_url field
                m3u_url = request.form['m3u_url'].strip()
                if not m3u_url:
                    error = "M3U URL cannot be empty."
                else:
                    try:
                        # Note: verify=False is used here. In production, consider proper SSL verification.
                        res = requests.get(m3u_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15, verify=False)
                        res.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                        channels_parsed = parse_m3u_lines(res.text.splitlines(), c)
                        conn.commit() # Commit after parsing all lines
                        message = f"Successfully imported {channels_parsed} channels from M3U."
                    except requests.exceptions.RequestException as e:
                        error = f"[ERROR] M3U fetch failed: {e}. Check URL or network."
                    except Exception as e:
                        error = f"[ERROR] M3U parsing error: {e}. Check M3U format."

        # Fetch data for rendering the admin page
        c.execute('SELECT * FROM tokens')
        tokens_raw = c.fetchall()
        
        # Include current device count and ban status for each token
        token_data = []
        for t in tokens_raw:
            token_str, expiry, banned, created_by = t[0], t[1], t[2], t[3]
            device_count = c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (token_str,)).fetchone()[0]
            token_data.append((token_str, expiry, device_count, banned, created_by))

        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()

        # Fetch blocked IPs to show in admin panel and allow unblocking
        c.execute('SELECT ip, unblock_time FROM blocked_ips')
        blocked_ips = []
        current_time = time.time()
        for ip, unblock_t in c.fetchall():
            if current_time < unblock_t:
                blocked_ips.append((ip, datetime.fromtimestamp(unblock_t).strftime('%Y-%m-%d %H:%M:%S UTC')))
            else:
                # Clean up expired blocks
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit() # Commit cleanup of expired blocks

        c.execute('SELECT * FROM channels')
        channels = c.fetchall()
        
    return render_template('admin.html', 
                           tokens=token_data, 
                           logs=logs, 
                           channels=channels, 
                           blocked_ips=blocked_ips, # Pass blocked IPs to template
                           MAX_DEVICES=MAX_DEVICES, 
                           datetime=datetime, # Pass datetime object for formatting in template
                           message=message, 
                           error=error)

@app.route('/admin/delete_token/<token>')
@login_required
def delete_token(token):
    """Deletes a token and its associated IPs."""
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM tokens WHERE token = ?", (token,))
        c.execute("DELETE FROM token_ips WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/unban_token/<token>') # Renamed to avoid clash if unban_ip is added
@login_required
def unban_token(token):
    """Unbans a token."""
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE tokens SET banned = 0 WHERE token = ?", (token,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/unblock_ip/<ip_address>')
@login_required
def unblock_ip(ip_address):
    """Unblocks a specific IP address immediately."""
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip_address,))
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

@app.route('/admin/download_playlist')
@login_required
def download_playlist_template():
    """Generates a sample M3U playlist for download by admin,
    with a placeholder for the token and dynamic host."""
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        # For admin download, use a placeholder for the token and a generic channel_id
        # The actual /stream route handles the UUID generation and token validation
        # Use request.host to get the current domain
        # Generate a placeholder UUID to make the URL look valid but indicate it's a template
        # A static dummy UUID for templates is fine, e.g., '00000000-0000-0000-0000-000000000000'
        # Or, just show the actual channel_id which can be derived, but it's less user-friendly for a template.
        # Let's use a placeholder string for the UUID to be clearer this is a template.
        proxy = f"https://{request.host}/stream/CHANNEL_UUID_PLACEHOLDER?token=YOUR_TOKEN_HERE"
        lines.append(f'#EXTINF:-1 tvg-logo="{logo}",{name}')
        lines.append(proxy)

    playlist_content = '\n'.join(lines)
    response = Response(playlist_content, mimetype='application/x-mpegURL')
    response.headers['Content-Disposition'] = 'attachment; filename=iptv_playlist_template.m3u'
    return response

def parse_m3u_lines(lines, c):
    """Parses M3U lines and inserts channels into the database.
    Returns the count of channels added."""
    name, logo = None, ''
    channels_added = 0
    for line in lines:
        line = line.strip() # Strip whitespace from lines
        if line.startswith('#EXTINF:'):
            try:
                parts = line.split(',', 1)
                # Use regex or more robust splitting if attributes are complex
                # For example, to get name after last comma if it contains commas
                name_part = parts[1].strip() if len(parts) > 1 else ''
                name = name_part

                # Extract tvg-logo if present, case-insensitive and handling quotes
                logo_match_str = [part for part in parts[0].split() if 'tvg-logo=' in part.lower()]
                if logo_match_str:
                    logo_val = logo_match_str[0].split('=', 1)[1].strip('"\'')
                    logo = logo_val
                else:
                    logo = ''
            except IndexError:
                print(f"[WARNING] Malformed #EXTINF line (IndexError): {line}")
                name, logo = None, '' # Reset to avoid using partial data
                continue
        elif line.startswith('http'):
            url = line
            if name and url:
                try:
                    c.execute('INSERT INTO channels(name, stream_url, logo_url) VALUES (?, ?, ?)', (name, url, logo))
                    channels_added += 1
                except sqlite3.IntegrityError: # Handle potential duplicates if name+url is unique
                    print(f"[INFO] Skipping duplicate channel: {name} - {url}")
                except Exception as e:
                    print(f"[ERROR] Error inserting channel {name} ({url}): {e}")
                finally:
                    name, logo = None, '' # Reset for the next channel
    return channels_added

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
                return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(unblock_time).strftime('%H:%M:%S')), 403
            else:
                # IP block has expired, remove it
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit() # Commit removal of expired block

        # Sniffer detection
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit() # Ensure block is recorded immediately
            return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(time.time() + BLOCK_DURATION).strftime('%H:%M:%S')), 403

        # Token validation
        valid, reason = validate_token(c, token, ip)
        conn.commit() # Commit token_ips changes or banned status
        if not valid:
            # Log this access attempt
            c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                      (datetime.utcnow().isoformat(), ip, token or 'none_provided', ua, ref))
            conn.commit()
            return abort(403, reason)

        # Log successful token access
        c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        conn.commit()

        # Fetch channels
        c.execute('SELECT name, stream_url, logo_url FROM channels')
        channels = c.fetchall()

    lines = ['#EXTM3U']
    for name, url, logo in channels:
        # Generate a unique UUID for each channel's stream URL consistently
        # Use url_for to build the proxy URL, making it more robust
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip()))
        proxy = url_for('stream', channel_id=uid, token=token, _external=True)
        lines.append(f'#EXTINF:-1 tvg-id="{name}" tvg-name="{name}" tvg-logo="{logo}",{name}') # Added tvg-id/name for better player compatibility
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

        # Check for IP block (duplicate logic, could be refactored into a decorator)
        row = c.execute("SELECT unblock_time FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row:
            unblock_time = row[0]
            if time.time() < unblock_time:
                return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(unblock_time).strftime('%H:%M:%S')), 403
            else:
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()

        # Sniffer detection (duplicate logic, could be refactored into a decorator)
        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(time.time() + BLOCK_DURATION).strftime('%H:%M:%S')), 403

        valid, reason = validate_token(c, token, ip)
        conn.commit()
        if not valid:
            c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                      (datetime.utcnow().isoformat(), ip, token or 'none_provided', ua, ref))
            conn.commit()
            return abort(403, reason)
        
        # Log successful stream access (potentially too chatty, consider logging less frequently for streams)
        c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        conn.commit()

        # Find the original stream URL corresponding to the channel_id UUID
        original_stream_url = None
        # Optimization: Only fetch stream_urls once and build a UUID map if channels list is large.
        # For now, iterating through all channels is acceptable for smaller lists.
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
            # Add Accept header if needed by source
            headers = {'User-Agent': 'Mozilla/5.0'} # Use a generic user agent for upstream requests
            range_header = request.headers.get('Range') # Pass Range header for seeking
            if range_header:
                headers['Range'] = range_header

            res = requests.get(original_stream_url, headers=headers, timeout=15, stream=True, verify=False)
            res.raise_for_status() # Raise an exception for HTTP errors

            content_type = res.headers.get('Content-Type', '')

            # If it's an HLS playlist (m3u8), rewrite segment/nested playlist URLs
            # Using 'application/vnd.apple.mpegurl' for robustness
            if 'm3u8' in original_stream_url or 'application/vnd.apple.mpegurl' in content_type or 'mpegurl' in content_type:
                playlist_text = res.text
                new_lines = []
                # Use urllib.parse.urljoin for more robust relative URL resolution
                from urllib.parse import urljoin
                base_url = original_stream_url.rsplit('/', 1)[0] + '/' # Ensure trailing slash for urljoin

                for line in playlist_text.splitlines():
                    line_strip = line.strip()
                    if line_strip.startswith('#'):
                        new_lines.append(line_strip) # Keep HLS directives as is
                    elif line_strip.endswith('.ts') or line_strip.endswith('.aac') or line_strip.endswith('.mp4'): # Common segment extensions
                        # Rewrite segments to go through our proxy
                        # Use urljoin to handle relative paths correctly
                        absolute_segment_url = urljoin(base_url, line_strip)
                        segment_name = absolute_segment_url.rsplit('/', 1)[-1] # Get filename including path if relative
                        
                        # Encode path segments if they contain special characters
                        from urllib.parse import quote
                        quoted_segment_path = '/'.join(quote(p, safe='') for p in absolute_segment_url[len(base_url):].split('/'))

                        proxied_segment_url = url_for('segment_proxy', channel_id=channel_id, segment=quoted_segment_path, token=token, _external=True)
                        new_lines.append(proxied_segment_url)
                    elif '.m3u8' in line_strip:
                        # Rewrite nested m3u8 playlists
                        absolute_nested_url = urljoin(base_url, line_strip)
                        nested_playlist_path = absolute_nested_url[len(base_url):] # Path relative to base
                        
                        from urllib.parse import quote
                        quoted_nested_path = '/'.join(quote(p, safe='') for p in nested_playlist_path.split('/'))
                        
                        proxied_nested_url = url_for('stream_nested', channel_id=channel_id, nested_playlist_name=quoted_nested_path, token=token, _external=True)
                        new_lines.append(proxied_nested_url)
                    else:
                        # For other lines (e.g., absolute URLs, or relative paths that are not .ts or .m3u8)
                        # Attempt to resolve relative URLs to absolute if they are not already.
                        if not line_strip.startswith('http://') and not line_strip.startswith('https://') and '/' in line_strip:
                             new_lines.append(urljoin(base_url, line_strip))
                        else:
                            new_lines.append(line_strip)

                # Return the rewritten playlist with correct content type
                resp = Response('\n'.join(new_lines), mimetype='application/x-mpegURL')
                # Copy relevant headers from source for playback compatibility (e.g., Cache-Control)
                for header, value in res.headers.items():
                    if header.lower() in ['content-type', 'content-length', 'transfer-encoding', 'connection', 'keep-alive']:
                        continue # Flask handles these or they are hop-by-hop
                    resp.headers[header] = value
                return resp
            else:
                # For non-HLS streams (e.g., direct video files)
                def generate():
                    # Stream the content in chunks
                    for chunk in res.iter_content(chunk_size=8192):
                        yield chunk
                
                resp = Response(generate(), content_type=content_type)
                # Copy all relevant headers from the original response
                for header, value in res.headers.items():
                    # Exclude hop-by-hop headers and Content-Encoding if you're not decompressing
                    if header.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive']:
                        resp.headers[header] = value
                
                resp.status_code = res.status_code # Preserve original status code (e.g., 206 for partial content)
                return resp
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Error fetching stream for channel {channel_id} from {original_stream_url}: {e}")
            return abort(500, 'Error fetching stream from source')
        except Exception as e:
            print(f"[ERROR] Unexpected error in stream route: {e}")
            return abort(500, 'Internal server error during stream processing')

    return abort(404, 'Stream not found') # Fallback, though usually caught above


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
                return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(unblock_time).strftime('%H:%M:%S')), 403
            else:
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(time.time() + BLOCK_DURATION).strftime('%H:%M:%S')), 403

        valid, reason = validate_token(c, token, ip)
        conn.commit()
        if not valid:
            c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                      (datetime.utcnow().isoformat(), ip, token or 'none_provided', ua, ref))
            conn.commit()
            return abort(403, reason)
        
        # Log successful nested stream access
        c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        conn.commit()

        original_stream_url = None
        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                original_stream_url = url.strip()
                break

        if not original_stream_url:
            return abort(404, 'Original stream URL not found for this channel ID')

        # Construct the full URL for the nested playlist
        from urllib.parse import urljoin, unquote
        # Unquote the nested_playlist_name if it was quoted in the incoming request
        decoded_nested_playlist_name = unquote(nested_playlist_name)

        # Get base URL of the *original* stream to correctly resolve nested paths
        original_base_url = original_stream_url.rsplit('/', 1)[0] + '/'
        full_nested_url = urljoin(original_base_url, decoded_nested_playlist_name)

        try:
            # Fetch the nested playlist
            headers = {'User-Agent': 'Mozilla/5.0'}
            res = requests.get(full_nested_url, headers=headers, timeout=15, stream=True, verify=False)
            res.raise_for_status()
            content_type = res.headers.get('Content-Type', '')

            playlist_text = res.text
            new_lines = []
            
            # The base URL for segments relative to this nested playlist might be the nested playlist's own base URL
            nested_playlist_base_url = full_nested_url.rsplit('/', 1)[0] + '/'

            for line in playlist_text.splitlines():
                line_strip = line.strip()
                if line_strip.startswith('#'):
                    new_lines.append(line_strip)
                elif line_strip.endswith('.ts') or line_strip.endswith('.aac') or line_strip.endswith('.mp4'):
                    # Rewrite segments to go through our proxy
                    absolute_segment_url = urljoin(nested_playlist_base_url, line_strip)
                    from urllib.parse import quote
                    # The 'segment' path must be relative to the original stream's base for consistent UUID lookup
                    # but should include the full path from the nested playlist
                    segment_path_relative_to_original_base = absolute_segment_url[len(original_base_url):]
                    quoted_segment_path = '/'.join(quote(p, safe='') for p in segment_path_relative_to_original_base.split('/'))

                    proxied_segment_url = url_for('segment_proxy', channel_id=channel_id, segment=quoted_segment_path, token=token, _external=True)
                    new_lines.append(proxied_segment_url)
                elif '.m3u8' in line_strip:
                    # If there are even deeper nested playlists, handle them recursively
                    absolute_deeper_nested_url = urljoin(nested_playlist_base_url, line_strip)
                    deeper_nested_playlist_path = absolute_deeper_nested_url[len(original_base_url):]
                    
                    from urllib.parse import quote
                    quoted_deeper_path = '/'.join(quote(p, safe='') for p in deeper_nested_playlist_path.split('/'))

                    proxied_deeper_url = url_for('stream_nested', channel_id=channel_id, nested_playlist_name=quoted_deeper_path, token=token, _external=True)
                    new_lines.append(proxied_deeper_url)
                else:
                    # Attempt to resolve other relative URLs (e.g., keys, other manifest files)
                    if not line_strip.startswith('http://') and not line_strip.startswith('https://') and '/' in line_strip:
                        new_lines.append(urljoin(nested_playlist_base_url, line_strip))
                    else:
                        new_lines.append(line_strip)
            
            resp = Response('\n'.join(new_lines), mimetype='application/x-mpegURL')
            for header, value in res.headers.items():
                if header.lower() in ['content-type', 'content-length', 'transfer-encoding', 'connection', 'keep-alive']:
                    continue
                resp.headers[header] = value
            return resp

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
                return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(unblock_time).strftime('%H:%M:%S')), 403
            else:
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()

        if is_sniffer(ip, ua):
            log_block(c, ip, token, ua, ref)
            conn.commit()
            return render_template('sniffer_blocked.html', ip=ip, unblock_time=datetime.fromtimestamp(time.time() + BLOCK_DURATION).strftime('%H:%M:%S')), 403

        valid, reason = validate_token(c, token, ip)
        conn.commit()
        if not valid:
            c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                      (datetime.utcnow().isoformat(), ip, token or 'none_provided', ua, ref))
            conn.commit()
            return abort(403, reason)
        
        # Log successful segment access (can be very chatty, consider disabling or sampling)
        c.execute("INSERT INTO logs(timestamp, ip, token, user_agent, referrer) VALUES (?, ?, ?, ?, ?)",
                  (datetime.utcnow().isoformat(), ip, token, ua, ref))
        conn.commit()

        original_stream_url = None
        c.execute('SELECT stream_url FROM channels')
        for (url,) in c.fetchall():
            if str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip())) == str(channel_id):
                original_stream_url = url.strip()
                break

        if not original_stream_url:
            return abort(404, 'Original stream URL not found for this channel ID')

        try:
            from urllib.parse import urljoin, unquote
            # Determine the base URL for the segments
            # This logic assumes the segment is relative to the *original M3U playlist's base URL*.
            # This is crucial for correctly resolving paths if nested playlists are involved.
            original_base_url = original_stream_url.rsplit('/', 1)[0] + '/'
            
            # Unquote the segment path that came in the URL
            decoded_segment_path = unquote(segment)
            segment_url = urljoin(original_base_url, decoded_segment_path)
            
            # Make the request to the original segment URL
            # Pass through relevant headers like Range for seeking
            headers = {'User-Agent': 'Mozilla/5.0'}
            range_header = request.headers.get('Range')
            if range_header:
                headers['Range'] = range_header

            # Note: verify=False is used here. In production, consider proper SSL verification.
            res = requests.get(segment_url, headers=headers, stream=True, timeout=15, verify=False)
            res.raise_for_status()

            # Stream the content back to the client
            # Copy all relevant headers including Content-Type, Content-Length, Accept-Ranges
            response = Response(stream_with_context(res.iter_content(8192)), content_type=res.headers.get('Content-Type'))
            response.status_code = res.status_code # Preserve status code (e.g., 206 Partial Content)

            for header, value in res.headers.items():
                # Exclude hop-by-hop headers and Content-Encoding if you're not decompressing
                if header.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive']:
                    response.headers[header] = value
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Segment fetch error for channel {channel_id}, segment {segment}: {e}")
            return abort(500, 'Segment fetch error from source')
        except Exception as e:
            print(f"[ERROR] Unexpected error in segment_proxy route: {e}")
            return abort(500, 'Internal server error during segment proxy')
    # This abort is logically unreachable if original_stream_url is None
    return abort(404, 'Segment not found (internal error)')


@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    """Allows users to generate a temporary token."""
    token = None
    if request.method == 'POST':
        # Generate a short, random token
        token = uuid.uuid4().hex[:12] 
        # This token is set to expire in 30 days
        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()
        try:
            with sqlite3.connect(DB) as conn:
                conn.execute('INSERT INTO tokens(token, expiry, created_by) VALUES (?, ?, ?)', (token, expiry, 'user'))
                conn.commit()
            message = f"Your new token is: {token}. It expires in 30 days. Save it securely!"
            playlist_url = url_for('playlist', token=token, _external=True)
            return render_template('unlock.html', token=token, message=message, playlist_url=playlist_url)
        except sqlite3.Error as e:
            error = f"Error generating token: {e}"
            return render_template('unlock.html', error=error)
            
    return render_template('unlock.html', token=token)

@app.route('/not-allowed')
def not_allowed():
    """Generic not allowed page (not directly used by your current logic, but good to have)."""
    return render_template('not_allowed.html')

if __name__ == '__main__':
    # For production, do NOT use debug=True.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, port=5000)
