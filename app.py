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

# ------------------------ DB INIT ------------------------ #
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_by TEXT DEFAULT 'admin')''')
        c.execute('''CREATE TABLE IF NOT EXISTS token_ips (token TEXT, ip TEXT, UNIQUE(token, ip))''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, stream_url TEXT, logo_url TEXT, original_url TEXT, is_restreamed INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_time REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS restream_processes (channel_id INTEGER PRIMARY KEY, pid INTEGER)''')
init_db()

# ------------------------ RESTREAM FUNCTIONS ------------------------ #
def start_restream(channel_id, original_url, restream_url):
    try:
        # Store the original URL before restreaming
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute('UPDATE channels SET original_url = ?, is_restreamed = 1 WHERE id = ?', 
                     (original_url, channel_id))
            conn.commit()

        # FFmpeg command for restreaming (adjust as needed)
        cmd = [
            'ffmpeg',
            '-i', original_url,
            '-c', 'copy',       # Copy all streams without re-encoding
            '-f', 'mpegts',     # Output format
            restream_url
        ]
        
        # Start the process and store the PID
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
                    os.kill(pid, 9)  # Forcefully kill the process
                except ProcessLookupError:
                    pass  # Process already dead
                
            # Reset the channel to original URL
            c.execute('SELECT original_url FROM channels WHERE id = ?', (channel_id,))
            original_url = c.fetchone()[0]
            if original_url:
                c.execute('UPDATE channels SET stream_url = ?, is_restreamed = 0 WHERE id = ?', 
                         (original_url, channel_id))
            
            # Clean up
            c.execute('DELETE FROM restream_processes WHERE channel_id = ?', (channel_id,))
            conn.commit()
            
    except Exception as e:
        print(f"Error stopping restream for channel {channel_id}: {e}")

# ------------------------ RESTREAM ROUTES ------------------------ #
@app.route('/admin/restream/<int:channel_id>')
@login_required
def restream_channel(channel_id):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        
        # Get the channel details
        c.execute('SELECT id, name, stream_url FROM channels WHERE id = ?', (channel_id,))
        channel = c.fetchone()
        if not channel:
            return abort(404, 'Channel not found')
        
        # Generate a new stream URL on your server
        restream_url = f"http://{request.host}/restream/{channel_id}"
        
        # Start restreaming in a separate thread
        threading.Thread(target=start_restream, args=(channel_id, channel[2], restream_url), daemon=True).start()
        
        # Update the database to use the new URL immediately
        c.execute('UPDATE channels SET stream_url = ? WHERE id = ?', (restream_url, channel_id))
        conn.commit()
        
    return redirect('/admin')

@app.route('/admin/stop_restream/<int:channel_id>')
@login_required
def stop_restream_channel(channel_id):
    stop_restream(channel_id)
    return redirect('/admin')

@app.route('/restream/<int:channel_id>')
def serve_restream(channel_id):
    # This endpoint would typically be handled by your streaming server
    # For this example, we'll proxy the request to the original URL
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

# ------------------------ LOGIN SYSTEM ------------------------ #
# ... [keep all your existing login system code unchanged] ...

# ------------------------ ADMIN PANEL ------------------------ #
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            # ... [keep all your existing POST handling code] ...
            pass

        c.execute('SELECT * FROM tokens')
        tokens = c.fetchall()
        token_data = [(t[0], t[1], c.execute('SELECT COUNT(*) FROM token_ips WHERE token=?', (t[0],)).fetchone()[0], t[2], t[3]) for t in tokens]
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
        logs = c.fetchall()
        c.execute('SELECT id, name, stream_url, logo_url, is_restreamed FROM channels')
        channels = c.fetchall()
        return render_template('admin.html', tokens=token_data, logs=logs, channels=channels)

# ... [keep all your other existing routes and functions unchanged] ...

if __name__ == '__main__':
    # Clean up any running restream processes on startup
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM restream_processes')
        conn.execute('UPDATE channels SET is_restreamed = 0')
        conn.commit()
    app.run(debug=True, port=5000)
