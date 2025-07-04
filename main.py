from flask import Flask, request, render_template, redirect, url_for, session, make_response
import sqlite3
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = "change_this_secret_key"

DATABASE = "db.sqlite3"
MAX_DEVICES = 4
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        stream_url TEXT,
        logo_url TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT,
        ip TEXT,
        user_agent TEXT,
        accessed_at TEXT
    )''')
    conn.commit()
    conn.close()

@app.before_request
def before_request():
    init_db()

@app.route("/")
def home():
    return redirect(url_for("unlock"))

@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    token = None
    if request.method == "POST":
        token = str(uuid.uuid4())
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO tokens (token, created_at) VALUES (?, ?)", (token, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    return render_template("unlock.html", token=token)

@app.route("/iptvplaylist.m3u")
def serve_playlist():
    token = request.args.get("token")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    if not token:
        return "Token required", 403

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM tokens WHERE token = ?", (token,))
    token_valid = c.fetchone()

    if not token_valid:
        return "Invalid token", 403

    # Check existing devices
    c.execute("SELECT DISTINCT ip FROM access_logs WHERE token = ?", (token,))
    unique_ips = [row[0] for row in c.fetchall()]
    if ip not in unique_ips and len(unique_ips) >= MAX_DEVICES:
        return "Device limit reached for this token", 403

    # Log access
    c.execute("INSERT INTO access_logs (token, ip, user_agent, accessed_at) VALUES (?, ?, ?, ?)",
              (token, ip, ua, datetime.now().isoformat()))
    
    # Get channels
    c.execute("SELECT name, stream_url, logo_url FROM channels")
    channels = c.fetchall()
    conn.commit()
    conn.close()

    # Build M3U Playlist
    playlist = "#EXTM3U\n"
    for name, url, logo in channels:
        playlist += f'#EXTINF:-1 tvg-logo="{logo}",{name}\n{url}\n'

    response = make_response(playlist)
    response.headers['Content-Type'] = 'audio/x-mpegurl'
    return response

# ---------------------- ADMIN --------------------------

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    if request.method == "POST":
        name = request.form["name"]
        stream_url = request.form["stream_url"]
        logo_url = request.form["logo_url"]
        c.execute("INSERT INTO channels (name, stream_url, logo_url) VALUES (?, ?, ?)",
                  (name, stream_url, logo_url))
        conn.commit()

    c.execute("SELECT * FROM channels")
    channels = c.fetchall()
    conn.close()
    return render_template("admin.html", channels=channels)

@app.route("/delete/<int:channel_id>")
def delete_channel(channel_id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == ADMIN_USER and request.form["password"] == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("admin"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))
