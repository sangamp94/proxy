from flask import Flask, render_template, request, redirect, url_for, session, make_response
import sqlite3, uuid, os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY"

DB = "database.db"
MAX_DEVICES = 4
ADMIN_USER = "admin"
ADMIN_PASS = "password123"
TOKEN_EXPIRY_DAYS = 7

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY, expiry TEXT, banned INTEGER DEFAULT 0, created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS token_ip (
        token TEXT, ip TEXT, added_at TEXT,
        PRIMARY KEY(token, ip)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
        time TEXT, ip TEXT, token TEXT, user_agent TEXT, referrer TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, stream_url TEXT, logo_url TEXT
    )''')
    conn.commit()
    conn.close()

@app.before_request
def before_request():
    init_db()

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("admin"):
        return redirect(url_for("admin"))
    if request.method=="POST":
        if request.form["username"]==ADMIN_USER and request.form["password"]==ADMIN_PASS:
            session["admin"] = True
            return redirect(url_for("admin"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    token = None
    if request.method == "POST":
        token = str(uuid.uuid4().hex[:8])
        expiry = (datetime.now() + timedelta(days=TOKEN_EXPIRY_DAYS)).isoformat()
        conn = sqlite3.connect(DB); c = conn.cursor()
        c.execute("INSERT INTO tokens(token, expiry, created_at) VALUES (?, ?, ?)",
                  (token, expiry, datetime.now().isoformat()))
        conn.commit(); conn.close()
    return render_template("unlock.html", token=token)

@app.route("/admin", methods=["GET","POST"])
def admin():
    if not session.get("admin"):
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Add new token
    if request.method=="POST" and request.form.get("action")=="add_token":
        token = str(uuid.uuid4().hex[:8])
        expiry = (datetime.now()+timedelta(days=TOKEN_EXPIRY_DAYS)).isoformat()
        c.execute("INSERT INTO tokens(token,expiry,created_at) VALUES(?,?,?)", (token,expiry,datetime.now().isoformat()))
        conn.commit()

    # Handle actions
    act = request.args.get("action")
    t = request.args.get("token")
    if act and t:
        if act=="delete":
            c.execute("DELETE FROM tokens WHERE token=?", (t,))
        elif act=="ban":
            c.execute("UPDATE tokens SET banned=1 WHERE token=?", (t,))
        elif act=="renew":
            expiry = (datetime.now()+timedelta(days=TOKEN_EXPIRY_DAYS)).isoformat()
            c.execute("UPDATE tokens SET expiry=?, banned=0 WHERE token=?", (expiry,t))
        elif act=="reset_ip":
            c.execute("DELETE FROM token_ip WHERE token=?", (t,))
        conn.commit()

    # Retrieve tokens
    c.execute("SELECT token, expiry, banned FROM tokens")
    tokens = c.fetchall()
    token_list = []
    for tk, exp, ban in tokens:
        c.execute("SELECT COUNT(*) FROM token_ip WHERE token=?", (tk,))
        ip_count = c.fetchone()[0]
        token_list.append((tk, exp, ip_count, ban))

    # Retrieve logs
    c.execute("SELECT time, ip, token, user_agent, referrer FROM access_logs ORDER BY time DESC LIMIT 50")
    logs = c.fetchall()

    # Channels
    c.execute("SELECT id,name,stream_url,logo_url FROM channels")
    channels = c.fetchall()

    conn.close()
    return render_template("admin.html", tokens=token_list, logs=logs, channels=channels)

@app.route("/add_channel", methods=["POST"])
def add_channel():
    if not session.get("admin"):
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB); c = conn.cursor()
    c.execute("INSERT INTO channels(name,stream_url,logo_url) VALUES(?,?,?)", (
        request.form["name"], request.form["stream_url"], request.form["logo_url"]
    ))
    conn.commit(); conn.close()
    return redirect(url_for("admin"))

@app.route("/delete_channel/<int:ch_id>")
def delete_channel(ch_id):
    if not session.get("admin"):
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB); c = conn.cursor()
    c.execute("DELETE FROM channels WHERE id=?", (ch_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin"))

@app.route("/iptvplaylist.m3u")
def playlist():
    token = request.args.get("token")
    ip = request.remote_addr; ua = request.headers.get("User-Agent")
    ref = request.referrer or ""

    conn = sqlite3.connect(DB); c = conn.cursor()
    c.execute("SELECT expiry, banned FROM tokens WHERE token=?", (token,))
    row = c.fetchone()
    if not row:
        return "Invalid token", 403
    expiry, banned = row
    if banned or datetime.fromisoformat(expiry) < datetime.now():
        return "Token invalid or expired", 403

    c.execute("SELECT ip FROM token_ip WHERE token=?", (token,))
    ips = [r[0] for r in c.fetchall()]
    if ip not in ips and len(ips) >= MAX_DEVICES:
        return "Device limit reached", 403

    c.execute("INSERT OR IGNORE INTO token_ip(token,ip,added_at) VALUES(?,?,?)", (token,ip,datetime.now().isoformat()))
    c.execute("INSERT INTO access_logs(time,ip,token,user_agent,referrer) VALUES(?,?,?,?,?)", (
        datetime.now().isoformat(), ip, token, ua, ref
    ))

    c.execute("SELECT name,stream_url,logo_url FROM channels")
    chs = c.fetchall(); conn.commit(); conn.close()

    playlist = "#EXTM3U\n"
    for name,url,logo in chs:
        playlist += f'#EXTINF:-1 tvg-logo="{logo}",{name}\n{url}\n'
    res = make_response(playlist)
    res.headers["Content-Type"] = "application/x-mpegurl"
    return res

# Run with port (Render + local dev)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
