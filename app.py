from flask import Flask, request, redirect, render_template, session, abort
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, uuid, requests, time

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB = 'database.db'
MAX_DEVICES = 4
BLOCK_DURATION = 300  # 5 minutes in seconds

# ------------------------ DB INIT ------------------------ #
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
                            referrer TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS channels (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT,
                            stream_url TEXT,
                            logo_url TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                            ip TEXT PRIMARY KEY,
                            unblock_time REAL)''')
init_db()

# ------------------------ AUTH DECORATOR ------------------------ #
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper

# ------------------------ DEBUG UA ------------------------ #
@app.route('/debug-ua')
def debug_ua():
    return f"User-Agent: {request.headers.get('User-Agent')}"

# (rest of your app remains unchanged)

if __name__ == '__main__':
    app.run(debug=False, port=5000)
