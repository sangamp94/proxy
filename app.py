import os
import uuid
import json
from flask import Flask, request, Response, redirect, send_file, render_template, abort
from urllib.parse import unquote, urlparse
import requests

app = Flask(__name__)

TOKENS_FILE = "tokens.json"
CHANNELS_FILE = "channels.json"
BANNED_IPS_FILE = "banned_ips.json"

MAX_DEVICES = 4
ADMIN_PASSWORD = "admin123"

# --------------- Utility Functions ---------------

def load_json(file):
    if not os.path.exists(file):
        return {}
    with open(file, 'r') as f:
        return json.load(f)

def save_json(file, data):
    with open(file, 'w') as f:
        json.dump(data, f, indent=2)

def ban_check(ip):
    return ip in load_json(BANNED_IPS_FILE)

def ban_ip(ip):
    data = load_json(BANNED_IPS_FILE)
    data[ip] = True
    save_json(BANNED_IPS_FILE, data)

def unban_ip(ip):
    data = load_json(BANNED_IPS_FILE)
    data.pop(ip, None)
    save_json(BANNED_IPS_FILE, data)

def is_sniffer(user_agent):
    sniffers = ['fiddler', 'httpcanary', 'charles', 'mitm', 'wireshark']
    return any(sniff in user_agent.lower() for sniff in sniffers)

def get_device_id(req):
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    return f"{ip}_{ua}"

# --------------- Admin Panel Routes ---------------

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if request.form.get('password') != ADMIN_PASSWORD:
            return "Unauthorized", 401

        action = request.form.get("action")
        if action == "add_channel":
            cid = str(uuid.uuid4())[:8]
            channels = load_json(CHANNELS_FILE)
            channels[cid] = {
                "name": request.form['name'],
                "logo": request.form['logo'],
                "url": request.form['url']
            }
            save_json(CHANNELS_FILE, channels)

        elif action == "delete_channel":
            cid = request.form['cid']
            channels = load_json(CHANNELS_FILE)
            channels.pop(cid, None)
            save_json(CHANNELS_FILE, channels)

        elif action == "add_token":
            token = str(uuid.uuid4())[:12]
            tokens = load_json(TOKENS_FILE)
            tokens[token] = {"devices": []}
            save_json(TOKENS_FILE, tokens)

        elif action == "delete_token":
            token = request.form['token']
            tokens = load_json(TOKENS_FILE)
            tokens.pop(token, None)
            save_json(TOKENS_FILE, tokens)

        elif action == "unban_ip":
            ip = request.form['ip']
            unban_ip(ip)

    return render_template("admin.html",
        channels=load_json(CHANNELS_FILE),
        tokens=load_json(TOKENS_FILE),
        banned_ips=list(load_json(BANNED_IPS_FILE).keys())
    )

# --------------- Playlist Serving ---------------

@app.route('/iptvplaylist.m3u')
def playlist():
    token = request.args.get("token")
    if not token or token not in load_json(TOKENS_FILE):
        return "Invalid token", 403

    base = request.url_root.rstrip("/")
    m3u = "#EXTM3U\n"
    channels = load_json(CHANNELS_FILE)

    for cid, data in channels.items():
        name, logo, url = data["name"], data["logo"], data["url"]
        m3u += f'#EXTINF:-1 tvg-logo="{logo}",{name}\n'
        m3u += f'{base}/stream?token={token}&channelid={cid}\n'

    return Response(m3u, mimetype="application/x-mpegURL")

# --------------- Proxy Stream Routes ---------------

@app.route('/stream')
def stream():
    token = request.args.get("token")
    cid = request.args.get("channelid")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")

    if ban_check(ip) or is_sniffer(ua):
        ban_ip(ip)
        return abort(403)

    tokens = load_json(TOKENS_FILE)
    if token not in tokens:
        return "Invalid token", 403

    device_id = get_device_id(request)
    if device_id not in tokens[token]["devices"]:
        if len(tokens[token]["devices"]) >= MAX_DEVICES:
            return "Device limit reached", 403
        tokens[token]["devices"].append(device_id)
        save_json(TOKENS_FILE, tokens)

    channels = load_json(CHANNELS_FILE)
    if cid not in channels:
        return "Invalid channel ID", 404

    real_url = channels[cid]["url"]
    resp = requests.get(real_url, headers={"User-Agent": ua}, stream=True)

    def rewrite_m3u8():
        for line in resp.iter_lines(decode_unicode=True):
            if line.strip().endswith(".ts"):
                segment = f"/segment?ts={line.strip()}&upstream={real_url}&token={token}"
                yield segment + "\n"
            else:
                yield line + "\n"

    return Response(rewrite_m3u8(), content_type="application/vnd.apple.mpegurl")

@app.route('/segment')
def segment():
    ts = request.args.get("ts")
    upstream = request.args.get("upstream")
    if not ts or not upstream:
        return abort(400)

    parsed = urlparse(upstream)
    base = f"{parsed.scheme}://{parsed.netloc}"
    url = base + "/" + ts

    resp = requests.get(url, stream=True)
    return Response(resp.iter_content(chunk_size=1024), content_type="video/MP2T")

# --------------- Static Admin Template ---------------

@app.route('/')
def home():
    return redirect('/admin')

# --------------- Start Server ---------------

if __name__ == '__main__':
    app.run(debug=True)
