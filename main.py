from flask import Flask, request, render_template_string, jsonify
import subprocess
import os
import uuid
import shutil
import requests
from threading import Thread

app = Flask(__name__)

PIXELDRAIN_API_KEY = "60022898-39c5-4a3c-a3c4-bbbccbde20ad"
DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

UPLOAD_FORM_HTML = """
<!DOCTYPE html>
<html>
  <head>
    <title>YouTube to Pixeldrain</title>
  </head>
  <body>
    <h1>Submit YouTube Playlist URL</h1>
    <form method="POST">
      <input type="text" name="playlist_url" placeholder="YouTube Playlist URL" required>
      <button type="submit">Submit</button>
    </form>
  </body>
</html>
"""

def run_yt_dlp(video_url, download_path):
    cmd = [
        "yt-dlp",
        "--proxy", "socks5://fr.hide.me:1080",  # Use French VPN proxy if set up
        "-o", os.path.join(download_path, "%(title)s.%(ext)s"),
        video_url
    ]
    subprocess.run(cmd, check=True)

def upload_to_pixeldrain(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(
            "https://pixeldrain.com/api/file",
            headers={"Authorization": f"Bearer {PIXELDRAIN_API_KEY}"},
            files={"file": f}
        )
    file_id = response.json().get("id")
    return f"https://pixeldrain.com/u/{file_id}" if file_id else None

def process_playlist(playlist_url, task_id):
    playlist_dir = os.path.join(DOWNLOAD_DIR, task_id)
    os.makedirs(playlist_dir, exist_ok=True)
    try:
        result = subprocess.run([
            "yt-dlp", "--flat-playlist", "--get-id", playlist_url
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        video_ids = result.stdout.strip().splitlines()

        links = []
        for i in range(0, len(video_ids), 2):
            chunk_ids = video_ids[i:i+2]
            chunk_dir = os.path.join(playlist_dir, f"chunk_{i//2}")
            os.makedirs(chunk_dir, exist_ok=True)

            for vid in chunk_ids:
                run_yt_dlp(f"https://youtube.com/watch?v={vid}", chunk_dir)

            for fname in os.listdir(chunk_dir):
                fpath = os.path.join(chunk_dir, fname)
                link = upload_to_pixeldrain(fpath)
                if link:
                    links.append(link)

            shutil.rmtree(chunk_dir)

        with open(os.path.join(playlist_dir, "links.txt"), "w") as f:
            f.write("\n".join(links))

    except Exception as e:
        with open(os.path.join(playlist_dir, "error.txt"), "w") as f:
            f.write(str(e))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        playlist_url = request.form.get("playlist_url")
        task_id = str(uuid.uuid4())[:8]
        Thread(target=process_playlist, args=(playlist_url, task_id)).start()
        return f"Processing started. Check status at /status/{task_id}"
    return render_template_string(UPLOAD_FORM_HTML)

@app.route("/status/<task_id>")
def status(task_id):
    playlist_dir = os.path.join(DOWNLOAD_DIR, task_id)
    links_file = os.path.join(playlist_dir, "links.txt")
    error_file = os.path.join(playlist_dir, "error.txt")
    if os.path.exists(links_file):
        with open(links_file) as f:
            return "<br>".join(f.read().splitlines())
    elif os.path.exists(error_file):
        with open(error_file) as f:
            return f"Error: {f.read()}"
    else:
        return "Processing..."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
