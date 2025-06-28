import os, shutil, time, uuid
from flask import Flask, request, jsonify, render_template_string
from yt_dlp import YoutubeDL
import requests
from threading import Thread

app = Flask(__name__)
PIXELDRAIN_API_KEY = "60022898-39c5-4a3c-a3c4-bbbccbde20ad"
TASKS = {}  # { task_id: {"status": ..., "links": [...]} }
BASE_DIR = "/tmp"

HTML_FORM = '''
<h2>🎥 YouTube Playlist to Pixeldrain</h2>
<form method="post">
  <input name="playlist_url" placeholder="Paste YouTube playlist URL" size="60" required>
  <button type="submit">Start</button>
</form>
{% if task_id %}
<p>Status: <a href="/status/{{task_id}}" target="_blank">/status/{{task_id}}</a></p>
{% endif %}
'''

def extract_video_urls(playlist_url):
    ydl_opts = {
        'quiet': True,
        'extract_flat': True,
        'force_generic_extractor': True,
    }
    with YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(playlist_url, download=False)
        return [entry['url'] for entry in info['entries'] if 'url' in entry]

def download_video(video_url, output_dir):
    ydl_opts = {
        'outtmpl': f'{output_dir}/%(title).100s.%(ext)s',
        'format': 'best[ext=mp4]',
        'quiet': True,
        'noplaylist': True
    }
    with YoutubeDL(ydl_opts) as ydl:
        ydl.download([video_url])

def upload_to_pixeldrain(file_path):
    with open(file_path, 'rb') as f:
        response = requests.post(
            'https://pixeldrain.com/api/file',
            headers={'Authorization': f'Bearer {PIXELDRAIN_API_KEY}'},
            files={'file': f}
        )
        if response.status_code == 200:
            file_id = response.json().get("id")
            return f"https://pixeldrain.com/u/{file_id}"
        else:
            print("Upload failed:", response.text)
            return None

def handle_task(task_id, playlist_url):
    task_dir = os.path.join(BASE_DIR, f"task_{task_id}")
    os.makedirs(task_dir, exist_ok=True)
    TASKS[task_id]["status"] = "Extracting playlist..."
    urls = extract_video_urls(playlist_url)

    for i in range(0, len(urls), 2):
        chunk = urls[i:i+2]
        for video_url in chunk:
            try:
                TASKS[task_id]["status"] = f"Downloading {video_url}"
                download_video(video_url, task_dir)

                for f in os.listdir(task_dir):
                    file_path = os.path.join(task_dir, f)
                    TASKS[task_id]["status"] = f"Uploading {f}"
                    link = upload_to_pixeldrain(file_path)
                    if link:
                        TASKS[task_id]["links"].append(link)
                    os.remove(file_path)
            except Exception as e:
                TASKS[task_id]["status"] = f"Error: {e}"
        time.sleep(1)

    shutil.rmtree(task_dir)
    TASKS[task_id]["status"] = "✅ Done"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        playlist_url = request.form["playlist_url"]
        task_id = str(uuid.uuid4())[:8]
        TASKS[task_id] = {"status": "Starting...", "links": []}
        Thread(target=handle_task, args=(task_id, playlist_url)).start()
        return render_template_string(HTML_FORM, task_id=task_id)
    return render_template_string(HTML_FORM, task_id=None)

@app.route("/status/<task_id>")
def status(task_id):
    task = TASKS.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
