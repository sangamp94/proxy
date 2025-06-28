import os, shutil, zipfile
from flask import Flask, request, send_file, render_template_string
from yt_dlp import YoutubeDL
from threading import Thread

app = Flask(__name__)
DOWNLOAD_DIR = "/tmp/videos"
ZIP_FILE = "/tmp/all_videos.zip"

HTML_FORM = '''
<h2>Download YouTube Playlist as ZIP</h2>
<form method="post">
  <input name="playlist_url" placeholder="Paste playlist URL here" size="60" required>
  <button type="submit">Download</button>
</form>
{% if ready %}
<p><a href="/download">✅ Click here to download ZIP</a></p>
{% endif %}
'''

def download_playlist(playlist_url):
    if os.path.exists(DOWNLOAD_DIR):
        shutil.rmtree(DOWNLOAD_DIR)
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    ydl_opts = {
        'outtmpl': f'{DOWNLOAD_DIR}/%(title).100s.%(ext)s',
        'format': 'bestvideo+bestaudio/best',
        'merge_output_format': 'mp4',
        'quiet': True,
    }

    with YoutubeDL(ydl_opts) as ydl:
        ydl.download([playlist_url])

    with zipfile.ZipFile(ZIP_FILE, 'w') as zipf:
        for filename in os.listdir(DOWNLOAD_DIR):
            zipf.write(os.path.join(DOWNLOAD_DIR, filename), arcname=filename)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        playlist_url = request.form["playlist_url"]
        Thread(target=download_playlist, args=(playlist_url,)).start()
        return render_template_string(HTML_FORM, ready=True)
    return render_template_string(HTML_FORM, ready=False)

@app.route("/download")
def download():
    if os.path.exists(ZIP_FILE):
        return send_file(ZIP_FILE, as_attachment=True)
    return "ZIP not ready yet."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
