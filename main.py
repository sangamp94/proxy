import os
import time
import shutil
import requests
import yt_dlp
from flask import Flask, request, jsonify
from tempfile import mkdtemp

PIXELDRAIN_API_KEY = "60022898-39c5-4a3c-a3c4-bbbccbde20ad"
DOWNLOAD_DIR = mkdtemp()

app = Flask(__name__)

def upload_to_pixeldrain(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(
            "https://pixeldrain.com/api/file",
            headers={"Authorization": f"Bearer {PIXELDRAIN_API_KEY}"},
            files={"file": f}
        )
    if response.ok:
        return "https://pixeldrain.com/u/" + response.json()["id"]
    return None

def get_video_urls(playlist_url):
    ydl_opts = {
        "extract_flat": True,
        "quiet": True,
        "skip_download": True,
        "forcejson": True,
    }
    result = []
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(playlist_url, download=False)
        for entry in info.get("entries", []):
            result.append(entry["url"])
    return result

def download_video(url, output_dir):
    ydl_opts = {
        "quiet": True,
        "outtmpl": os.path.join(output_dir, "%(title).80s.%(ext)s"),
        "format": "mp4",
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=True)
        return ydl.prepare_filename(info)

def process_playlist(playlist_url):
    urls = get_video_urls(playlist_url)
    pixeldrain_links = []
    for i in range(0, len(urls), 2):
        chunk = urls[i:i + 2]
        for url in chunk:
            try:
                print(f"Downloading: {url}")
                file_path = download_video(url, DOWNLOAD_DIR)
                print(f"Uploading: {file_path}")
                link = upload_to_pixeldrain(file_path)
                if link:
                    pixeldrain_links.append(link)
                os.remove(file_path)
            except Exception as e:
                print(f"Error: {e}")
        time.sleep(1)  # short delay to avoid rate limits
    return pixeldrain_links

@app.route("/", methods=["POST"])
def handle():
    data = request.form
    playlist_url = data.get("playlist")
    if not playlist_url:
        return "Missing playlist URL", 400
    links = process_playlist(playlist_url)
    return jsonify({"links": links})

@app.route("/upload_form")
def upload_form():
    return '''
    <form method="post" action="/">
      Playlist URL: <input name="playlist" size="80"><br>
      <input type="submit">
    </form>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
