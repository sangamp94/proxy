from flask import Flask, request, jsonify, render_template_string
import requests
import subprocess
import os
import shutil
import mimetypes
import time
from yt_dlp import YoutubeDL

app = Flask(__name__)
PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"
ffmpeg_path = shutil.which("ffmpeg")
ffmpeg_available = bool(ffmpeg_path)

HTML_FORM = """
<!DOCTYPE html>
<html>
  <head><title>Pixeldrain Playlist Uploader</title></head>
  <body>
    <h2>🎵 Upload YouTube Playlist to Pixeldrain</h2>
    <form action="/upload_playlist" method="post">
      <input type="text" name="playlist" placeholder="Enter YouTube playlist URL" style="width: 400px;" required>
      <button type="submit">Upload</button>
    </form>
  </body>
</html>
"""

@app.route("/")
def home():
    return "✅ Pixeldrain Playlist Uploader Running. POST to /upload_playlist with { 'playlist': 'YOUTUBE_PLAYLIST_URL' }"

@app.route("/upload_form", methods=["GET"])
def upload_form():
    return render_template_string(HTML_FORM)

@app.route("/upload_playlist", methods=["POST"])
def upload_playlist():
    playlist_url = request.form.get("playlist") or request.get_json().get("playlist")
    if not playlist_url or not playlist_url.startswith("http"):
        return jsonify({"error": "Invalid or missing playlist URL"}), 400

    start_time = time.time()
    uploaded, failed = [], []

    ydl_opts = {'quiet': True, 'extract_flat': 'in_playlist', 'dump_single_json': True}
    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(playlist_url, download=False)
            entries = info.get("entries", [])
    except Exception as e:
        return jsonify({"error": f"❌ Playlist fetch failed: {e}"}), 500

    for entry in entries:
        video_url = entry.get("url")
        if not video_url:
            continue

        try:
            print(f"📥 Downloading {video_url}...")
            subprocess.run([
                "yt-dlp", "-f", "best[ext=mp4]/best", "-o", "video.mp4", video_url
            ], check=True)

            if not os.path.exists("video.mp4"):
                failed.append({"url": video_url, "error": "Download failed"})
                continue

            upload_file = "converted.mp4" if ffmpeg_available else "video.mp4"
            if ffmpeg_available:
                try:
                    subprocess.run([
                        ffmpeg_path, "-y", "-i", "video.mp4",
                        "-c:v", "libx264", "-c:a", "aac",
                        "-movflags", "+faststart", upload_file
                    ], check=True)
                except:
                    upload_file = "video.mp4"

            with open(upload_file, "rb") as f:
                r = requests.post(
                    "https://pixeldrain.com/api/file",
                    auth=('', PIXELDRAIN_API_KEY),
                    files={"file": f},
                    timeout=300
                )
            result = r.json()
            if result.get("success"):
                uploaded.append({"url": video_url, "link": f"https://pixeldrain.com/u/{result['id']}"})
            else:
                failed.append({"url": video_url, "error": result.get("msg")})
        except Exception as e:
            failed.append({"url": video_url, "error": str(e)})
        finally:
            for f in ["video.mp4", "converted.mp4"]:
                if os.path.exists(f):
                    os.remove(f)

    return jsonify({
        "success": True,
        "total": len(entries),
        "uploaded": uploaded,
        "failed": failed,
        "duration_sec": round(time.time() - start_time, 2)
    })

@app.route("/favicon.ico")
def favicon():
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
