from flask import Flask, request, jsonify, render_template_string
import subprocess
import requests
import os
import shutil
import time
from yt_dlp import YoutubeDL

app = Flask(__name__)
PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"  # replace this
COOKIE_FILE = "cookies.txt"  # optional

ffmpeg_path = shutil.which("ffmpeg")
ffmpeg_available = bool(ffmpeg_path)

@app.route("/")
def home():
    return "✅ Pixeldrain Playlist Uploader Running. POST or GET to /upload_playlist or use /upload_form"

@app.route("/upload_form", methods=["GET"])
def upload_form():
    return render_template_string("""
        <h2>📤 Upload YouTube Playlist to Pixeldrain</h2>
        <form method="post" action="/upload_playlist">
            <input type="text" name="playlist" placeholder="Enter playlist URL" size="80" required>
            <button type="submit">Upload</button>
        </form>
    """)

@app.route("/upload_playlist", methods=["GET", "POST"])
def upload_playlist():
    playlist_url = request.form.get("playlist") or request.args.get("playlist") or request.json.get("playlist")

    if not playlist_url or not playlist_url.startswith("http"):
        return jsonify({"error": "Invalid or missing playlist URL"}), 400

    start_time = time.time()
    uploaded = []
    failed = []

    ydl_opts = {
        'quiet': True,
        'extract_flat': True,
        'dump_single_json': True,
    }

    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(playlist_url, download=False)
            entries = info.get("entries", [])
    except Exception as e:
        return jsonify({"error": f"Failed to parse playlist: {e}"}), 500

    for entry in entries:
        video_url = entry.get("url")
        if not video_url:
            continue
        if not video_url.startswith("http"):
            video_url = f"https://www.youtube.com/watch?v={video_url}"

        try:
            print(f"📥 Downloading: {video_url}")
            download_cmd = [
                "yt-dlp", "-f", "best[ext=mp4]/best",
                "-o", "video.mp4", video_url
            ]
            if os.path.exists(COOKIE_FILE):
                download_cmd += ["--cookies", COOKIE_FILE]

            subprocess.run(download_cmd, check=True)

            file_path = "video.mp4"
            if not os.path.exists(file_path):
                failed.append({"url": video_url, "error": "Download failed"})
                continue

            upload_file = "converted.mp4" if ffmpeg_available else file_path

            if ffmpeg_available:
                subprocess.run([
                    ffmpeg_path, "-y", "-i", file_path,
                    "-c:v", "libx264", "-c:a", "aac",
                    "-movflags", "+faststart", upload_file
                ], check=True)

            print(f"📤 Uploading: {upload_file}")
            with open(upload_file, "rb") as f:
                r = requests.post(
                    "https://pixeldrain.com/api/file",
                    auth=('', PIXELDRAIN_API_KEY),
                    files={"file": f},
                    timeout=300
                )
            response = r.json()
            if response.get("success"):
                uploaded.append({
                    "url": video_url,
                    "link": f"https://pixeldrain.com/u/{response['id']}"
                })
            else:
                failed.append({"url": video_url, "error": response.get("message")})

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
        "duration_seconds": round(time.time() - start_time, 2)
    })

@app.route("/favicon.ico")
def favicon():
    return '', 204

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
