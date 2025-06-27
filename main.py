from flask import Flask, request, jsonify, render_template
import requests
import subprocess
import os
import time
from yt_dlp import YoutubeDL
import shutil

app = Flask(__name__)
PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"
ffmpeg_path = shutil.which("ffmpeg")
USE_FFMPEG = bool(ffmpeg_path)

@app.route("/")
def index():
    return "✅ Pixeldrain Playlist Uploader Running. POST to /upload_playlist with { 'playlist': 'YOUTUBE_PLAYLIST_URL' }"

@app.route("/upload_form")
def upload_form():
    return render_template("upload_form.html")

@app.route("/upload_playlist", methods=["POST"])
def upload_playlist():
    data = request.get_json()
    playlist_url = data.get("playlist")
    if not playlist_url:
        return jsonify({"error": "Missing playlist URL"}), 400

    uploaded, failed = [], []
    start_time = time.time()

    ydl_opts = {
        'quiet': True,
        'extract_flat': 'in_playlist',
        'dump_single_json': True,
    }

    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(playlist_url, download=False)
            videos = info.get("entries", [])
    except Exception as e:
        return jsonify({"error": f"Failed to extract playlist: {e}"}), 500

    for entry in videos:
        url = entry.get("url")
        if not url:
            continue

        try:
            subprocess.run(["yt-dlp", "-f", "best[ext=mp4]/best", "-o", "video.mp4", url], check=True)

            input_file = "video.mp4"
            output_file = "converted.mp4" if USE_FFMPEG else input_file

            if USE_FFMPEG:
                subprocess.run([
                    ffmpeg_path, "-y", "-i", input_file,
                    "-c:v", "libx264", "-c:a", "aac", "-movflags", "+faststart", output_file
                ], check=True)

            with open(output_file, "rb") as f:
                r = requests.post(
                    "https://pixeldrain.com/api/file",
                    auth=('', PIXELDRAIN_API_KEY),
                    files={"file": f},
                    timeout=300
                )
            res = r.json()
            if res.get("success"):
                uploaded.append({
                    "video": url,
                    "link": f"https://pixeldrain.com/u/{res['id']}"
                })
            else:
                failed.append({"video": url, "error": res.get("message", "Upload failed")})

        except Exception as e:
            failed.append({"video": url, "error": str(e)})

        finally:
            for f in ("video.mp4", "converted.mp4"):
                if os.path.exists(f):
                    os.remove(f)

    return jsonify({
        "success": True,
        "total": len(videos),
        "uploaded": uploaded,
        "failed": failed,
        "duration_seconds": round(time.time() - start_time, 2)
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
