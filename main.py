from flask import Flask, request, jsonify
import requests
import subprocess
import os
import shutil
import time
from yt_dlp import YoutubeDL

app = Flask(__name__)

PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"
ffmpeg_path = shutil.which("ffmpeg")
ffmpeg_available = bool(ffmpeg_path)

@app.route("/upload_playlist", methods=["POST"])
def upload_playlist():
    data = request.get_json()
    playlist_url = data.get("playlist")

    if not playlist_url or not playlist_url.startswith("http"):
        return jsonify({"error": "Invalid playlist URL"}), 400

    start_time = time.time()
    uploaded = []
    failed = []

    ydl_opts = {
        'quiet': True,
        'extract_flat': 'in_playlist',
        'dump_single_json': True,
    }

    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(playlist_url, download=False)
            entries = info.get("entries", [])
    except Exception as e:
        return jsonify({"error": f"❌ Failed to parse playlist: {e}"}), 500

    for entry in entries:
        video_url = entry.get("url")
        if not video_url:
            continue

        try:
            print(f"📥 Downloading: {video_url}")
            subprocess.run([
                "yt-dlp", "-f", "best[ext=mp4]/best",
                "-o", "video.mp4", video_url
            ], check=True)

            file_path = "video.mp4"
            upload_path = "converted.mp4" if ffmpeg_available else file_path

            if ffmpeg_available:
                try:
                    subprocess.run([
                        ffmpeg_path, "-y", "-i", file_path,
                        "-c:v", "libx264", "-c:a", "aac",
                        "-movflags", "+faststart", upload_path
                    ], check=True)
                except Exception as e:
                    print("⚠️ FFmpeg failed. Using original file.")
                    upload_path = file_path

            print("📤 Uploading to Pixeldrain...")
            with open(upload_path, "rb") as f:
                r = requests.post(
                    "https://pixeldrain.com/api/file",
                    auth=('', PIXELDRAIN_API_KEY),
                    files={"file": f},
                    timeout=300
                )
            response = r.json()
            if response.get("success"):
                uploaded.append({
                    "video": video_url,
                    "link": f"https://pixeldrain.com/u/{response['id']}"
                })
                print(f"✅ Uploaded: {response['id']}")
            else:
                failed.append({"video": video_url, "error": response.get("msg", "Upload error")})

        except Exception as e:
            failed.append({"video": video_url, "error": str(e)})
            print(f"❌ Failed: {video_url} - {e}")

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

@app.route("/", methods=["GET"])
def home():
    return "✅ Pixeldrain Playlist Uploader Running. POST to /upload_playlist with { 'playlist': 'YOUTUBE_PLAYLIST_URL' }"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
