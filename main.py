from flask import Flask, request, jsonify, render_template_string
import requests, subprocess, os, shutil, time, mimetypes
from yt_dlp import YoutubeDL

app = Flask(__name__)
PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"
FFMPEG_PATH = shutil.which("ffmpeg")
FFMPEG_AVAILABLE = bool(FFMPEG_PATH)
COOKIES_FILE = "cookies.txt"  # optional, for age-restricted or geo-blocked videos

HTML_FORM = '''
<!DOCTYPE html>
<html><head><title>Pixeldrain Playlist Uploader</title></head>
<body>
  <h2>🎥 Pixeldrain YouTube Playlist Uploader</h2>
  <form method="post" action="/upload_playlist">
    Playlist URL: <input type="text" name="playlist" size="70" required><br><br>
    <button type="submit">Upload</button>
  </form>
</body></html>
'''

@app.route("/", methods=["GET"])
def home():
    return "✅ Pixeldrain Playlist Uploader Running. POST to /upload_playlist with { 'playlist': 'YOUTUBE_PLAYLIST_URL' }"

@app.route("/upload_form", methods=["GET"])
def form():
    return render_template_string(HTML_FORM)

@app.route("/upload_playlist", methods=["POST"])
def upload_playlist():
    playlist_url = request.form.get("playlist") or request.get_json(silent=True).get("playlist")
    if not playlist_url:
        return jsonify({"error": "Missing playlist URL"}), 400

    start_time = time.time()
    uploaded, failed = [], []

    ydl_opts = {
        'quiet': True,
        'extract_flat': 'in_playlist',
        'dump_single_json': True,
        'cookies': COOKIES_FILE if os.path.exists(COOKIES_FILE) else None
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

        try:
            print(f"📥 Downloading {video_url}...")
            subprocess.run(["yt-dlp", "-f", "best[ext=mp4]/best", "-o", "video.mp4", video_url,
                            "--cookies", COOKIES_FILE] if os.path.exists(COOKIES_FILE) else 
                            ["yt-dlp", "-f", "best[ext=mp4]/best", "-o", "video.mp4", video_url],
                            check=True)

            upload_file = "video.mp4"
            if FFMPEG_AVAILABLE:
                print("🎞️ Converting with FFmpeg...")
                subprocess.run([
                    FFMPEG_PATH, "-y", "-i", "video.mp4",
                    "-c:v", "libx264", "-c:a", "aac",
                    "-movflags", "+faststart", "converted.mp4"
                ], check=True)
                upload_file = "converted.mp4"

            print(f"📤 Uploading {upload_file}...")
            with open(upload_file, "rb") as f:
                res = requests.post(
                    "https://pixeldrain.com/api/file",
                    auth=('', PIXELDRAIN_API_KEY),
                    files={"file": f}, timeout=300
                )

            res_json = res.json()
            if res_json.get("success"):
                uploaded.append({
                    "title": entry.get("title"),
                    "pixeldrain_url": f"https://pixeldrain.com/u/{res_json['id']}"
                })
            else:
                failed.append({"url": video_url, "error": res_json.get("msg")})

        except Exception as e:
            failed.append({"url": video_url, "error": str(e)})

        finally:
            for f in ["video.mp4", "converted.mp4"]:
                if os.path.exists(f): os.remove(f)

    return jsonify({
        "success": True,
        "total": len(entries),
        "uploaded": uploaded,
        "failed": failed,
        "duration_sec": round(time.time() - start_time, 2)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
