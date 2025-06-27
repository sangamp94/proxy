from flask import Flask, request, jsonify
import os, shutil, time, subprocess, requests
from yt_dlp import YoutubeDL

app = Flask(__name__)

PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8  # 🔒 Replace with yours
ffmpeg_path = shutil.which("ffmpeg")
ffmpeg_available = bool(ffmpeg_path)

@app.route("/upload_playlist", methods=["GET", "POST"])
def upload_playlist():
    if request.method == "GET":
        return '''
            <h2>📤 Upload YouTube Playlist to Pixeldrain</h2>
            <form method="post" action="/upload_playlist">
                <label>Playlist URL:</label><br>
                <input type="text" name="playlist" size="60" required>
                <br><br>
                <button type="submit">Start Upload</button>
            </form>
        '''

    playlist_url = request.json.get("playlist") if request.is_json else request.form.get("playlist")
    if not playlist_url or not playlist_url.startswith("http"):
        return jsonify({"error": "Invalid or missing playlist URL"}), 400

    uploaded = []
    failed = []
    start_time = time.time()

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
        return jsonify({"error": f"Failed to parse playlist: {str(e)}"}), 500

    for entry in entries:
        video_url = entry.get("url")
        if not video_url:
            continue
        try:
            print(f"📥 Downloading: {video_url}")
            subprocess.run([
                "yt-dlp", "-f", "best[ext=mp4]/best",
                "-o", "video.mp4", f"https://www.youtube.com/watch?v={video_url}"
            ], check=True)

            input_file = "video.mp4"
            output_file = "converted.mp4" if ffmpeg_available else input_file

            if ffmpeg_available:
                try:
                    print(f"🎞️ Converting video with FFmpeg...")
                    subprocess.run([
                        ffmpeg_path, "-y", "-i", input_file,
                        "-c:v", "libx264", "-c:a", "aac",
                        "-movflags", "+faststart", output_file
                    ], check=True)
                except Exception as e:
                    print(f"⚠️ FFmpeg failed, using raw video.")
                    output_file = input_file

            print(f"📤 Uploading to Pixeldrain...")
            with open(output_file, "rb") as f:
                r = requests.post(
                    "https://pixeldrain.com/api/file",
                    auth=('', PIXELDRAIN_API_KEY),
                    files={"file": f}
                )

            resp = r.json()
            if resp.get("success"):
                uploaded.append({
                    "video_url": f"https://www.youtube.com/watch?v={video_url}",
                    "pixeldrain_link": f"https://pixeldrain.com/u/{resp['id']}"
                })
            else:
                failed.append({"url": video_url, "error": resp.get("msg")})

        except Exception as e:
            failed.append({"url": video_url, "error": str(e)})
        finally:
            for f in ["video.mp4", "converted.mp4"]:
                if os.path.exists(f):
                    os.remove(f)

    return jsonify({
        "status": "completed",
        "total": len(entries),
        "uploaded": uploaded,
        "failed": failed,
        "duration_seconds": round(time.time() - start_time, 2)
    })

@app.route("/")
def home():
    return '''
        <h1>✅ Pixeldrain Playlist Uploader</h1>
        <p>POST a JSON with {"playlist": "YOUTUBE_URL"} to <code>/upload_playlist</code></p>
        <p>Or use <a href="/upload_playlist">/upload_playlist</a> in browser</p>
    '''

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
