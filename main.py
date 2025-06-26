# === app.py — Flask-based Pixeldrain uploader with video conversion ===
from flask import Flask, request, jsonify
import requests
import subprocess
import os
import shutil
import mimetypes
from datetime import datetime

app = Flask(__name__)

PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"

# === Utility: Check for ffmpeg ===
ffmpeg_path = shutil.which("ffmpeg")
ffmpeg_available = bool(ffmpeg_path)

@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_json()
    video_url = data.get("url")

    if not video_url or not video_url.startswith("http"):
        return jsonify({"error": "Invalid or missing video URL"}), 400

    original = "original.mp4"
    converted = "converted.mp4"

    print("📥 Downloading video...")
    try:
        r = requests.get(video_url, stream=True, timeout=60)
        r.raise_for_status()
        content_type = r.headers.get("Content-Type", "")
        if "text" in content_type:
            raise ValueError(f"Received non-video content (Content-Type: {content_type})")

        with open(original, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    except Exception as e:
        return jsonify({"error": f"Failed to download: {str(e)}"}), 500

    # Convert if possible
    if ffmpeg_available:
        print("🎞️ Converting video with FFmpeg...")
        try:
            result = subprocess.run([
                ffmpeg_path, "-y", "-i", original,
                "-c:v", "libx264", "-c:a", "aac",
                "-movflags", "+faststart",
                converted
            ], capture_output=True, text=True)

            if result.returncode != 0:
                print("❌ Conversion failed. Using original.")
                converted = original
        except Exception as e:
            print(f"❌ Exception in conversion: {e}")
            converted = original
    else:
        print("⚠️ FFmpeg not found. Skipping conversion.")
        converted = original

    # Upload to Pixeldrain
    if not os.path.exists(converted):
        return jsonify({"error": "No file to upload"}), 500

    mime_type, _ = mimetypes.guess_type(converted)
    if not mime_type or not mime_type.startswith("video"):
        return jsonify({"error": f"Not a video file (MIME: {mime_type})"}), 400

    print("📤 Uploading to Pixeldrain...")
    try:
        with open(converted, "rb") as f:
            response = requests.post(
                "https://pixeldrain.com/api/file",
                auth=('', PIXELDRAIN_API_KEY),
                files={"file": f},
                timeout=300
            )
        response.raise_for_status()
        response_json = response.json()

        if response_json.get("success"):
            file_id = response_json.get("id")
            return jsonify({"success": True, "link": f"https://pixeldrain.com/u/{file_id}"})
        else:
            return jsonify({"error": response_json}), 500

    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

    finally:
        for f in [original, converted]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except Exception as e:
                    print(f"⚠️ Cleanup failed for {f}: {e}")

@app.route("/", methods=["GET"])
def home():
    return "✅ Pixeldrain uploader is running! Use POST /upload with JSON { 'url': '<video_url>' }"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
