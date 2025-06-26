from flask import Flask, request, jsonify
import requests
import subprocess
import os
import shutil
import mimetypes
import time

app = Flask(__name__)

PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"
ffmpeg_path = shutil.which("ffmpeg")
ffmpeg_available = bool(ffmpeg_path)

@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_json()
    video_url = data.get("url")
    steps = {"download": None, "convert": None, "upload": None, "link": None}
    start_time = time.time()

    if not video_url or not video_url.startswith("http"):
        return jsonify({"error": "Invalid or missing video URL"}), 400

    original = "original.mp4"
    converted = "converted.mp4"

    print("📥 Downloading video...")
    try:
        r = requests.get(video_url, stream=True, timeout=300)
        r.raise_for_status()
        content_type = r.headers.get("Content-Type", "")
        if "text" in content_type:
            raise ValueError(f"Received non-video content (Content-Type: {content_type})")

        with open(original, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        steps["download"] = "done"
        print("✅ Download complete")
    except Exception as e:
        steps["download"] = f"failed: {str(e)}"
        return jsonify({"steps": steps, "error": "Failed to download"}), 500

    if ffmpeg_available:
        print("🎞️ Converting with FFmpeg...")
        try:
            result = subprocess.run([
                ffmpeg_path, "-y", "-i", original,
                "-c:v", "libx264", "-c:a", "aac",
                "-movflags", "+faststart",
                converted
            ], capture_output=True, text=True)

            if result.returncode == 0:
                steps["convert"] = "done"
                print("✅ Conversion complete")
            else:
                steps["convert"] = "failed, using original"
                print("❌ Conversion failed. Using original.")
                converted = original
        except Exception as e:
            steps["convert"] = f"exception: {e}, using original"
            print(f"❌ Exception in conversion: {e}")
            converted = original
    else:
        steps["convert"] = "skipped"
        print("⚠️ FFmpeg not found. Skipping conversion.")
        converted = original

    if not os.path.exists(converted):
        steps["upload"] = "file missing"
        return jsonify({"steps": steps, "error": "No file to upload"}), 500

    mime_type, _ = mimetypes.guess_type(converted)
    if not mime_type or not mime_type.startswith("video"):
        steps["upload"] = f"invalid mime: {mime_type}"
        return jsonify({"steps": steps, "error": "Not a video file"}), 400

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
            link = f"https://pixeldrain.com/u/{file_id}"
            steps["upload"] = "done"
            steps["link"] = link
            print(f"✅ Upload complete: {link}")
        else:
            steps["upload"] = f"failed: {response_json.get('msg')}"
            return jsonify({"steps": steps, "error": "Pixeldrain upload error"}), 500

    except Exception as e:
        steps["upload"] = f"exception: {str(e)}"
        return jsonify({"steps": steps, "error": "Upload failed"}), 500

    finally:
        for f in [original, converted]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception as e:
                    print(f"⚠️ Cleanup failed: {e}")

    duration = round(time.time() - start_time, 2)
    return jsonify({"success": True, "steps": steps, "duration_sec": duration})

@app.route("/", methods=["GET"])
def home():
    return "✅ Pixeldrain uploader is running!"

@app.route("/favicon.ico")
def favicon():
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
