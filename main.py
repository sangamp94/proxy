from flask import Flask, send_file, jsonify, abort
import subprocess
import threading
import json
import os
import time

CONFIG_PATH = "stream.json"
OUTPUT_DIR = "static"
OUTPUT_MP4 = f"{OUTPUT_DIR}/decrypted.mp4"
OUTPUT_HLS = f"{OUTPUT_DIR}/stream.m3u8"

app = Flask(__name__)
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Load config
with open(CONFIG_PATH) as f:
    config = json.load(f)

CHANNEL_NAME = config.get("channel_name", "Channel")
CHANNEL_LOGO = config.get("channel_logo", "")
MPD_URL = config["mpd_url"]
KEY_ID = config["key_id"]
KEY = config["key"]

current_process = None

def stop_stream():
    global current_process
    if current_process:
        print("[🔌] Stopping current FFmpeg process...")
        current_process.terminate()
        try:
            current_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            current_process.kill()
        current_process = None

def download_and_decrypt():
    print("[⬇️] Downloading and decrypting MPD with yt-dlp...")
    cmd = [
        "yt-dlp",
        "--allow-unplayable-formats",
        "--downloader", "ffmpeg",
        "--fixup", "never",
        "--merge-output-format", "mp4",
        "--external-downloader", "ffmpeg",
        "--downloader-args", f"ffmpeg_i:-decryption_key {KEY_ID}:{KEY}",
        "-o", OUTPUT_MP4,
        MPD_URL
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("[❌] yt-dlp error:")
        print(result.stderr)
        return False
    print("[✅] yt-dlp download complete.")
    return True

def start_hls_stream():
    global current_process
    if not os.path.exists(OUTPUT_MP4):
        print("[❌] MP4 not found, cannot start HLS stream.")
        return

    print("[🎥] Starting FFmpeg HLS stream...")
    ffmpeg_cmd = [
        "ffmpeg", "-re",
        "-i", OUTPUT_MP4,
        "-c:v", "libx264", "-preset", "ultrafast",
        "-maxrate", "800k", "-bufsize", "1000k",
        "-c:a", "aac", "-b:a", "128k",
        "-f", "hls",
        "-hls_time", "6",
        "-hls_list_size", "5",
        "-hls_flags", "delete_segments+program_date_time",
        OUTPUT_HLS
    ]

    current_process = subprocess.Popen(ffmpeg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print("[✅] FFmpeg process started.")

def manage_stream():
    while True:
        try:
            if not os.path.exists(OUTPUT_HLS):
                print("[ℹ️] stream.m3u8 not found, preparing stream...")
                stop_stream()
                if download_and_decrypt():
                    start_hls_stream()
                else:
                    print("[⚠️] Download failed. Retrying in 20 seconds.")
            else:
                print("[📡] HLS stream is live.")
        except Exception as e:
            print(f"[❌] Error in stream manager: {e}")
        time.sleep(20)

# --- Flask Routes ---
@app.route("/")
def home():
    return f"{CHANNEL_NAME} HLS Server is running 🎬"

@app.route("/stream/live.m3u8")
def stream_m3u8():
    if not os.path.exists(OUTPUT_HLS):
        abort(404, description="HLS playlist not ready yet.")
    return send_file(OUTPUT_HLS, mimetype="application/vnd.apple.mpegurl")

@app.route("/stream/<segment>")
def stream_ts(segment):
    segment_path = os.path.join(OUTPUT_DIR, segment)
    if not os.path.exists(segment_path):
        abort(404)
    return send_file(segment_path, mimetype="video/MP2T")

@app.route("/status")
def status():
    return jsonify({
        "channel": CHANNEL_NAME,
        "logo": CHANNEL_LOGO,
        "stream_ready": os.path.exists(OUTPUT_HLS)
    })

if __name__ == "__main__":
    print("[🚀] Starting HLS server on http://0.0.0.0:10000")
    threading.Thread(target=manage_stream, daemon=True).start()
    app.run(host="0.0.0.0", port=10000)
