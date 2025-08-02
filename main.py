from flask import Flask, send_file, jsonify, abort
import subprocess
import threading
import json
import os
import time
import sys

# --- Config ---
CONFIG_PATH = "stream.json"
OUTPUT_DIR = os.path.abspath("static")
OUTPUT_MP4 = os.path.join(OUTPUT_DIR, "decrypted.mp4")
OUTPUT_HLS = os.path.join(OUTPUT_DIR, "stream.m3u8")

# --- Load Configuration ---
try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
except Exception as e:
    print(f"[❌] Failed to load stream.json: {e}")
    sys.exit(1)

CHANNEL_NAME = config.get("channel_name", "Unnamed Channel")
CHANNEL_LOGO = config.get("channel_logo", "")
MPD_URL = config.get("mpd_url")
KEY_ID = config.get("key_id")
KEY = config.get("key")

# --- App Setup ---
app = Flask(__name__)
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

current_process = None

# --- Stream Logic ---
def stop_stream():
    global current_process
    if current_process:
        print("[🔌] Stopping FFmpeg...")
        current_process.terminate()
        try:
            current_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            current_process.kill()
        current_process = None
        print("[✅] FFmpeg stopped.")

def download_and_decrypt():
    print("[⬇️] Running yt-dlp to download and decrypt MPD stream...")
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
    print("[yt-dlp STDOUT]")
    print(result.stdout)
    print("[yt-dlp STDERR]")
    print(result.stderr)
    return result.returncode == 0

def start_hls_stream():
    global current_process
    if not os.path.exists(OUTPUT_MP4):
        print("[❌] No decrypted.mp4 found.")
        return

    print("[🎥] Starting FFmpeg to generate HLS stream...")
    ffmpeg_cmd = [
        "ffmpeg", "-re",
        "-i", OUTPUT_MP4,
        "-c:v", "libx264", "-preset", "ultrafast",
        "-c:a", "aac", "-b:a", "128k",
        "-f", "hls",
        "-hls_time", "6",
        "-hls_list_size", "5",
        "-hls_flags", "delete_segments+program_date_time",
        OUTPUT_HLS
    ]

    current_process = subprocess.Popen(
        ffmpeg_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    # Live log FFmpeg output
    def log_ffmpeg():
        for line in current_process.stdout:
            print("[ffmpeg]", line.strip())

    threading.Thread(target=log_ffmpeg, daemon=True).start()

def manage_stream():
    print("[🧠] Stream management thread started.")
    while True:
        try:
            if not os.path.exists(OUTPUT_HLS):
                print("[📡] stream.m3u8 not found, triggering setup...")
                stop_stream()
                if download_and_decrypt():
                    start_hls_stream()
                else:
                    print("[❌] yt-dlp failed. Will retry.")
            else:
                print("[✅] HLS stream is live.")
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
    print("[🚀] Launching Flask app + stream thread")
    threading.Thread(target=manage_stream, daemon=True).start()
    app.run(host="0.0.0.0", port=10000)
