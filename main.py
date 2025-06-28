import os
from threading import Thread
from flask import Flask

app = Flask(__name__)

def start_ffmpeg_stream():
    # 🧠 Your FFmpeg stream logic goes here
    # Example: os.system("ffmpeg -i input -f mpegts udp://localhost:1234")
    print("FFmpeg stream started...")
    # Simulate stream for demo
    import time
    while True:
        print("Streaming...")
        time.sleep(10)

@app.route('/')
def home():
    return "Server is running on port " + str(os.environ.get("PORT", 10000))

if __name__ == "__main__":
    # Start FFmpeg stream in background
    Thread(target=start_ffmpeg_stream, daemon=True).start()

    # Use dynamic port (Render/Heroku) or default to 10000
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
