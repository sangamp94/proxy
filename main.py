from flask import Flask, Response, request
import requests

app = Flask(__name__)

# Default stream source (can be made dynamic later)
DEFAULT_SOURCE_URL = "https://uxplaylists-live.vercel.app/uiop.php?id=56032"

@app.route('/')
def home():
    return (
        "✅ M3U8 Proxy is running.<br>"
        "Use <code>/live/stream.m3u8</code> to play in VLC or HLS player."
    )

@app.route('/live/stream.m3u8')
def proxy_stream():
    # Optional: get custom id from query (?id=xxxxx)
    source_id = request.args.get("id", "56032")
    source_url = f"https://uxplaylists-live.vercel.app/uiop.php?id={source_id}"

    try:
        r = requests.get(source_url, timeout=10)
        r.raise_for_status()
        return Response(r.text, mimetype="application/vnd.apple.mpegurl")
    except Exception as e:
        return Response(
            f"#EXTM3U\n# Proxy error: {str(e)}",
            mimetype="application/vnd.apple.mpegurl"
        )

if __name__ == "__main__":
    # Run locally on port 10000
    app.run(host="0.0.0.0", port=10000)
