from flask import Flask, Response
import requests

app = Flask(__name__)

# Replace this with the actual M3U8 or .php?id=... generator
SOURCE_URL = "https://uxplaylists-live.vercel.app/uiop.php?id=56032"

@app.route("/")
def home():
    return (
        "Use this endpoint in VLC:<br><br>"
        f"<code>/live/stream.m3u8</code><br><br>"
        f"Example: <code>https://your-app.onrender.com/live/stream.m3u8</code>"
    )

@app.route("/live/stream.m3u8")
def serve_m3u8():
    try:
        # Fetch M3U8 playlist (supports redirect)
        r = requests.get(SOURCE_URL, timeout=10, allow_redirects=True)
        if r.status_code != 200:
            return f"Failed to fetch M3U8: HTTP {r.status_code}", 500

        # Extract base URL to resolve .ts segments
        real_url = r.url
        base_url = real_url.rsplit("/", 1)[0]

        playlist = r.text
        output = []

        for line in playlist.splitlines():
            if line.strip().endswith(".ts"):
                # Turn relative .ts path into absolute
                full_url = f"{base_url}/{line.strip()}"
                output.append(full_url)
            else:
                output.append(line)

        return Response("\n".join(output), content_type="application/vnd.apple.mpegurl")

    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
