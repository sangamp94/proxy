from flask import Flask, Response
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# Your original source (master playlist)
MASTER_M3U8 = "https://uxplaylists-live.vercel.app/uiop.php?id=56032"

@app.route("/")
def index():
    return "Use /live/stream.m3u8 in VLC"

@app.route("/live/stream.m3u8")
def serve_stream():
    try:
        # Step 1: Get master playlist (contains links to media playlists)
        master_resp = requests.get(MASTER_M3U8, timeout=10, allow_redirects=True)
        if master_resp.status_code != 200:
            return "Failed to fetch master playlist", 500

        master_lines = master_resp.text.splitlines()
        media_relative_url = None

        for line in master_lines:
            if line and not line.startswith("#"):
                media_relative_url = line.strip()
                break  # Just use the first stream

        if not media_relative_url:
            return "Media playlist not found", 500

        media_playlist_url = urljoin(master_resp.url, media_relative_url)

        # Step 2: Fetch media playlist (contains .ts segments)
        media_resp = requests.get(media_playlist_url, timeout=10)
        if media_resp.status_code != 200:
            return "Failed to fetch media playlist", 500

        media_lines = media_resp.text.splitlines()
        base_url = media_playlist_url.rsplit("/", 1)[0]

        final_playlist = []
        for line in media_lines:
            if line.strip().endswith(".ts"):
                ts_url = urljoin(base_url + "/", line.strip())
                final_playlist.append(ts_url)
            else:
                final_playlist.append(line)

        return Response("\n".join(final_playlist), content_type="application/vnd.apple.mpegurl")

    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
