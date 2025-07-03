from flask import Flask, Response, request
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# Your master .m3u8 playlist
MASTER_M3U8 = "https://uxplaylists-live.vercel.app/uiop.php?id=56032"
MEDIA_PLAYLIST_URL = None  # will be set dynamically

@app.route("/")
def home():
    return "Paste /live/stream.m3u8 into VLC"

@app.route("/live/stream.m3u8")
def stream():
    global MEDIA_PLAYLIST_URL

    try:
        # Fetch master .m3u8
        master = requests.get(MASTER_M3U8, allow_redirects=True, timeout=10)
        if master.status_code != 200:
            return "Failed to fetch master playlist", 500

        # Find media .m3u8 (second level)
        media_rel_url = None
        for line in master.text.splitlines():
            if line and not line.startswith("#"):
                media_rel_url = line.strip()
                break

        if not media_rel_url:
            return "No media playlist found", 500

        MEDIA_PLAYLIST_URL = urljoin(master.url, media_rel_url)
        base_url = MEDIA_PLAYLIST_URL.rsplit("/", 1)[0]

        # Fetch media playlist
        media = requests.get(MEDIA_PLAYLIST_URL, timeout=10)
        if media.status_code != 200:
            return "Failed to fetch media playlist", 500

        modified_lines = []
        for line in media.text.splitlines():
            if line.strip().endswith(".ts"):
                # Route through our Flask app
                full_url = f"/live/ts_proxy?segment={line.strip()}"
                modified_lines.append(full_url)
            else:
                modified_lines.append(line)

        return Response("\n".join(modified_lines), content_type="application/vnd.apple.mpegurl")

    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route("/live/ts_proxy")
def ts_proxy():
    segment = request.args.get("segment")
    if not segment or not MEDIA_PLAYLIST_URL:
        return "Missing segment", 400

    base_url = MEDIA_PLAYLIST_URL.rsplit("/", 1)[0]
    ts_url = urljoin(base_url + "/", segment)

    try:
        r = requests.get(ts_url, stream=True)
        return Response(r.iter_content(1024), content_type="video/MP2T")
    except Exception as e:
        return f"Failed to fetch .ts: {str(e)}", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
