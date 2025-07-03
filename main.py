from flask import Flask, Response, request
import requests
from urllib.parse import urljoin

app = Flask(__name__)

MASTER_M3U8 = "https://uxplaylists-live.vercel.app/uiop.php?id=56032"
MEDIA_PLAYLIST_URL = None  # Will be set dynamically

@app.route("/")
def home():
    return "✅ Paste <code>/live/stream.m3u8</code> into VLC or use m3u8-player.com"

@app.route("/live/stream.m3u8")
def stream():
    global MEDIA_PLAYLIST_URL
    try:
        # Fetch master playlist
        master = requests.get(MASTER_M3U8, timeout=10)
        if master.status_code != 200:
            return "Failed to fetch master playlist", 500

        # Extract variant (.m3u8) line
        media_rel_url = next((l.strip() for l in master.text.splitlines() if l and not l.startswith("#")), None)
        if not media_rel_url:
            return "No variant playlist found", 500

        MEDIA_PLAYLIST_URL = urljoin(master.url, media_rel_url)

        # Fetch the variant playlist
        media = requests.get(MEDIA_PLAYLIST_URL, timeout=10)
        if media.status_code != 200:
            return "Failed to fetch variant playlist", 500

        # Rewrite .ts and nested .m3u8 links
        modified_lines = []
        for line in media.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                modified_lines.append(line)
            elif line.endswith(".ts"):
                modified_lines.append(f"/live/ts_proxy?segment={line}")
            elif line.endswith(".m3u8"):
                modified_lines.append(f"/live/variant_proxy?variant={line}")
            else:
                modified_lines.append(line)

        return Response("\n".join(modified_lines), content_type="application/vnd.apple.mpegurl")

    except Exception as e:
        return f"Error in /live/stream.m3u8: {str(e)}", 500

@app.route("/live/variant_proxy")
def variant_proxy():
    variant = request.args.get("variant")
    if not variant or not MEDIA_PLAYLIST_URL:
        return "Missing variant or base URL", 400

    base_url = MEDIA_PLAYLIST_URL.rsplit("/", 1)[0]
    variant_url = urljoin(base_url + "/", variant)

    try:
        r = requests.get(variant_url, timeout=10)
        if r.status_code != 200:
            return "Failed to fetch variant playlist", 500

        modified_lines = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                modified_lines.append(line)
            elif line.endswith(".ts"):
                modified_lines.append(f"/live/ts_proxy?segment={line}")
            else:
                modified_lines.append(line)

        return Response("\n".join(modified_lines), content_type="application/vnd.apple.mpegurl")

    except Exception as e:
        return f"Error in /live/variant_proxy: {str(e)}", 500

@app.route("/live/ts_proxy")
def ts_proxy():
    segment = request.args.get("segment")
    if not segment or not MEDIA_PLAYLIST_URL:
        return "Missing segment or base URL", 400

    base_url = MEDIA_PLAYLIST_URL.rsplit("/", 1)[0]
    ts_url = urljoin(base_url + "/", segment)

    try:
        r = requests.get(ts_url, stream=True)
        return Response(r.iter_content(1024), content_type="video/MP2T")
    except Exception as e:
        return f"Error fetching TS segment: {str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
