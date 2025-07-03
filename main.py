from flask import Flask, Response, request
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# Original playlist source (protected)
SOURCE_URL = "https://tp.kliv.fun/PROTP2990/playlist.php"

# Spoof OTT Navigator user-agent
HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; com.ott.play)"
}

@app.route('/')
def home():
    return (
        "✅ OTT Navigator M3U8 Proxy running!<br>"
        "Play via <code>/live/playlist.m3u8</code> in VLC."
    )

@app.route('/live/playlist.m3u8')
def proxy_playlist():
    try:
        # Get the actual m3u8 content
        res = requests.get(SOURCE_URL, headers=HEADERS, allow_redirects=True, timeout=10)
        res.raise_for_status()

        content = res.text
        final_url = res.url
        base_url = final_url.rsplit('/', 1)[0] + "/"

        # Rewrite .ts and nested .m3u8 links as absolute
        new_lines = []
        for line in content.splitlines():
            if line.strip().endswith(".ts") or line.strip().endswith(".m3u8"):
                full_url = urljoin(base_url, line.strip())
                new_lines.append(full_url)
            else:
                new_lines.append(line)

        rewritten_playlist = "\n".join(new_lines)

        return Response(rewritten_playlist, mimetype="application/vnd.apple.mpegurl")
    except Exception as e:
        return Response(f"#EXTM3U\n# Proxy error: {e}", mimetype="application/vnd.apple.mpegurl")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
