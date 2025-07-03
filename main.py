from flask import Flask, request, Response, render_template_string
import requests

app = Flask(__name__)
REMOTE_BASE = ""  # Global base for .ts files

@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
      <title>Restream Player</title>
      <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
    </head>
    <body>
      <h2>Restreamed M3U8 Stream</h2>
      <video id="video" width="100%" height="auto" controls autoplay></video>
      <script>
        if(Hls.isSupported()) {
          var video = document.getElementById('video');
          var hls = new Hls();
          hls.loadSource('/stream.m3u8');
          hls.attachMedia(video);
          hls.on(Hls.Events.MANIFEST_PARSED,function() {
            video.play();
          });
        }
      </script>
    </body>
    </html>
    """)

@app.route("/stream.m3u8")
def proxy_m3u8():
    global REMOTE_BASE
    url = request.args.get("url") or "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"
    REMOTE_BASE = url.rsplit("/", 1)[0]
    r = requests.get(url)
    data = r.text
    # Rewrite .ts segment paths to hit our proxy
    data = data.replace(".ts", ".ts-proxy")
    return Response(data, content_type="application/vnd.apple.mpegurl")

@app.route("/<segment>.ts-proxy")
def proxy_ts(segment):
    global REMOTE_BASE
    ts_url = f"{REMOTE_BASE}/{segment}.ts"
    r = requests.get(ts_url, stream=True)
    return Response(r.iter_content(chunk_size=1024), content_type="video/MP2T")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
