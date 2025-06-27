from flask import Flask, request, jsonify, render_template_string
import os, time, requests, shutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from yt_dlp import YoutubeDL

app = Flask(__name__)
PIXELDRAIN_API_KEY = "4c407095-bec6-4fb3-acff-7d57003b5da8"

# === Utilities ===

def get_playlist_video_urls(playlist_url):
    ydl_opts = {
        'quiet': True,
        'extract_flat': 'in_playlist',
        'dump_single_json': True,
    }
    with YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(playlist_url, download=False)
        return [entry['url'] for entry in info.get("entries", [])]

def setup_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    return webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)

def download_from_pastedownload(driver, video_url):
    try:
        driver.get("https://pastedownload.com/youtube-video2-downloader/#url=" + video_url)
        time.sleep(5)
        links = driver.find_elements("css selector", "a.download-button")
        for link in links:
            href = link.get_attribute("href")
            if href and href.endswith(".mp4"):
                filename = f"video_{int(time.time())}.mp4"
                r = requests.get(href, stream=True)
                with open(filename, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                return filename
    except Exception as e:
        print("❌ Error downloading:", e)
    return None

def upload_to_pixeldrain(filepath):
    with open(filepath, 'rb') as f:
        r = requests.post(
            "https://pixeldrain.com/api/file",
            auth=('', PIXELDRAIN_API_KEY),
            files={"file": f}
        )
    result = r.json()
    if result.get("success"):
        return f"https://pixeldrain.com/u/{result['id']}"
    return None

# === Routes ===

@app.route("/", methods=["GET"])
def form():
    return render_template_string('''
        <h2>🎬 Pixeldrain YouTube Playlist Uploader via PasteDownload</h2>
        <form method="POST" action="/upload_playlist">
            <input type="text" name="playlist" placeholder="Enter YouTube Playlist URL" size="60" required>
            <br><br>
            <button type="submit">🚀 Start Upload</button>
        </form>
    ''')

@app.route("/upload_playlist", methods=["GET", "POST"])
def upload_playlist():
    playlist_url = request.values.get("playlist")
    if not playlist_url:
        return jsonify({"error": "Missing playlist URL"}), 400

    video_urls = get_playlist_video_urls(playlist_url)
    uploaded = []
    failed = []
    driver = setup_driver()

    for i in range(0, len(video_urls), 2):
        downloaded = []
        for j in range(i, min(i+2, len(video_urls))):
            url = f"https://youtube.com/watch?v={video_urls[j]}"
            print(f"⬇️ Downloading: {url}")
            file = download_from_pastedownload(driver, url)
            if file:
                print(f"✅ Downloaded {file}")
                downloaded.append((url, file))
            else:
                failed.append({"url": url, "error": "Download failed"})

        for url, file in downloaded:
            print(f"📤 Uploading: {file}")
            link = upload_to_pixeldrain(file)
            if link:
                uploaded.append({"url": url, "pixeldrain": link})
            else:
                failed.append({"url": url, "error": "Upload failed"})
            os.remove(file)

    driver.quit()

    return jsonify({
        "total": len(video_urls),
        "uploaded": uploaded,
        "failed": failed
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
