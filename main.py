import os
import time
import requests
from flask import Flask, request, jsonify, render_template_string
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from yt_dlp import YoutubeDL

app = Flask(__name__)
DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ----------- Setup Chrome Driver ----------
def setup_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=chrome_options)

# ----------- Extract video URLs from YouTube playlist ----------
def extract_video_urls(playlist_url):
    ydl_opts = {
        'extract_flat': True,
        'force_generic_extractor': False,
        'quiet': True,
        'dump_single_json': True
    }
    with YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(playlist_url, download=False)
        return [entry['url'] for entry in info.get('entries', [])]

# ----------- Download using PasteDownload ----------
def download_video_via_pastedownload(video_url, driver):
    driver.get("https://pastedownload.com/youtube-video2-downloader/")
    input_box = driver.find_element(By.ID, "sf_url")
    input_box.clear()
    input_box.send_keys(video_url)
    driver.find_element(By.ID, "sf_submit").click()

    time.sleep(7)  # Let the links load

    links = driver.find_elements(By.XPATH, "//a[contains(@class, 'download-link')]")
    for link in links:
        href = link.get_attribute("href")
        if href and "https" in href and (".mp4" in href or "video" in href):
            filename = os.path.join(DOWNLOAD_DIR, "video_" + str(int(time.time())) + ".mp4")
            print("Downloading:", href)
            with open(filename, "wb") as f:
                f.write(requests.get(href).content)
            return filename
    return None

# ----------- Upload to Pixeldrain ----------
def upload_to_pixeldrain(file_path):
    with open(file_path, 'rb') as f:
        response = requests.post('https://pixeldrain.com/api/file', files={'file': f})
    return response.json().get("link", "")

# ----------- Upload Playlist View ----------
@app.route("/upload_playlist", methods=["GET", "POST"])
def upload_playlist():
    playlist_url = request.args.get("playlist") if request.method == "GET" else request.form.get("playlist")
    if not playlist_url:
        return jsonify({"error": "Missing playlist parameter"}), 400

    urls = extract_video_urls(playlist_url)
    if not urls:
        return jsonify({"error": "No videos found"}), 400

    driver = setup_driver()
    uploaded_links = []

    # 2 videos at a time
    for i in range(0, len(urls), 2):
        batch = urls[i:i+2]
        local_files = []

        for url in batch:
            try:
                file = download_video_via_pastedownload(url, driver)
                if file:
                    local_files.append(file)
            except Exception as e:
                print(f"Error downloading {url}: {e}")

        for file in local_files:
            try:
                pixeldrain_url = upload_to_pixeldrain(file)
                uploaded_links.append("https://pixeldrain.com/u/" + pixeldrain_url)
            except Exception as e:
                print(f"Error uploading {file}: {e}")
            finally:
                os.remove(file)

    driver.quit()
    return jsonify({"uploaded": uploaded_links})

# ----------- Upload Form ----------
@app.route("/upload_form")
def upload_form():
    return render_template_string('''
    <form method="post" action="/upload_playlist">
        <input type="text" name="playlist" placeholder="YouTube playlist URL" required>
        <input type="submit" value="Start Upload">
    </form>
    ''')

# ----------- Home ----------
@app.route("/")
def index():
    return "YouTube Playlist ➜ PasteDownload ➜ Pixeldrain Uploader"

if __name__ == "__main__":
    app.run(debug=True, port=10000)
