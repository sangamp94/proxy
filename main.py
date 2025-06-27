import os
import time
import shutil
import requests
from flask import Flask, request, jsonify
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By

app = Flask(__name__)
DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def setup_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    prefs = {"download.default_directory": os.path.abspath(DOWNLOAD_DIR)}
    chrome_options.add_experimental_option("prefs", prefs)
    return webdriver.Chrome(executable_path=ChromeDriverManager().install(), options=chrome_options)

def get_download_link(driver, video_url):
    driver.get("https://pastedownload.com/youtube-video2-downloader/")
    time.sleep(2)
    input_box = driver.find_element(By.ID, "sf_url")
    input_box.clear()
    input_box.send_keys(video_url)
    driver.find_element(By.ID, "sf_submit").click()
    time.sleep(10)  # wait for download link to appear
    try:
        return driver.find_element(By.CSS_SELECTOR, "a.link-download").get_attribute("href")
    except:
        return None

def upload_to_pixeldrain(file_path):
    with open(file_path, "rb") as f:
        res = requests.post("https://pixeldrain.com/api/file", files={"file": f})
    if res.ok:
        return res.json().get("id")
    return None

def process_video(video_url):
    driver = setup_driver()
    try:
        print(f"[INFO] Processing: {video_url}")
        dl_link = get_download_link(driver, video_url)
        if not dl_link:
            return f"[ERROR] Couldn't fetch download link for: {video_url}"
        local_file = os.path.join(DOWNLOAD_DIR, "video.mp4")
        with requests.get(dl_link, stream=True) as r:
            with open(local_file, "wb") as f:
                shutil.copyfileobj(r.raw, f)
        pixeldrain_id = upload_to_pixeldrain(local_file)
        os.remove(local_file)
        return f"https://pixeldrain.com/u/{pixeldrain_id}" if pixeldrain_id else "[ERROR] Upload failed"
    finally:
        driver.quit()

@app.route("/upload_playlist", methods=["GET", "POST"])
def upload_playlist():
    playlist = request.args.get("playlist") or request.form.get("playlist")
    if not playlist:
        return "Missing 'playlist' parameter", 400

    print(f"[INFO] Starting for playlist: {playlist}")
    from yt_dlp import YoutubeDL
    with YoutubeDL({"quiet": True}) as ydl:
        playlist_info = ydl.extract_info(playlist, download=False)
        video_urls = [entry["webpage_url"] for entry in playlist_info["entries"] if entry]

    results = []
    for i in range(0, len(video_urls), 2):
        group = video_urls[i:i+2]
        for video_url in group:
            results.append(process_video(video_url))
        print("[INFO] Cleaned up batch\n")
    return jsonify(results)

@app.route("/", methods=["GET"])
def index():
    return '''
    <form method="post" action="/upload_playlist">
        <input type="text" name="playlist" placeholder="YouTube Playlist URL" required />
        <button type="submit">Start Upload</button>
    </form>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
