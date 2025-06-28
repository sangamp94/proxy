import os
import shutil
import requests
from bs4 import BeautifulSoup
from flask import Flask, send_file

app = Flask(__name__)
SCRAPE_URL = "https://mov.mafia.live"
OUTPUT_DIR = "scraped_site"
ZIP_FILE = "site_dump.zip"

headers = {"User-Agent": "Mozilla/5.0"}

def download_asset(url, folder):
    try:
        local_filename = url.split("/")[-1].split("?")[0]
        r = requests.get(url, headers=headers, timeout=10, stream=True)
        if r.status_code == 200:
            path = os.path.join(folder, local_filename)
            with open(path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            return f"./assets/{local_filename}"
    except:
        pass
    return url  # fallback

def scrape_and_save():
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(os.path.join(OUTPUT_DIR, "assets"), exist_ok=True)

    resp = requests.get(SCRAPE_URL, headers=headers)
    soup = BeautifulSoup(resp.text, "html.parser")

    for tag in soup.find_all(["link", "script", "img"]):
        attr = "src" if tag.name in ["script", "img"] else "href"
        if tag.has_attr(attr):
            link = tag[attr]
            if link.startswith("http") and "://" in link:
                local_path = download_asset(link, os.path.join(OUTPUT_DIR, "assets"))
                tag[attr] = local_path

    with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(soup.prettify())

    shutil.make_archive("site_dump", 'zip', OUTPUT_DIR)

@app.route("/")
def home():
    return "<h2>Visit <a href='/download'>/download</a> to get ZIP of mov.mafia.live homepage.</h2>"

@app.route("/download")
def download_zip():
    scrape_and_save()
    return send_file(ZIP_FILE, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
