import os
import requests
from flask import Flask, send_file, request
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import shutil
import zipfile

app = Flask(__name__)

COOKIES = {
    "addhash": "0e820a116d8b179da9352a14c0565d4a::cc7d978d870ea795fbf8e189078b382d::1751194708"
}

def download_site(url, session, base_folder):
    os.makedirs(base_folder, exist_ok=True)
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    html_file = os.path.join(base_folder, "index.html")
    with open(html_file, "w", encoding='utf-8') as f:
        f.write(response.text)

    tags_attrs = {
        'link': 'href',
        'script': 'src',
        'img': 'src',
        'iframe': 'src',
        'source': 'src'
    }

    downloaded_assets = []

    for tag, attr in tags_attrs.items():
        for element in soup.find_all(tag):
            asset_url = element.get(attr)
            if not asset_url:
                continue

            asset_full_url = urljoin(url, asset_url)
            parsed = urlparse(asset_full_url)
            filename = parsed.path.strip("/").replace("/", "_")
            if not filename:
                continue

            try:
                asset_data = session.get(asset_full_url).content
                asset_path = os.path.join(base_folder, filename)
                with open(asset_path, "wb") as af:
                    af.write(asset_data)
                downloaded_assets.append(asset_path)
            except:
                continue

    return base_folder

def zip_folder(folder_path, output_path):
    shutil.make_archive(output_path, 'zip', folder_path)
    return output_path + ".zip"

@app.route("/")
def index():
    return '''
    <form action="/clone" method="get">
      URL: <input name="url" value="https://netfree2.cc" />
      <input type="submit" value="Clone Website">
    </form>
    '''

@app.route("/clone")
def clone_website():
    target_url = request.args.get("url")
    if not target_url:
        return "URL missing", 400

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Cookie": f"addhash={COOKIES['addhash']}"
    })

    base_folder = "cloned_site"
    zip_name = "netfree2_clone"

    if os.path.exists(base_folder):
        shutil.rmtree(base_folder)

    try:
        download_site(target_url, session, base_folder)
        zip_path = zip_folder(base_folder, zip_name)
        return send_file(zip_path, as_attachment=True)
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
