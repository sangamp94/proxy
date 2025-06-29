from flask import Flask, jsonify, send_file
import requests
from bs4 import BeautifulSoup
import zipfile
import os

app = Flask(__name__)

# Netfree2 cookies (converted to headers)
COOKIES = {
    "addhash": "0e820a116d8b179da9352a14c0565d4a::cc7d978d870ea795fbf8e189078b382d::1751194708::ni",
    "HstCfa1685644": "1751194706126",
    "HstCla1685644": "1751194706126",
    "HstCmu1685644": "1751194706126",
    "HstPn1685644": "1",
    "HstPt1685644": "1",
    "HstCnv1685644": "1",
    "HstCns1685644": "1",
    "__dtsu": "51A01751194713F1D2BD232A1B3CB7E9",
    "t_hash_t": "a20e055be926993c2f00c22c358bfd79::7e6d83663c61b4bb08a90ab4dc69239e::1751194749::ni",
    "HstCfa1188575": "1751194751474",
    "HstCla1188575": "1751194751474",
    "HstCmu1188575": "1751194751474",
    "HstPn1188575": "1",
    "HstPt1188575": "1",
    "HstCnv1188575": "1",
    "HstCns1188575": "1"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}

@app.route("/")
def home():
    return '''
    ✅ NetFree2 Scraper is running.<br><br>
    <a href="/fetch_data">➡️ View Fetched Data (JSON)</a><br><br>
    <a href="/download"><button>⬇️ Download Code as ZIP</button></a>
    '''

@app.route("/fetch_data")
def fetch_data():
    try:
        url = "https://netfree2.cc/mobile/home"
        response = requests.get(url, cookies=COOKIES, headers=HEADERS)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        items = []
        for card in soup.select(".container .card"):
            title = card.select_one("h5")
            link = card.find("a", href=True)
            image = card.find("img", src=True)

            items.append({
                "title": title.text.strip() if title else None,
                "link": link['href'] if link else None,
                "image": image['src'] if image else None
            })

        return jsonify({
            "status": "success",
            "total_items": len(items),
            "data": items
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/download")
def download_code_zip():
    zip_filename = "netfree2_scraper_code.zip"

    # Create ZIP with main.py and requirements.txt
    with zipfile.ZipFile(zip_filename, "w") as zipf:
        if os.path.exists("main.py"):
            zipf.write("main.py")
        if os.path.exists("requirements.txt"):
            zipf.write("requirements.txt")

    return send_file(zip_filename, as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # 10000 for local fallback
    app.run(host="0.0.0.0", port=port)
