import re
import json
import requests
import http.cookiejar
from bs4 import BeautifulSoup
from flask import Flask, send_file
from urllib.parse import urljoin

app = Flask(__name__)
BASE_URL = "https://netfree2.cc/mobile/"

def load_cookies_from_file(path="cookies.txt"):
    cj = http.cookiejar.MozillaCookieJar()
    try:
        cj.load(path, ignore_discard=True, ignore_expires=True)
        return cj
    except Exception as e:
        print(f"❌ Failed to load cookies from {path}: {e}")
        return None

def get_all_playlists(session):
    url = urljoin(BASE_URL, "playlist.php")
    res = session.get(url)
    if res.status_code != 200:
        print(f"❌ Error fetching playlist.php: {res.status_code}")
        return []

    soup = BeautifulSoup(res.text, "html.parser")
    playlists = []
    for a in soup.find_all("a", href=True):
        if "playlist.php?id=" in a["href"]:
            title = a.get_text(strip=True)
            full_url = urljoin(BASE_URL, a["href"])
            playlists.append((title, full_url))
    print(f"✅ Found {len(playlists)} playlists.")
    return playlists

def get_all_video_links(session, playlist_url):
    res = session.get(playlist_url)
    soup = BeautifulSoup(res.text, "html.parser")

    links = []
    for a in soup.find_all("a", href=True):
        if "view.php?id=" in a["href"]:
            links.append(urljoin(BASE_URL, a["href"]))
    return links

def extract_player_json(html_text):
    match = re.search(
        r'var\s+playerInstance\s*=\s*jwplayer\("player"\)\.setup\((\[\{.+?\}\])\);',
        html_text, re.DOTALL
    )
    if match:
        json_text = match.group(1)
        try:
            return json.loads(json_text)
        except json.JSONDecodeError:
            print("⚠️ JSON parsing error.")
    return None

@app.route("/scrape")
def scrape():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0"
    })

    cookies = load_cookies_from_file("cookies.txt")
    if not cookies:
        return "❌ Cookie load failed", 500

    session.cookies = cookies
    result = []

    playlists = get_all_playlists(session)
    for title, url in playlists:
        print(f"\n🎬 Playlist: {title}")
        video_links = get_all_video_links(session, url)
        for video_url in video_links:
            try:
                r = session.get(video_url)
                player_data = extract_player_json(r.text)
                if player_data:
                    result.extend(player_data)
            except Exception as e:
                print(f"❌ Error on {video_url}: {e}")

    with open("netfree2_export.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return send_file("netfree2_export.json", as_attachment=True)

@app.route("/")
def index():
    return "<h2>NetFree2 Scraper</h2><p><a href='/scrape'>Click to export all NetFree2 videos JSON</a></p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
