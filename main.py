import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

BASE_URL = "https://netfree2.cc/mobile/"
COOKIES = {
    "addhash": "0e820a116d8b179da9352a14c0565d4a::cc7d978d870ea795fbf8e189078b382d::1751194708"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Cookie": f"addhash={COOKIES['addhash']}"
}


def get_all_playlists():
    url = urljoin(BASE_URL, "index.php")
    res = requests.get(url, headers=HEADERS)
    soup = BeautifulSoup(res.text, "html.parser")

    playlists = []
    for a in soup.find_all("a", href=True):
        if "playlist.php?id=" in a["href"]:
            title = a.get_text(strip=True)
            full_url = urljoin(BASE_URL, a["href"])
            playlists.append((title, full_url))
    return playlists


def get_all_video_links(playlist_url):
    res = requests.get(playlist_url, headers=HEADERS)
    soup = BeautifulSoup(res.text, "html.parser")

    links = []
    for a in soup.find_all("a", href=True):
        if "view.php?id=" in a["href"]:
            links.append(urljoin(BASE_URL, a["href"]))
    return links


def extract_player_json(html_text):
    match = re.search(r'var\s+playerInstance\s*=\s*jwplayer\("player"\)\.setup\((\[\{.+?\}\])\);', html_text, re.DOTALL)
    if match:
        json_text = match.group(1)
        try:
            return json.loads(json_text)
        except json.JSONDecodeError:
            print("Failed to parse JSON")
    return None


def main():
    result = []

    playlists = get_all_playlists()
    print(f"Found {len(playlists)} playlists...")

    for playlist_title, playlist_url in playlists:
        print(f"Processing playlist: {playlist_title}")
        video_links = get_all_video_links(playlist_url)

        for video_url in video_links:
            try:
                r = requests.get(video_url, headers=HEADERS)
                player_data = extract_player_json(r.text)

                if player_data:
                    result.extend(player_data)
                else:
                    print(f"⚠️ Could not extract player JSON from: {video_url}")
            except Exception as e:
                print(f"❌ Error on {video_url}: {e}")

    with open("netfree2_export.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Done. Exported {len(result)} entries to netfree2_export.json")


if __name__ == "__main__":
    main()
