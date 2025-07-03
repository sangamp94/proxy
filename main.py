import requests
import subprocess

# Spoof OTT Navigator User-Agent
OTT_USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 10; com.ott.play)"

def resolve_redirect(spoo_url):
    headers = {
        "User-Agent": OTT_USER_AGENT,
    }

    try:
        print(f"[+] Resolving: {spoo_url}")
        response = requests.get(spoo_url, headers=headers, allow_redirects=True, timeout=10)
        final_url = response.url
        print(f"[✓] Final URL: {final_url}")
        return final_url
    except requests.RequestException as e:
        print(f"[✗] Error resolving URL: {e}")
        return None

def play_with_streamlink(url):
    try:
        print("[🎥] Launching streamlink with OTT headers...")
        subprocess.run([
            "streamlink",
            "--http-header", f"User-Agent={OTT_USER_AGENT}",
            url,
            "best"
        ])
    except FileNotFoundError:
        print("[!] streamlink is not installed. Falling back to VLC.")
        return False

def play_with_vlc(url):
    print("[🎬] Launching VLC with OTT headers...")
    try:
        subprocess.run([
            "vlc",
            "--http-user-agent", OTT_USER_AGENT,
            url
        ])
    except FileNotFoundError:
        print("[!] VLC not installed or not in PATH.")

if __name__ == "__main__":
    spoo_url = "https://spoo.me/Tpk"

    final_url = resolve_redirect(spoo_url)
    if final_url and final_url.endswith(".m3u8"):
        played = play_with_streamlink(final_url)
        if not played:
            play_with_vlc(final_url)
    else:
        print("[!] Final URL is not a valid .m3u8 stream.")
