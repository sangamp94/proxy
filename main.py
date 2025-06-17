from flask import Flask, request
import requests
import os
import time
from datetime import datetime, timedelta

app = Flask(__name__)

BOT_TOKEN = "7386617987:AAGounvetKHtmtqCxEbY_Idc5M2IfUNSst4"
API_KEY = "DaVkdyx2LrukvV1"
USERNAME = "4694ed2e56e889559977"
API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/"

VALID_TOKEN = "12345678"
user_tokens = {}
last_upload_time = {}
TOKEN_EXPIRY_HOURS = 5
UPLOAD_COOLDOWN_MINUTES = 2

def send_message(chat_id, text):
    requests.post(API_URL + "sendMessage", json={
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    })

def is_user_verified(chat_id):
    expiry = user_tokens.get(chat_id)
    return expiry and datetime.now() < expiry

def is_upload_allowed(chat_id):
    last_time = last_upload_time.get(chat_id)
    return not last_time or datetime.now() >= last_time + timedelta(minutes=UPLOAD_COOLDOWN_MINUTES)

def wait_for_streamtape(remote_id):
    status_url = f"https://api.streamtape.com/remotedl/status?login={USERNAME}&key={API_KEY}&id={remote_id}"
    for _ in range(30):  # 30 x 5s = 150s max wait
        time.sleep(5)
        try:
            res = requests.get(status_url).json()
            entry = res["result"].get(remote_id)
            if not entry:
                break
            if entry["status"] == "downloaded":
                return entry["url"]
            elif entry["status"] == "error":
                return "ERROR"
        except:
            pass
    return None

@app.route("/", methods=["POST"])
def webhook():
    update = request.get_json()
    if not update:
        return "No update received"

    message = update.get("message")
    if not message:
        return "No message"

    chat_id = message["chat"]["id"]
    text = message.get("text")
    video = message.get("video") or message.get("document")

    if text and text.startswith("/start"):
        send_message(chat_id, "👋 *Welcome to Streamtape Bot!*\nUse `/token <your_token>` to unlock access.")
        return "ok"

    if text and text.startswith("/token"):
        parts = text.split(" ", 1)
        if len(parts) < 2:
            send_message(chat_id, "❗ Usage: `/token <your_token>`")
            return "ok"
        input_token = parts[1].strip()
        if input_token == VALID_TOKEN:
            user_tokens[chat_id] = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
            send_message(chat_id, f"✅ *Access granted for {TOKEN_EXPIRY_HOURS} hours!*")
        else:
            send_message(chat_id, "⛔ *Invalid token.*")
        return "ok"

    if text and text.startswith("/uploadurl"):
        if not is_user_verified(chat_id):
            send_message(chat_id, "⛔ *Access denied. Use `/token <your_token>` first.*")
            return "ok"
        if not is_upload_allowed(chat_id):
            send_message(chat_id, "⏳ Please wait before uploading again.")
            return "ok"

        parts = text.split(" ", 1)
        if len(parts) < 2:
            send_message(chat_id, "❗ Usage: `/uploadurl <video_url>`")
            return "ok"

        video_url = parts[1].strip()
        if not video_url.startswith("http"):
            send_message(chat_id, "❗ Invalid video URL.")
            return "ok"

        send_message(chat_id, "🔄 Uploading to *Streamtape*...")

        try:
            # Step 1: Start remote upload
            add_url = f"https://api.streamtape.com/remotedl/add?login={USERNAME}&key={API_KEY}&url={video_url}"
            response = requests.get(add_url, timeout=20).json()

            if response.get("status") != 200:
                send_message(chat_id, f"❌ Upload failed: {response.get('msg', 'Unknown error')}")
                return "ok"

            remote_id = response["result"]["id"]
            send_message(chat_id, "⏳ Waiting for Streamtape to finish processing...")

            # Step 2: Wait for status
            final_url = wait_for_streamtape(remote_id)

            if final_url and final_url != "ERROR":
                send_message(chat_id, f"✅ *Uploaded Successfully!*\n🔗 [Watch Now]({final_url})")
                last_upload_time[chat_id] = datetime.now()
            elif final_url == "ERROR":
                send_message(chat_id, "❌ Upload failed during processing.")
            else:
                send_message(chat_id, "⚠️ Timeout. Streamtape took too long to respond.")

        except Exception as e:
            send_message(chat_id, f"⚠️ Error: `{str(e)}`")

        return "ok"

    if video:
        send_message(chat_id, "⛔ *Direct file upload not supported.* Use `/uploadurl <video_url>`.")
        return "ok"

    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
