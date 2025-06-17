from flask import Flask, request
import requests
import os
from datetime import datetime, timedelta

app = Flask(__name__)

BOT_TOKEN = "7386617987:AAGounvetKHtmtqCxEbY_Idc5M2IfUNSst4"
API_KEY = "DaVkdyx2LrukvV1"  # Streamtape API Key
USERNAME = "tapoj45295@forcrack.com"  # required for Streamtape
API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/"

VALID_TOKEN = "12345678"  # Token for access control
user_tokens = {}
last_upload_time = {}
TOKEN_EXPIRY_HOURS = 5
UPLOAD_COOLDOWN_MINUTES = 2


def send_message(chat_id, text):
    requests.post(API_URL + "sendMessage", json={
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown"
    })


def is_user_verified(chat_id):
    expiry = user_tokens.get(chat_id)
    return expiry and datetime.now() < expiry


def is_upload_allowed(chat_id):
    last_time = last_upload_time.get(chat_id)
    return not last_time or datetime.now() >= last_time + timedelta(minutes=UPLOAD_COOLDOWN_MINUTES)


@app.route('/', methods=['POST'])
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
        send_message(chat_id, "👋 *Welcome to Video Upload 2 Bot!*\nUse `/token <your_token>` to unlock access.")
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
            send_message(chat_id, f"⏳ Please wait before uploading again.")
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
            response = requests.get(
                f"https://api.streamtape.com/file/ul?login={USERNAME}&key={API_KEY}&url={video_url}",
                timeout=20
            ).json()

            if response.get("status") == 200:
                link = response["result"]["url"]
                send_message(chat_id, f"✅ Uploaded!\n🔗 [Watch Now]({link})")
                last_upload_time[chat_id] = datetime.now()
            else:
                send_message(chat_id, f"❌ Failed: {response.get('msg', 'Unknown error')}")

        except Exception as e:
            send_message(chat_id, f"⚠️ Upload error: `{str(e)}`")

        return "ok"

    if video:
        send_message(chat_id, "⛔ *Direct file upload is not supported in Streamtape.*\nUse `/uploadurl <video_url>`.")
        return "ok"

    return "ok"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
