from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route("/", methods=["GET"])
def home():
    return "🟢 TeraBox Proxy is running."

@app.route("/proxy", methods=["POST"])
def proxy():
    data = request.get_json()
    if not data or "link" not in data:
        return jsonify({"error": "Missing URL"}), 400

    link = data["link"]
    try:
        # Replace with your actual TeraBox extraction logic
        # For example, here it mimics a response structure
        response = {
            "direct_link": "https://example.com/video.mp4",
            "file_name": "Example Movie.mp4",
            "size": "1.23 GB",
            "thumb": "https://example.com/thumb.jpg"
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
