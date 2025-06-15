from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Allow GET to show a message at "/"
@app.route("/", methods=["GET"])
def home():
    return "✅ TeraBox Proxy is running. POST to /proxy with JSON: { link: 'TeraBox URL' }"

# Proxy endpoint that relays POST request to TeraBoxDownloader API
@app.route("/proxy", methods=["POST"])
def proxy():
    data = request.get_json()
    if not data or "link" not in data:
        return jsonify({"error": "Missing 'link' in request body"}), 400

    link = data["link"]

    try:
        response = requests.post(
            "https://teraboxdownloader.online/api.php",
            json={"url": link},
            headers={"Content-Type": "application/json"}
        )

        return jsonify(response.json())

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)
