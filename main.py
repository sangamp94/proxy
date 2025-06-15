from flask import Flask, request, jsonify
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all origins

@app.route('/')
def home():
    return "TeraBox Proxy is running."

@app.route('/proxy', methods=['POST'])
def proxy():
    try:
        url = "https://teraboxdownloader.online/api.php"
        headers = {'Content-Type': 'application/json'}
        payload = request.get_json()

        if not payload or 'link' not in payload:
            return jsonify({"error": "Missing 'link' in request."}), 400

        response = requests.post(url, json=payload, headers=headers)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
