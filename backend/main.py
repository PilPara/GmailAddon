from flask import Flask, request, jsonify
from auth_analyzer import anaylze_auth
import os

app = Flask(__name__)

@app.route('/analyze', methods=["POST"])
def analyze_email():
    data = request.get_json()
    # print(data)
    # print(data.get("authResults"))

    response = anaylze_auth(data)
    print(response)

    return jsonify({
        "score": 0,
        "verdict": "Safe",
        "signals": response["signals"]
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)


