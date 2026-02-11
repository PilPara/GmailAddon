from flask import Flask, request, jsonify
from auth_analyzer import anaylze_auth
from domain_analyzer import analyze_domain
import os
import json


app = Flask(__name__)

def pretyPrint(data, indent=2):
    print(json.dumps(data, indent=indent))

@app.route('/analyze', methods=["POST"])
def analyze_email():
    data = request.get_json()
    pretyPrint(data)
    # print(data.get("authResults"))

    auth_response = anaylze_auth(data)
    pretyPrint(auth_response)
    domain_response = anaylze_auth(data)
    pretyPrint(domain_response)

    return jsonify({
        "score": 0,
        "verdict": "Safe",
        "signals": auth_response["signals"] + domain_response["signals"]
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)


