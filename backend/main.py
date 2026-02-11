from flask import Flask, request, jsonify
from auth_analyzer import anaylze_auth
from domain_analyzer import analyze_domain
from link_analyzer import analyze_links
from llm_analyzer import analyze_with_llm
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
    domain_response = analyze_domain(data)
    pretyPrint(domain_response)
    links_response = analyze_links(data)
    pretyPrint(links_response)

    llm_response = analyze_with_llm(data)
    pretyPrint(llm_response)

    return jsonify({
        "score": 0,
        "verdict": "Safe",
        "signals": auth_response["signals"] + domain_response["signals"] + links_response["signals"] + llm_response["signals"]
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)


