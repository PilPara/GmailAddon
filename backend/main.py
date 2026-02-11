from flask import Flask, request, jsonify
from auth_analyzer import anaylze_auth

app = Flask(__name__)

@app.route('/analyze', methods=["POST"])
def analyze_email():
    data = request.get_json()
    # print(data)
    # print(data.get("authResults"))

    response = anaylze_auth(data)
    print(response)
    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)


