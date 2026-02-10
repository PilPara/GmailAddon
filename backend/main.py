from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/analyze', methods=["POST"])
def analyze_email():
    data = request.get_json()

    response = {
        "score": 50,
        "verdict": "Suspicious",
        "signals": [{"label": "Test signal", "points": 50, "details": "Dummy response"}]
    }

    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


