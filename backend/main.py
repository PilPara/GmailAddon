from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dotenv import load_dotenv
from auth_analyzer import anaylze_auth
from domain_analyzer import analyze_domain
from link_analyzer import analyze_links
from llm_analyzer import analyze_with_llm
from attachment_analyzer import analyze_attachments
from scorer import calculate_score
import os
import json
import time

load_dotenv()

app = Flask(__name__)

def prettyPrint(data, indent=2):
    print(json.dumps(data, indent=indent))

@app.route('/analyze', methods=["POST"])
def analyze_email():
    start = time.time()
    data = request.get_json()

    # NOTE: ThreadPoolExecutor creates a pool of worker threads
    # Used because the LLM API call is slow (2-5s)
    # while all other analyzers finish in milliseconds
    with ThreadPoolExecutor() as executor:

        # NOTE: Submit LLM to a separate thread — starts running immediately in background
        # Returns a "future" (a promise that the result will be available later)
        llm_future = executor.submit(analyze_with_llm, data)

        # NOTE: Run all fast analyzers on the main thread while LLM works in parallel
        auth_response = anaylze_auth(data)
        domain_response = analyze_domain(data)
        links_response = analyze_links(data)
        attachment_response = analyze_attachments(data)

        sync_done = time.time()
        print(f"Sync analyzers: {sync_done - start:.2f}s")

        # NOTE: Collect LLM result — returns instantly if already finished,
        # otherwise waits up to 15 seconds.
        # Graceful degradation: if LLM fails or times out, results are still returned
        try:
            llm_response = llm_future.result(timeout=15)
        except TimeoutError:
            llm_response = {"signals": [{"label": "LLM Analysis Unavailable", "details": "Request timed out"}]}
        except Exception as e:
            print(f"LLM failed: {e}")
            llm_response = {"signals": [{"label": "LLM Analysis Unavailable", "details": str(e)}]}

        print(f"LLM wait: {time.time() - sync_done:.2f}s")

    # NOTE: Merge all signals from every analyzer into one list
    signals = (
        auth_response["signals"] +
        domain_response["signals"] +
        links_response["signals"] +
        llm_response["signals"] +
        attachment_response["signals"]
    )

    # NOTE: Pass all signals to scoring engine (OWASP Likelihood x Impact)
    result = calculate_score(signals)
    print(f"Scoring debug: {result['debug']}")

    print(f"Total analysis time: {time.time() - start:.2f}s")

    return jsonify({
        "score": result["score"],
        "verdict": result["severity"],
        "signals": signals
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
