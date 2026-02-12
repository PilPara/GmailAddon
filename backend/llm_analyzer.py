import os
import json
import requests

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_API_KEY1 = os.environ.get("GEMINI_API_KEY1")
GEMINI_API_KEY_BRO = os.environ.get("GEMINI_API_KEY_BRO")

# NOTE: Ordered list of model + key combinations to try
# Falls back through the chain until one succeeds
GEMINI_MODELS = [
    {"model": "gemini-2.5-flash", "key": GEMINI_API_KEY},
    {"model": "gemini-2.5-flash", "key": GEMINI_API_KEY1},
    {"model": "gemini-2.5-flash", "key": GEMINI_API_KEY_BRO},
    {"model": "gemini-2.0-flash", "key": GEMINI_API_KEY},
    {"model": "gemini-2.0-flash", "key": GEMINI_API_KEY1},
    {"model": "gemini-2.0-flash", "key": GEMINI_API_KEY_BRO},
]

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

# NOTE: Load LLM prompt from external file for readability and maintainability
PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompt.txt")
with open(PROMPT_PATH, "r") as f:
    SYSTEM_PROMPT = f.read()


def try_gemini_request(payload):
    # NOTE: Try each model+key combo in order, return first successful response
    last_error = None

    for combo in GEMINI_MODELS:
        if not combo["key"]:
            continue

        url = GEMINI_BASE_URL.format(model=combo["model"], key=combo["key"])

        try:
            print(f"Trying {combo['model']} with key ...{combo['key'][-4:]}")
            response = requests.post(url, json=payload, timeout=15)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            last_error = e
            # NOTE: Redact both possible keys from error messages
            error_msg = str(e)
            if GEMINI_API_KEY:
                error_msg = error_msg.replace(GEMINI_API_KEY, "[REDACTED]")
            if GEMINI_API_KEY_BRO:
                error_msg = error_msg.replace(GEMINI_API_KEY_BRO, "[REDACTED_BRO]")
            if GEMINI_API_KEY1:
                error_msg = error_msg.replace(GEMINI_API_KEY1, "[REDACTED_1]")
            print(f"Failed: {error_msg}")
            continue

    return last_error


def analyze_with_llm(headers):
    signals = []
    subject = headers.get("subject", "")
    body = headers.get("body", "")

    if not GEMINI_API_KEY and not GEMINI_API_KEY_BRO:
        signals.append({
            "label": "LLM Analysis Skipped",
            "details": "No Gemini API keys configured",
            "user_details": "AI analysis is not available"
        })
        return {"signals": signals}

    user_message = f"Subject: {subject}\n\nBody: {body}"

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": SYSTEM_PROMPT + "\n\n" + user_message}]
            }
        ]
    }

    result = try_gemini_request(payload)

    # NOTE: If all attempts failed, result is the last exception
    if isinstance(result, Exception):
        error_msg = str(result)
        if GEMINI_API_KEY:
            error_msg = error_msg.replace(GEMINI_API_KEY, "[REDACTED]")
        if GEMINI_API_KEY_BRO:
            error_msg = error_msg.replace(GEMINI_API_KEY_BRO, "[REDACTED_BRO]")
        signals.append({
            "label": "LLM Analysis Failed",
            "details": f"All models failed. Last error: {error_msg}",
            "user_details": "AI analysis could not be completed — other checks are still active"
        })
        return {"signals": signals}

    try:
        data = result.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        analysis = json.loads(text)

        # NOTE: Urgency signal
        urgency = analysis.get("urgency", {})
        level = urgency.get("level", "unknown")
        phrases = urgency.get("phrases", [])
        phrase_str = ", ".join(phrases) if phrases else "none"

        urgency_user_details = {
            "none": "No pressure tactics detected in this email",
            "low": "Mild time-sensitive language detected — likely normal",
            "moderate": "This email uses language designed to make you act quickly",
            "high": "This email uses strong pressure tactics to rush you into action"
        }

        signals.append({
            "label": f"Urgency: {level.capitalize()}",
            "details": f"Phrases detected: {phrase_str}",
            "user_details": urgency_user_details.get(level, "Could not determine urgency level")
        })

        # NOTE: Social engineering signal
        se = analysis.get("social_engineering", {})
        tactics = se.get("tactics", [])
        se_details = se.get("details", "")

        if tactics:
            signals.append({
                "label": f"Social Engineering: {len(tactics)} tactic(s)",
                "details": f"{', '.join(tactics)} — {se_details}",
                "user_details": f"This email uses {len(tactics)} manipulation technique(s) to influence your behavior"
            })
        else:
            signals.append({
                "label": "Social Engineering: None",
                "details": "No manipulation tactics detected",
                "user_details": "No manipulation techniques detected"
            })

        # NOTE: Classification signal — used by scoring engine for both
        # likelihood (deception sophistication) and impact (attack type)
        classification = analysis.get("classification", {})
        attack_type = classification.get("attack_type", "unknown")
        confidence = classification.get("confidence", 0)

        classification_user_details = {
            "legitimate": f"This email appears to be legitimate ({confidence}% confidence)",
            "phishing": f"This email appears to be a phishing attempt ({confidence}% confidence)",
            "spear_phishing": f"This email appears to be a targeted phishing attack ({confidence}% confidence)",
            "bec": f"This email may be impersonating someone you work with ({confidence}% confidence)",
            "scam": f"This email appears to be a scam ({confidence}% confidence)",
            "malware_delivery": f"This email may be trying to install malicious software ({confidence}% confidence)",
            "credential_harvesting": f"This email may be trying to steal your login credentials ({confidence}% confidence)",
            "urgency_scam": f"This email uses urgency to pressure you into a scam ({confidence}% confidence)"
        }

        signals.append({
            "label": f"Classification: {attack_type.replace('_', ' ').title()}",
            "details": f"Confidence: {confidence}%",
            "user_details": classification_user_details.get(attack_type, f"Classification: {attack_type} ({confidence}% confidence)")
        })

        # NOTE: Plain English summary for end user
        explanation = analysis.get("explanation", "")
        if explanation:
            signals.append({
                "label": "AI Summary",
                "details": explanation,
                "user_details": explanation
            })

    except (json.JSONDecodeError, KeyError) as e:
        signals.append({
            "label": "LLM Analysis Failed",
            "details": f"Failed to parse Gemini response: {str(e)}",
            "user_details": "AI analysis could not be completed — other checks are still active"
        })

    return {"signals": signals}
