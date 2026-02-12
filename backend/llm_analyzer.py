import os
import json
import requests

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"

# NOTE: Load LLM prompt from external file for readability and maintainability
PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompt.txt")
with open(PROMPT_PATH, "r") as f:
    SYSTEM_PROMPT = f.read()


def analyze_with_llm(headers):
    signals = []
    subject = headers.get("subject", "")
    body = headers.get("body", "")

    if not GEMINI_API_KEY:
        signals.append({
            "label": "LLM Analysis Skipped",
            "details": "Gemini API key not configured"
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

    try:
        response = requests.post(GEMINI_URL, json=payload, timeout=15)
        response.raise_for_status()
        result = response.json()

        text = result["candidates"][0]["content"]["parts"][0]["text"]
        text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        analysis = json.loads(text)

        # NOTE: Urgency signal
        urgency = analysis.get("urgency", {})
        level = urgency.get("level", "unknown")
        phrases = urgency.get("phrases", [])
        phrase_str = ", ".join(phrases) if phrases else "none"
        signals.append({
            "label": f"Urgency: {level.capitalize()}",
            "details": f"Phrases detected: {phrase_str}"
        })

        # NOTE: Social engineering signal
        se = analysis.get("social_engineering", {})
        tactics = se.get("tactics", [])
        se_details = se.get("details", "")
        if tactics:
            signals.append({
                "label": f"Social Engineering: {len(tactics)} tactic(s)",
                "details": f"{', '.join(tactics)} — {se_details}"
            })
        else:
            signals.append({
                "label": "Social Engineering: None",
                "details": "No manipulation tactics detected"
            })

        # NOTE: Classification signal — used by scoring engine for both
        # likelihood (deception sophistication) and impact (attack type)
        classification = analysis.get("classification", {})
        attack_type = classification.get("attack_type", "unknown")
        confidence = classification.get("confidence", 0)
        signals.append({
            "label": f"Classification: {attack_type.replace('_', ' ').title()}",
            "details": f"Confidence: {confidence}%"
        })

        # NOTE: Plain English summary for end user
        explanation = analysis.get("explanation", "")
        if explanation:
            signals.append({
                "label": "AI Summary",
                "details": explanation
            })

    except requests.exceptions.RequestException as e:
        error_msg = str(e).replace(GEMINI_API_KEY, "[REDACTED]") if GEMINI_API_KEY else str(e)
        signals.append({
            "label": "LLM Analysis Failed",
            "details": f"API request error: {error_msg}"
        })

    except (json.JSONDecodeError, KeyError) as e:
        signals.append({
            "label": "LLM Analysis Failed",
            "details": f"Failed to parse Gemini response: {str(e)}"
        })

    return {"signals": signals}
