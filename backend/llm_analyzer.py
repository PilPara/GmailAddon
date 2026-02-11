import os
import json
import requests

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"

SYSTEM_PROMPT = """You are an expert email security analyst. Your job is to analyze an email and determine if it is malicious, suspicious, or legitimate.

You will receive an email with a subject line and body. Analyze it thoroughly and return your assessment.

## Analysis Tasks

### 1. Urgency Language Detection
Look for language designed to pressure the recipient into acting quickly. This includes:
- Deadlines and time pressure ("within 24 hours", "immediately", "as soon as possible", "act now", "expires today", "limited time")
- Consequences for inaction ("account will be suspended", "you will lose access", "failure to respond will result in")
- Emotional pressure ("urgent", "critical", "important action required", "do not ignore")
- Artificial scarcity ("only available for", "one-time offer", "last chance")

Report which specific phrases trigger urgency and rate the overall urgency level as none, low, moderate, or high.

### 2. Social Engineering Tactics
Identify any manipulation techniques being used:
- Authority impersonation: claiming to be from a company, executive, IT department, bank, government
- Trust building: referencing a prior relationship, mutual contact, or shared context to lower defenses
- Reciprocity: offering something to create obligation
- Fear and intimidation: threatening consequences to force action
- Curiosity baiting: vague references designed to make the recipient click
- Pretexting: creating a fabricated scenario to justify the request
- Flattery: excessive compliments to lower guard

### 3. Attack Type Classification
Classify the email into one of the following categories:
- legitimate: Normal business or personal email with no malicious intent
- phishing: Attempting to steal credentials or personal information
- spear_phishing: Targeted phishing using personal details about the recipient
- bec: Business Email Compromise — impersonating a colleague or executive
- scam: Generic scam such as lottery, inheritance, romance, or advance-fee fraud
- malware_delivery: Primary goal is to get the recipient to open an attachment or click a link to install malware
- credential_harvesting: Focused on capturing usernames, passwords, MFA codes
- urgency_scam: Relies primarily on time pressure to trick the recipient

### 4. Confidence Score
Rate your confidence from 0 to 100:
- 0-20: Very uncertain
- 21-40: Slightly suspicious but likely legitimate
- 41-60: Moderately suspicious
- 61-80: Likely malicious
- 81-100: Almost certainly malicious

### 5. Explanation
Write a 2-3 sentence plain English summary. This will be shown to a non-technical end user.

## Important Guidelines
- Legitimate business emails sometimes contain urgency language. A recruiter saying "please schedule as soon as possible" is normal.
- Context matters. A scheduling link from a known recruitment platform is different from a random link asking you to verify your account.
- Not every email with an attachment or link is malicious. Assess the full picture.
- Be honest about uncertainty.
- Consider the sender, the context, the language, and the ask together.

## Response Format
Respond ONLY with a valid JSON object. No markdown, no backticks, no explanation outside the JSON:

{
  "urgency": {
    "level": "none|low|moderate|high",
    "phrases": ["phrase 1", "phrase 2"]
  },
  "social_engineering": {
    "tactics": ["tactic 1", "tactic 2"],
    "details": "brief explanation of tactics found"
  },
  "classification": {
    "attack_type": "legitimate|phishing|spear_phishing|bec|scam|malware_delivery|credential_harvesting|urgency_scam",
    "confidence": 0
  },
  "explanation": "2-3 sentence plain English summary"
}"""


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

        # Urgency signal
        urgency = analysis.get("urgency", {})
        level = urgency.get("level", "unknown")
        phrases = urgency.get("phrases", [])
        phrase_str = ", ".join(phrases) if phrases else "none"
        signals.append({
            "label": f"Urgency: {level.capitalize()}",
            "details": f"Phrases detected: {phrase_str}"
        })

        # Social engineering signal
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

        # Classification signal
        classification = analysis.get("classification", {})
        attack_type = classification.get("attack_type", "unknown")
        confidence = classification.get("confidence", 0)
        signals.append({
            "label": f"Classification: {attack_type.replace('_', ' ').title()}",
            "details": f"Confidence: {confidence}%"
        })

        # Explanation signal
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
