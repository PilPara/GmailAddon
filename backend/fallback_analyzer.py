import re

# NOTE: Regex-based fallback when LLM is unavailable
# Catches obvious phishing signals from email subject and body

# NOTE: Phrases that pressure the recipient into acting quickly
URGENCY_PATTERNS = [
    re.compile(r'within \d+ hours?', re.IGNORECASE),
    re.compile(r'immediately', re.IGNORECASE),
    re.compile(r'act now', re.IGNORECASE),
    re.compile(r'urgent', re.IGNORECASE),
    re.compile(r'expires? today', re.IGNORECASE),
    re.compile(r'limited time', re.IGNORECASE),
    re.compile(r'as soon as possible', re.IGNORECASE),
    re.compile(r'final notice', re.IGNORECASE),
    re.compile(r'last chance', re.IGNORECASE),
    re.compile(r'right away', re.IGNORECASE),
]

# NOTE: Phrases that threaten consequences to force action
THREAT_PATTERNS = [
    re.compile(r'account.{0,20}(suspend|lock|terminat|delet|clos|restrict|deactivat)', re.IGNORECASE),
    re.compile(r'permanently (lock|delet|suspend|block)', re.IGNORECASE),
    re.compile(r'will be (lock|delet|suspend|block|terminat)', re.IGNORECASE),
    re.compile(r'failure to (respond|verify|confirm|comply)', re.IGNORECASE),
    re.compile(r'lose access', re.IGNORECASE),
    re.compile(r'no further warnings?', re.IGNORECASE),
]

# NOTE: Phrases requesting sensitive information directly
CREDENTIAL_PATTERNS = [
    re.compile(r'verify your (identity|account|email|credentials)', re.IGNORECASE),
    re.compile(r'confirm your (identity|account|email|password)', re.IGNORECASE),
    re.compile(r'(enter|provide|send|reply with).{0,30}(password|credentials|SSN|social security|credit card|bank account|phone number)', re.IGNORECASE),
    re.compile(r'click.{0,20}(link|here|below).{0,20}(verify|confirm|secure|update)', re.IGNORECASE),
    re.compile(r'log\s*in.{0,20}(verify|confirm|secure|update)', re.IGNORECASE),
]

# NOTE: Impersonating authority figures or organizations
AUTHORITY_PATTERNS = [
    re.compile(r'(security|support|admin|helpdesk|IT) (team|department|division)', re.IGNORECASE),
    re.compile(r'(Google|Microsoft|Apple|Amazon|PayPal|Netflix|Bank).{0,20}(security|support|team|service)', re.IGNORECASE),
    re.compile(r'(we have detected|we noticed|our system detected|unusual.{0,15}activity)', re.IGNORECASE),
]

# NOTE: Minimum number of pattern matches to trigger each signal
URGENCY_THRESHOLD = 1
THREAT_THRESHOLD = 1
CREDENTIAL_THRESHOLD = 1
AUTHORITY_THRESHOLD = 1

# NOTE: Fallback classification confidence when multiple categories match
FALLBACK_HIGH_CONFIDENCE = 75
FALLBACK_MEDIUM_CONFIDENCE = 55
FALLBACK_LOW_CONFIDENCE = 35


def analyze_fallback(headers):
    # NOTE: Regex-based content analysis as fallback when LLM is unavailable
    signals = []
    subject = headers.get("subject", "")
    body = headers.get("body", "")
    text = subject + " " + body

    urgency_matches = []
    for pattern in URGENCY_PATTERNS:
        match = pattern.search(text)
        if match:
            urgency_matches.append(match.group(0))

    threat_matches = []
    for pattern in THREAT_PATTERNS:
        match = pattern.search(text)
        if match:
            threat_matches.append(match.group(0))

    credential_matches = []
    for pattern in CREDENTIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            credential_matches.append(match.group(0))

    authority_matches = []
    for pattern in AUTHORITY_PATTERNS:
        match = pattern.search(text)
        if match:
            authority_matches.append(match.group(0))

    # NOTE: Count how many categories triggered
    categories_hit = 0

    if len(urgency_matches) >= URGENCY_THRESHOLD:
        categories_hit += 1
        signals.append({
            "label": "Urgency: High",
            "details": f"Urgency phrases detected: {', '.join(urgency_matches)}",
            "user_details": "This email uses language designed to pressure you into acting quickly"
        })

    if len(threat_matches) >= THREAT_THRESHOLD:
        categories_hit += 1
        signals.append({
            "label": "Threat Detected",
            "details": f"Threat phrases detected: {', '.join(threat_matches)}",
            "user_details": "This email threatens negative consequences if you don't act"
        })

    if len(credential_matches) >= CREDENTIAL_THRESHOLD:
        categories_hit += 1
        signals.append({
            "label": "Credential Request Detected",
            "details": f"Credential request phrases detected: {', '.join(credential_matches)}",
            "user_details": "This email is asking for personal information or login credentials"
        })

    if len(authority_matches) >= AUTHORITY_THRESHOLD:
        categories_hit += 1
        signals.append({
            "label": "Authority Impersonation Detected",
            "details": f"Authority impersonation phrases detected: {', '.join(authority_matches)}",
            "user_details": "This email claims to be from an official team or organization"
        })

    # NOTE: Generate classification based on how many categories matched
    if categories_hit >= 3:
        confidence = FALLBACK_HIGH_CONFIDENCE
        attack_type = "phishing"
    elif categories_hit >= 2:
        confidence = FALLBACK_MEDIUM_CONFIDENCE
        attack_type = "phishing"
    elif categories_hit >= 1:
        confidence = FALLBACK_LOW_CONFIDENCE
        attack_type = "phishing"
    else:
        return {"signals": signals}

    signals.append({
        "label": f"Classification: {attack_type.replace('_', ' ').title()}",
        "details": f"Confidence: {confidence}% (pattern-based fallback)",
        "user_details": f"Pattern analysis suggests this is a phishing attempt ({confidence}% confidence)"
    })

    return {"signals": signals}
