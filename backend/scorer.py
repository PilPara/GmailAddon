import re

# NOTE: Scoring engine based on adapted OWASP Risk Rating Methodology
# Risk = Likelihood (0-10) x Impact (0-10) = 0-100
# Severity determined by matrix lookup, not raw score

# NOTE: Auth score thresholds for individual checks
AUTH_SCORES = {
    "spf": {
        "pass": 0, "temperror": 0,
        "neutral": 1, "none": 1, "permerror": 1,
        "softfail": 2,
        "fail": 3
    },
    "dkim": {
        "pass": 0, "temperror": 0,
        "neutral": 1, "none": 1, "policy": 1, "permerror": 1,
        "fail": 3
    },
    "dmarc": {
        "pass": 0, "temperror": 0,
        "none": 1, "permerror": 1,
        "fail": 2  # NOTE: base score — gets boosted by policy
    }
}

# NOTE: DMARC policy multipliers — stricter policy + failure = more suspicious
DMARC_POLICY_BOOST = {
    "NONE": 0,
    "QUARANTINE": 1,
    "REJECT": 2,
    "UNKNOWN": 0
}

# NOTE: Fixed scores for domain mismatch checks (0-9 scale)
# Domain mismatch is slightly more suspicious than Reply-To mismatch
# because it indicates the actual sending infrastructure differs from claimed sender
DOMAIN_MISMATCH_SCORE = 7
REPLY_TO_MISMATCH_SCORE = 6

# NOTE: Link threat scores (0-9 scale)
# IP URLs are most suspicious — no legitimate service uses raw IPs in emails
# Shorteners hide destination, suspicious TLDs are cheap throwaway domains
IP_URL_SCORE = 8
SHORTENER_SCORE = 5
SUSPICIOUS_TLD_SCORE = 6

# NOTE: LLM classification confidence is interpreted relative to classification
# "95% confident it's legitimate" = low threat (score 0)
# "85% confident it's phishing" = high threat (score 9)
CONFIDENCE_PATTERN = re.compile(r'Confidence:\s*(\d+)%')

# NOTE: Confidence thresholds for LLM scoring
# Used to bucket confidence percentages into threat levels
CONFIDENCE_HIGH = 80
CONFIDENCE_MEDIUM = 60
CONFIDENCE_LOW = 40

# NOTE: LLM threat scores when classified as legitimate
# Higher confidence in "legitimate" = lower threat score
LEGITIMATE_HIGH_CONFIDENCE_SCORE = 0
LEGITIMATE_MEDIUM_CONFIDENCE_SCORE = 3
LEGITIMATE_LOW_CONFIDENCE_SCORE = 5
LEGITIMATE_UNCERTAIN_SCORE = 7

# NOTE: LLM threat scores when classified as malicious
# Higher confidence in malicious classification = higher threat score
MALICIOUS_HIGH_CONFIDENCE_SCORE = 9
MALICIOUS_MEDIUM_CONFIDENCE_SCORE = 7
MALICIOUS_LOW_CONFIDENCE_SCORE = 5
MALICIOUS_UNCERTAIN_SCORE = 3

# NOTE: Max score cap for individual factors
MAX_FACTOR_SCORE = 9
# NOTE: Max combined auth score (SPF + DKIM + DMARC)
MAX_AUTH_SCORE = 9
# NOTE: Max individual auth check score
MAX_AUTH_CHECK_SCORE = 3

# NOTE: Data compromise scores by attack type (0-9 scale)
# Credential harvesting and dangerous attachments pose highest data compromise risk
# BEC/data theft target sensitive info, social engineering is broader, spam is lowest
DATA_COMPROMISE_BY_ATTACK = {
    "credential_harvesting": 9,
    "phishing": 7,
    "spear_phishing": 8,
    "bec": 7,
    "malware_delivery": 6,
    "data_theft": 7,
    "urgency_scam": 5,
    "scam": 4,
    "spam": 2,
    "legitimate": 0,
    "unknown": 3
}

# NOTE: Score applied when a dangerous executable attachment is present
# Overrides attack-type score if higher — executables can do anything
DANGEROUS_ATTACHMENT_DATA_COMPROMISE_SCORE = 9

# NOTE: Score applied when a macro-enabled Office file is present
# Slightly lower than raw executables — requires user to enable macros
MACRO_ATTACHMENT_DATA_COMPROMISE_SCORE = 8

# NOTE: Loss of availability scores by attack type (0-9 scale)
# Dangerous attachments score highest — ransomware risk
# Credential harvesting allows account lockout
# Most other attack types have low availability impact
AVAILABILITY_BY_ATTACK = {
    "credential_harvesting": 5,
    "phishing": 3,
    "spear_phishing": 3,
    "bec": 2,
    "malware_delivery": 4,
    "data_theft": 2,
    "urgency_scam": 1,
    "scam": 1,
    "spam": 0,
    "legitimate": 0,
    "unknown": 2
}

# NOTE: Availability score when dangerous executable attachment is present
# Ransomware is the primary risk — can lock out entire systems
DANGEROUS_ATTACHMENT_AVAILABILITY_SCORE = 9

# NOTE: Availability score when macro-enabled attachment is present
MACRO_ATTACHMENT_AVAILABILITY_SCORE = 7

def score_auth(signals):
    """Score authentication signals. Returns 0-9."""
    spf_score = 0
    dkim_score = 0
    dmarc_score = 0
    dmarc_policy = "UNKNOWN"

    for signal in signals:
        label = signal.get("label", "").lower()

        if label.startswith("spf"):
            result = label.split(" ")[-1]  # NOTE: e.g., "spf passed" -> "passed"

            # NOTE: Map label back to auth result key
            result_key = "pass" if result == "passed" else result.replace("failed", "fail")
            spf_score = AUTH_SCORES["spf"].get(result_key, 0)

        elif label.startswith("dkim"):
            result = label.split(" ")[-1]
            result_key = "pass" if result == "passed" else result.replace("failed", "fail")
            dkim_score = AUTH_SCORES["dkim"].get(result_key, 0)

        elif label.startswith("dmarc"):
            result = label.split(" ")[-1]
            result_key = "pass" if result == "passed" else result.replace("failed", "fail")
            dmarc_score = AUTH_SCORES["dmarc"].get(result_key, 0)
            dmarc_policy = signal.get("policy", "UNKNOWN")

    # NOTE: Boost DMARC score based on policy if it failed
    if dmarc_score > 0:
        dmarc_score += DMARC_POLICY_BOOST.get(dmarc_policy, 0)

    # NOTE: Cap individual scores at 3
    dmarc_score = min(dmarc_score, 3)

    total = spf_score + dkim_score + dmarc_score
    return min(total, 9)

def score_domain(signals):
    """Score domain mismatch signals. Returs 0-9"""
    score = 0

    for signal in signals:
        label = signal.get("label", "")

        if label == "Domain Mismatch":
            score = DOMAIN_MISMATCH_SCORE

        if label == "Reply-To Mismatch":
            score = max(score, REPLY_TO_MISMATCH_SCORE)

    return min(score, 9)

def score_links(signals):
    """Score link-related signals. Returns 0-9."""
    score = 0

    for signal in signals:
        label = signal.get("label", "")

        if label == "IP-Based URL Detected":
            score = max(score, IP_URL_SCORE)

        elif label == "Suspicious TLD Detected":
            score = max(score, SUSPICIOUS_TLD_SCORE)

        elif label == "URL Shortener Detected":
            score = max(score, SHORTENER_SCORE)

    return min(score, 9)

def score_llm(signals):
    """Score LLM deception sophistication. Returns 0-9.
    Combines attack type classification with confidence level."""
    attack_type = "unknown"
    confidence = 0

    for signal in signals:
        label = signal.get("label", "")
        details = signal.get("details", "")

        if label.startswith("Classification:"):
            # NOTE: Extract attack type from label (e.g., "Classification: Phishing" -> "phishing")
            attack_type = label.split(": ", 1)[1].lower().replace(" ", "_")

            # NOTE: Extract confidence from details (e.g., "Confidence: 85%" -> 85)
            match = CONFIDENCE_PATTERN.search(details)
            if match:
                confidence = int(match.group(1))

    # NOTE: If classified as legitimate, score is inverse of confidence
    if attack_type == "legitimate":
        if confidence >= CONFIDENCE_HIGH:
            return LEGITIMATE_HIGH_CONFIDENCE_SCORE
        elif confidence >= CONFIDENCE_MEDIUM:
            return LEGITIMATE_MEDIUM_CONFIDENCE_SCORE
        elif confidence >= CONFIDENCE_LOW:
            return LEGITIMATE_LOW_CONFIDENCE_SCORE
        else:
            return LEGITIMATE_UNCERTAIN_SCORE

    # NOTE: If classified as malicious, score scales with confidence
    if confidence >= CONFIDENCE_HIGH:
        return MALICIOUS_HIGH_CONFIDENCE_SCORE
    elif confidence >= CONFIDENCE_MEDIUM:
        return MALICIOUS_MEDIUM_CONFIDENCE_SCORE
    elif confidence >= CONFIDENCE_LOW:
        return MALICIOUS_LOW_CONFIDENCE_SCORE
    else:
        return MALICIOUS_UNCERTAIN_SCORE

def extract_attack_type(signals):
    # NOTE: Extract LLM attack type classification from signals
    for signal in signals:
        label = signal.get("label", "")
        if label.startswith("Classification:"):
            return label.split(": ", 1)[1].lower().replace(" ", "_")
    return "unknown"

def has_dangerous_attachment(signals):
    # NOTE: Check if any signal indicates a dangerous executable attachment
    for signal in signals:
        if signal.get("label") == "Dangerous File Type":
            return True
    return False

def has_macro_attachment(signals):
    # NOTE: Check if any signal indicates a macro-enabled attachment
    for signal in signals:
        if signal.get("label") == "Macro-Enabled File":
            return True
    return False

def score_impact(signals):
    # NOTE: Score impact based on attack type and attachment signals
    # Returns dict with data_compromise (0-9) and availability (0-9)
    attack_type = extract_attack_type(signals)
    has_dangerous = has_dangerous_attachment(signals)
    has_macro = has_macro_attachment(signals)

    # NOTE: Start with attack-type base scores
    data_compromise = DATA_COMPROMISE_BY_ATTACK.get(attack_type, DATA_COMPROMISE_BY_ATTACK["unknown"])
    availability = AVAILABILITY_BY_ATTACK.get(attack_type, AVAILABILITY_BY_ATTACK["unknown"])

    # NOTE: Dangerous attachments override if higher — executables can do anything
    if has_dangerous:
        data_compromise = max(data_compromise, DANGEROUS_ATTACHMENT_DATA_COMPROMISE_SCORE)
        availability = max(availability, DANGEROUS_ATTACHMENT_AVAILABILITY_SCORE)

    # NOTE: Macro-enabled files override if higher — require user action but still dangerous
    if has_macro:
        data_compromise = max(data_compromise, MACRO_ATTACHMENT_DATA_COMPROMISE_SCORE)
        availability = max(availability, MACRO_ATTACHMENT_AVAILABILITY_SCORE)

    return {
        "data_compromise": min(data_compromise, MAX_FACTOR_SCORE),
        "availability": min(availability, MAX_FACTOR_SCORE)
    }

def calculate_score(all_signals):
    """Main scoring function. Takes all signals, returns score and verdict."""
    auth_score = score_auth(all_signals)
    domain_score = score_domain(all_signals)
    link_score = score_links(all_signals)
    llm_score = score_llm(all_signals)
    impact_score = score_impact(all_signals)

    # TODO: add other likelihood factors
    # TODO: add impact factors
    # TODO: matrix lookup

    return {
        "score": 0,
        "likelihood": 0,
        "impact": 0,
        "severity": "Note",
        "debug": {
            "auth_score": auth_score,
            "domain_score": domain_score,
            "link_score": link_score,
            "llm_score": llm_score,
            "impact_score": impact_score
        }
    }
