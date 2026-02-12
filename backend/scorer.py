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


def calculate_score(all_signals):
    """Main scoring function. Takes all signals, returns score and verdict."""
    auth_score = score_auth(all_signals)

    # TODO: add other likelihood factors
    # TODO: add impact factors
    # TODO: matrix lookup

    return {
        "score": 0,
        "likelihood": 0,
        "impact": 0,
        "severity": "Note",
        "debug": {
            "auth_score": auth_score
        }
    }
