import re

# NOTE: Precompiled regex patterns for extracting auth results
SPF_PATTERN = re.compile(r'spf=(\w+)')
DKIM_PATTERN = re.compile(r'dkim=(\w+)')
DMARC_RESULT_PATTERN = re.compile(r'dmarc=(\w+)')

# NOTE: Extracts the domain owner's DMARC policy (none/quarantine/reject)
# This tells us what the domain owner wants done with failing emails
DMARC_POLICY_PATTERN = re.compile(r'dmarc=\w+\s*\(p=(\w+)')

def check_spf_signal(auth_results):
    spf = SPF_PATTERN.search(auth_results)
    spf_check_value = ""
    if spf:
        spf_check_value = spf.group(1)

    match spf_check_value:
        case "pass":
            signal = {"label": "SPF Passed", "details": "Sender server is authorized by domain"}
        case "fail":
            signal = {
                "label": "SPF Failed",
                "details": "The SPF record has designated the host as NOT being allowed to send"
            }
        case "softfail":
            signal = {
                "label": "SPF Soft Failed",
                "details": "The SPF record has designated the host as NOT being allowed to send but is in transition"
            }
        case "neutral":
            signal = {
                "label": "SPF Neutral",
                "details": "The SPF record specifies explicitly that nothing can be said about validity"
            }
        case "none":
            signal = {
                "label": "SPF None",
                "details": "No SPF record found for domain"
            }
        case "permerror":
            signal = {
                "label": "SPF PermError",
                "details": "SPF record badly formatted"
            }
        case "temperror":
            signal = {
                "label": "SPF TempError",
                "details": "Temporary SPF check error"
            }
        case _:
            signal = {
                "label": "SPF Unknown",
                "details": f"Unexpected SPF result {spf_check_value}"
            }

    return signal

def check_dkim_signal(auth_results):
    dkim = DKIM_PATTERN.search(auth_results)
    dkim_check_value = ""
    if dkim:
        dkim_check_value = dkim.group(1)

    match dkim_check_value:
        case "pass":
            signal = {
                "label": "DKIM Passed",
                "details": "Message signature verified successfully"
            }
        case "fail":
            signal = {
                "label": "DKIM Failed",
                "details": "Message signature failed verification"
            }
        case "none":
            signal = {
                "label": "DKIM None",
                "details": "Message was not signed"
            }
        case "policy":
            signal = {
                "label": "DKIM Policy",
                "details": "Signature not acceptable to receiving domain policy"
            }
        case "neutral":
            signal = {
                "label": "DKIM Neutral",
                "details": "Signature contained syntax errors or could not be processed"
            }
        case "temperror":
            signal = {
                "label": "DKIM TempError",
                "details": "Temporary error verifying signature, e.g. DNS timeout"
            }
        case "permerror":
            signal = {
                "label": "DKIM PermError",
                "details": "Permanent error verifying signature, e.g. missing header"
            }
        case _:
            signal = {
                "label": "DKIM Unknown",
                "details": f"Unexpected DKIM result: {dkim_check_value}"
            }

    return signal

def check_dmarc_signal(auth_results):
    dmarc = DMARC_RESULT_PATTERN.search(auth_results)
    dmarc_check_value = ""
    if dmarc:
        dmarc_check_value = dmarc.group(1)

    # NOTE: Extract DMARC policy (p=NONE/QUARANTINE/REJECT)
    # The policy indicates what the domain owner wants receivers to do with failing emails
    # REJECT is the strongest — domain owner explicitly says block unauthorized emails
    policy_match = DMARC_POLICY_PATTERN.search(auth_results)
    dmarc_policy = policy_match.group(1).upper() if policy_match else "UNKNOWN"

    match dmarc_check_value:
        case "pass":
            signal = {
                "label": "DMARC Passed",
                "details": f"DMARC policy ({dmarc_policy}) published and at least one authentication mechanism passed"
            }
        case "fail":
            signal = {
                "label": "DMARC Failed",
                "details": f"DMARC policy ({dmarc_policy}) published but no authentication mechanisms passed"
            }
        case "none":
            signal = {
                "label": "DMARC None",
                "details": "No DMARC policy record published for the domain"
            }
        case "temperror":
            signal = {
                "label": "DMARC TempError",
                "details": "Temporary error during DMARC evaluation"
            }
        case "permerror":
            signal = {
                "label": "DMARC PermError",
                "details": "Permanent error during DMARC evaluation, e.g. malformed record"
            }
        case _:
            signal = {
                "label": "DMARC Unknown",
                "details": f"Unexpected DMARC result: {dmarc_check_value}"
            }

    # NOTE: Attach policy to signal for scoring engine to use
    signal["policy"] = dmarc_policy

    return signal


def anaylze_auth(headers):
    auth_result = headers.get("authResults", "")
    spf_signal = check_spf_signal(auth_result)
    dkim_signal = check_dkim_signal(auth_result)
    dmarc_signal = check_dmarc_signal(auth_result)

    return {
        "signals": [spf_signal, dkim_signal, dmarc_signal]
    }
