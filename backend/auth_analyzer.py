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
            signal = {"label": "SPF Passed", "details": "Sender server is authorized by domain",
                      "user_details": "The sending server is allowed to send on behalf of this domain ✓"}
        case "fail":
            signal = {
                "label": "SPF Failed",
                "details": "The SPF record has designated the host as NOT being allowed to send",
                "user_details": "The sending server is NOT authorized to send for this domain ✗"
            }
        case "softfail":
            signal = {
                "label": "SPF Soft Failed",
                "details": "The SPF record has designated the host as NOT being allowed to send but is in transition",
                "user_details": "The sending server may not be authorized — the domain's policy is still being set up"
            }
        case "neutral":
            signal = {
                "label": "SPF Neutral",
                "details": "The SPF record specifies explicitly that nothing can be said about validity",
                "user_details": "The domain doesn't confirm or deny this server is allowed to send"
            }
        case "none":
            signal = {
                "label": "SPF None",
                "details": "No SPF record found for domain",
                "user_details": "The sender's domain has no verification policy set up"
            }
        case "permerror":
            signal = {
                "label": "SPF PermError",
                "details": "SPF record badly formatted",
                "user_details": "The sender's verification record has errors — could not be checked"
            }
        case "temperror":
            signal = {
                "label": "SPF TempError",
                "details": "Temporary SPF check error",
                "user_details": "Temporary issue checking sender verification — try again later"
            }
        case _:
            signal = {
                "label": "SPF Unknown",
                "details": f"Unexpected SPF result {spf_check_value}",
                "user_details": "Sender verification returned an unexpected result"
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
                "details": "Message signature verified successfully",
                "user_details": "The email content hasn't been tampered with in transit ✓"
            }
        case "fail":
            signal = {
                "label": "DKIM Failed",
                "details": "Message signature failed verification",
                "user_details": "The email content may have been altered after it was sent ✗"
            }
        case "none":
            signal = {
                "label": "DKIM None",
                "details": "Message was not signed",
                "user_details": "The email was not digitally signed — its contents can't be verified"
            }
        case "policy":
            signal = {
                "label": "DKIM Policy",
                "details": "Signature not acceptable to receiving domain policy",
                "user_details": "The email's digital signature doesn't meet your domain's requirements"
            }
        case "neutral":
            signal = {
                "label": "DKIM Neutral",
                "details": "Signature contained syntax errors or could not be processed",
                "user_details": "The email's digital signature couldn't be fully verified"
            }
        case "temperror":
            signal = {
                "label": "DKIM TempError",
                "details": "Temporary error verifying signature, e.g. DNS timeout",
                "user_details": "Temporary issue verifying email signature — try again later"
            }
        case "permerror":
            signal = {
                "label": "DKIM PermError",
                "details": "Permanent error verifying signature, e.g. missing header",
                "user_details": "The email's digital signature is broken and can't be verified"
            }
        case _:
            signal = {
                "label": "DKIM Unknown",
                "details": f"Unexpected DKIM result: {dkim_check_value}",
                "user_details": "Email signature check returned an unexpected result"
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
                "details": f"DMARC policy ({dmarc_policy}) published and at least one authentication mechanism passed",
                "user_details": "The sender's domain has a protection policy and this email passed it ✓"
            }
        case "fail":
            signal = {
                "label": "DMARC Failed",
                "details": f"DMARC policy ({dmarc_policy}) published but no authentication mechanisms passed",
                "user_details": "This email failed the sender's own domain protection policy ✗"
            }
        case "none":
            signal = {
                "label": "DMARC None",
                "details": "No DMARC policy record published for the domain",
                "user_details": "The sender's domain has no protection policy — anyone could send as them"
            }
        case "temperror":
            signal = {
                "label": "DMARC TempError",
                "details": "Temporary error during DMARC evaluation",
                "user_details": "Temporary issue checking domain protection policy — try again later"
            }
        case "permerror":
            signal = {
                "label": "DMARC PermError",
                "details": "Permanent error during DMARC evaluation, e.g. malformed record",
                "user_details": "The sender's domain protection policy is broken and can't be checked"
            }
        case _:
            signal = {
                "label": "DMARC Unknown",
                "details": f"Unexpected DMARC result: {dmarc_check_value}",
                "user_details": "Domain protection check returned an unexpected result"
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
