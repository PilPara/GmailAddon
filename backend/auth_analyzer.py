# Authentication-Results: mx.google.com;
#        dkim=pass header.i=@comeet-notifications.com header.s=pic header.b=RfhSqodq;
#        dkim=pass header.i=@mailgun.org header.s=mg header.b=lInAAXux;
#        spf=pass (google.com: domain of bounce+b96971.61a741-avidaniv12=gmail.com@comeet-notifications.com designates 159.135.229.156 as permitted sender) smtp.mailfrom="bounce+b96971.61a741-Avidaniv12=gmail.com@comeet-notifications.com";
#        dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=upwind.comeet-notifications.com

import re

def check_spf_signal(auth_results):
    spf = re.search(r'spf=(\w+)', auth_results)
    full_match = ""
    spf_check_value  = ""
    if spf:
        full_match = spf.group(0)
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
                    "label": "SPF Uknown",
                    "details": f"Unexpected SPF result {spf_check_value}"
            }

    return signal

def check_dkim_signal(auth_results):
    dkim = re.search(r'dkim=(\w+)', auth_results)
    dkim_check_value = ""
    if dkim:
        full_match = dkim.group(0)
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
    dmarc = re.search(r'dmarc=(\w+)', auth_results)
    dmarc_check_value = ""
    if dmarc:
        full_match = dmarc.group(0)
        dmarc_check_value = dmarc.group(1)

    match dmarc_check_value:
        case "pass":
            signal = {
                "label": "DMARC Passed",
                "details": "DMARC policy published and at least one authentication mechanism passed"
            }

        case "fail":
            signal = {
                "label": "DMARC Failed",
                "details": "DMARC policy published but no authentication mechanisms passed"
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

    return signal


def anaylze_auth(headers):
    auth_result = headers.get("authResults", "")
    spf_signal = check_spf_signal(auth_result)
    dkim_signal = check_dkim_signal(auth_result)
    dmarc_signal = check_dmarc_signal(auth_result)

    return {
        "signals": [spf_signal, dkim_signal, dmarc_signal]
    }



