import re
import tldextract


def get_root_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"


def extract_domain(email_string):
    match = re.search(r'<([^>]+)>', email_string)
    if match:
        email_string = match.group(1)
    parts = email_string.strip().split("@")
    if len(parts) == 2:
        return parts[1].lower()
    return ""


def analyze_domain(headers):
    signals = []
    return_path = headers.get("returnPath", "")
    from_header = headers.get("from", "")

    rp_domain = extract_domain(return_path)
    from_domain = extract_domain(from_header)

    if not rp_domain or not from_domain:
        signals.append({
            "label": "Domain Check Incomplete",
            "details": f"Missing header — Return-Path: '{rp_domain}', From: '{from_domain}'"
        })
    elif rp_domain == from_domain:
        signals.append({
            "label": "Domain Match",
            "details": f"Return-Path and From share the same domain: {from_domain}"
        })
    elif get_root_domain(rp_domain) == get_root_domain(from_domain):
        signals.append({
            "label": "Domain Subdomain Match",
            "details": f"Return-Path ({rp_domain}) and From ({from_domain}) share root domain: {get_root_domain(from_domain)}"
        })
    else:
        signals.append({
            "label": "Domain Mismatch",
            "details": f"Return-Path domain ({rp_domain}) does not match From domain ({from_domain}) — possible spoofing"
        })

    return {"signals": signals}
