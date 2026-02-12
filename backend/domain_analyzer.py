import re
import tldextract

# NOTE: Precompiled regex for extracting email from angle brackets (e.g., "Name <user@domain.com>")
EMAIL_BRACKET_PATTERN = re.compile(r'<([^>]+)>')

def get_root_domain(domain):
    """Extract the root domain (e.g., 'google.com' from 'mail.google.com')"""
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def extract_domain(email_string):
    """Extract domain from an email address string, handling '<user@domain>' format"""
    match = EMAIL_BRACKET_PATTERN.search(email_string)
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
    reply_to = headers.get("replyTo", "")

    rp_domain = extract_domain(return_path)
    from_domain = extract_domain(from_header)

    # NOTE: Return-Path vs From domain comparison
    # Mismatch indicates possible spoofing — sender may be hiding real origin
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

    # NOTE: Reply-To vs From comparison
    # A different Reply-To domain is a BEC indicator —
    # email looks like it's from a trusted sender but replies go to the attacker
    if reply_to:
        reply_to_domain = extract_domain(reply_to)
        if reply_to_domain and reply_to_domain != from_domain:
            if get_root_domain(reply_to_domain) != get_root_domain(from_domain):
                signals.append({
                    "label": "Reply-To Mismatch",
                    "details": f"Reply-To ({reply_to_domain}) does not match From ({from_domain}) — replies go to a different domain"
                })
            else:
                signals.append({
                    "label": "Reply-To Subdomain Match",
                    "details": f"Reply-To ({reply_to_domain}) and From ({from_domain}) share root domain"
                })
        else:
            signals.append({
                "label": "Reply-To Match",
                "details": f"Reply-To matches From domain: {from_domain}"
            })

    return {"signals": signals}
