import re

# SHORTENERS = [
#     "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
#     "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
#     "shorte.st", "tiny.cc", "bc.vc", "rb.gy", "cutt.ly"
# ]
#
# SUSPICIOUS_TLDS = [
#     ".tk", ".xyz", ".top", ".buzz", ".ml", ".ga", ".cf",
#     ".gq", ".work", ".click", ".loan", ".racing", ".win",
#     ".download", ".stream", ".bid", ".icu"
# ]


def extract_urls(body):
    return re.findall(r'https?://[^\s<>"\']+', body)


def is_ip_url(url):
    return bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))


# def is_shortener(url):
#     for shortener in SHORTENERS:
#         if shortener in url.lower():
#             return shortener
#     return None


# def has_suspicious_tld(url):
#     domain = re.search(r'https?://([^/]+)', url)
#     if domain:
#         domain = domain.group(1).lower()
#         for tld in SUSPICIOUS_TLDS:
#             if domain.endswith(tld):
#                 return tld
#     return None


def analyze_links(headers):
    signals = []
    body = headers.get("body", "")
    urls = extract_urls(body)

    if not urls:
        signals.append({
            "label": "No Links Found",
            "details": "Email body contains no URLs"
        })
        return {"signals": signals}

    ip_urls = []
    shortened = []
    suspicious = []

    for url in urls:
        if is_ip_url(url):
            ip_urls.append(url)

    #     shortener = is_shortener(url)
    #     if shortener:
    #         shortened.append({"url": url, "service": shortener})
    #
    #     tld = has_suspicious_tld(url)
    #     if tld:
    #         suspicious.append({"url": url, "tld": tld})
    #
    if ip_urls:
        signals.append({
            "label": "IP-Based URL Detected",
            "details": f"Found {len(ip_urls)} URL(s) using IP addresses: {', '.join(ip_urls)}"
        })

    # if shortened:
    #     labels = [f"{s['url']} ({s['service']})" for s in shortened]
    #     signals.append({
    #         "label": "URL Shortener Detected",
    #         "details": f"Found {len(shortened)} shortened URL(s): {', '.join(labels)}"
    #     })

    # if suspicious:
    #     labels = [f"{s['url']} ({s['tld']})" for s in suspicious]
    #     signals.append({
    #         "label": "Suspicious TLD Detected",
    #         "details": f"Found {len(suspicious)} URL(s) with suspicious TLDs: {', '.join(labels)}"
    #     })

    if len(urls) > 5:
        signals.append({
            "label": "High Link Count",
            "details": f"Email contains {len(urls)} links"
        })

    if not signals:
        signals.append({
            "label": "Links Clean",
            "details": f"Found {len(urls)} link(s), none flagged"
        })

    return {"signals": signals}
