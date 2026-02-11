def analyze_attachments(headers):
    signals = []
    attachments = headers.get("attachments", [])

    if not attachments:
        signals.append({
            "label": "No Attachments",
            "details": "Email has no attachments"
        })
        return {"signals": signals}

    for attachment in attachments:
        signals.append({
            "label": "Attachment Found",
            "details": f"{attachment.get('filename')} ({attachment.get('mimeType')}, {attachment.get('size')} bytes)"
        })

    return {"signals": signals}
