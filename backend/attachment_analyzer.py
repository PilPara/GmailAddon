import re

# NOTE: File extensions that can execute code directly on the user's machine
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".ps1", ".vbs",
    ".js", ".msi", ".com", ".pif", ".hta", ".wsf"
}

# NOTE: Office file types that support macros — can run malicious code when opened
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

# NOTE: Regex to detect double extensions (e.g., "invoice.pdf.exe")
# Attackers use this to disguise executables as harmless files
DOUBLE_EXTENSION_PATTERN = re.compile(r'\.\w+\.\w+$')

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
        filename = attachment.get("filename", "")
        mime_type = attachment.get("mimeType", "")
        size = attachment.get("size", 0)
        filename_lower = filename.lower()

        signals.append({
            "label": "Attachment Found",
            "details": f"{filename} ({mime_type}, {size} bytes)"
        })

        # NOTE: Check for dangerous executable extensions
        for ext in DANGEROUS_EXTENSIONS:
            if filename_lower.endswith(ext):
                signals.append({
                    "label": "Dangerous File Type",
                    "details": f"{filename} has executable extension ({ext}) — can run code on your machine"
                })
                break

        # NOTE: Check for macro-enabled Office files
        for ext in MACRO_EXTENSIONS:
            if filename_lower.endswith(ext):
                signals.append({
                    "label": "Macro-Enabled File",
                    "details": f"{filename} is a macro-enabled Office file ({ext}) — macros can execute malicious code"
                })
                break

        # NOTE: Check for double extensions (e.g., report.pdf.exe)
        if DOUBLE_EXTENSION_PATTERN.search(filename_lower):
            # NOTE: Only flag if the real extension (last one) is dangerous
            real_ext = "." + filename_lower.rsplit(".", 1)[-1]
            if real_ext in DANGEROUS_EXTENSIONS or real_ext in MACRO_EXTENSIONS:
                signals.append({
                    "label": "Double Extension Detected",
                    "details": f"{filename} uses a double extension to disguise its true file type ({real_ext})"
                })

    return {"signals": signals}
