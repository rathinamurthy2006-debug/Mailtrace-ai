import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "urgent",
    "immediately",
    "verify",
    "verification",
    "password",
    "login",
    "bank details",
    "account suspended",
    "payment failed",
    "click here",
    "limited time",
    "confirm your account",
    "update your details",
    "gift card",
    "wire transfer",
    "invoice attached"
]

SUSPICIOUS_FILE_TYPES = [
    ".exe",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".scr",
    ".zip",
    ".rar",
    ".iso"
]

KNOWN_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "bankofamerica", "chase", "wellsfargo",
    "dhl", "fedex", "linkedin", "dropbox"
]


def levenshtein_distance(a, b):
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_lookalike_domain(domain):
    if not domain:
        return None

    first_label = domain.split(".")[0].lower()
    chunks = re.split(r"[-_.]", first_label)
    chunks.append(first_label)

    for brand in KNOWN_BRANDS:
        for chunk in chunks:
            if not chunk or chunk == brand:
                continue

            distance = levenshtein_distance(chunk, brand)

            if 0 < distance <= 2 and len(chunk) >= len(brand) - 2:
                return brand

    return None


def get_domain(email_address):
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", email_address)

    if match:
        return match.group(1).lower()

    return ""


def calculate_risk(email_data):
    score = 0
    reasons = []
    body = email_data.get("body_preview", "").lower()
    subject = email_data.get("subject", "").lower()
    full_text = f"{subject} {body}"

    sender_domain = get_domain(email_data.get("from", ""))
    reply_domain = get_domain(email_data.get("reply_to", ""))

    # Suspicious language
    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in full_text:
            found_words.append(word)

    if len(found_words) >= 3:
        score += 20
        reasons.append(f"Multiple phishing/social-engineering keywords detected: {', '.join(found_words[:5])}")

    elif len(found_words) > 0:
        score += 10
        reasons.append(f"Suspicious language detected: {', '.join(found_words[:5])}")

    # Sender vs reply-to mismatch
    if sender_domain and reply_domain and sender_domain != reply_domain:
        score += 15
        reasons.append("Sender domain and Reply-To domain do not match")

    # NLP-based lookalike/typosquatted brand domain detection
    lookalike_match = detect_lookalike_domain(sender_domain)

    if lookalike_match:
        score += 25
        reasons.append(
            f"Sender domain '{sender_domain}' closely resembles known brand '{lookalike_match}' (possible typosquatting)"
        )

    # URLs
    urls = email_data.get("urls", [])

    if urls:
        score += 10
        reasons.append(f"{len(urls)} URL(s) found in email content")

        suspicious_url_words = ["login", "verify", "secure", "account", "update", "bank"]

        for url in urls:
            parsed_url = urlparse(url)
            url_text = f"{parsed_url.netloc}{parsed_url.path}".lower()

            if any(word in url_text for word in suspicious_url_words):
                score += 15
                reasons.append(f"Suspicious URL pattern detected: {url}")
                break

    # Authentication results
    auth_results = " ".join(email_data.get("authentication_results", [])).lower()

    if "spf=fail" in auth_results:
        score += 20
        reasons.append("SPF authentication failed")

    if "dkim=fail" in auth_results:
        score += 20
        reasons.append("DKIM signature validation failed")

    if "dmarc=fail" in auth_results:
        score += 20
        reasons.append("DMARC alignment validation failed")

    # Attachments
    for attachment in email_data.get("attachments", []):
        filename = attachment.get("filename", "").lower()

        if any(filename.endswith(extension) for extension in SUSPICIOUS_FILE_TYPES):
            score += 20
            reasons.append(f"Potentially dangerous attachment found: {filename}")

    # Cap risk score
    score = min(score, 100)

    if score >= 75:
        category = "Phishing / High-Risk Email"
        confidence = "High"
        action = "Quarantine the email and open an investigation case."

    elif score >= 40:
        category = "Suspicious Email"
        confidence = "Medium"
        action = "Do not click links or open attachments. Verify sender independently."

    else:
        category = "Low-Risk / Requires Review"
        confidence = "Low"
        action = "No immediate action required, but validate if the sender is unknown."

    if not reasons:
        reasons.append("No major high-risk indicators were found by the current rule engine.")

    return {
        "risk_score": score,
        "threat_category": category,
        "confidence": confidence,
        "recommended_action": action,
        "reasons": reasons
    }
