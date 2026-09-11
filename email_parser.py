import email
import re
from email import policy
from email.parser import BytesParser


def extract_urls(text):
    url_pattern = r"https?://[^\s\"'<>]+|www\.[^\s\"'<>]+"
    return list(set(re.findall(url_pattern, text, re.IGNORECASE)))


def extract_ips(text:str):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(pattern, text or "")
    seen = set()
    result = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def get_email_body(message):
    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type in ["text/plain", "text/html"] and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(
                            payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                        )
                except Exception:
                    pass
    else:
        try:
            payload = message.get_payload(decode=True)
            if payload:
                body_parts.append(
                    payload.decode(message.get_content_charset() or "utf-8", errors="ignore")
                )
        except Exception:
            pass

    return "\n".join(body_parts)


def get_attachments(message):
    attachments = []

    for part in message.walk():
        content_disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in content_disposition.lower():
            filename = part.get_filename()

            attachments.append({
                "filename": filename or "unknown_attachment",
                "content_type": part.get_content_type()
            })

    return attachments


def parse_eml_file(file_path):
    with open(file_path, "rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    body = get_email_body(message)

    received_headers = message.get_all("Received", [])
    authentication_results = message.get_all("Authentication-Results", [])

    return {
        "from": str(message.get("From", "Not available")),
        "to": str(message.get("To", "Not available")),
        "subject": str(message.get("Subject", "No subject")),
        "date": str(message.get("Date", "Not available")),
        "reply_to": str(message.get("Reply-To", "Not available")),
        "return_path": str(message.get("Return-Path", "Not available")),
        "message_id": str(message.get("Message-ID", "Not available")),
        "body_preview": body[:2500],
        "urls": extract_urls(body),
        "ips_found": extract_ips("\n".join(received_headers)),
        "received_headers": received_headers,
        "authentication_results": authentication_results,
        "attachments": get_attachments(message)
    }
