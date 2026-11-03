import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

import imapclient
from bs4 import BeautifulSoup

import config

CACHE_FILE = Path(__file__).parent / "scan_results.json"


def connect():
    if config.IMAP_USE_SSL:
        server = imapclient.IMAPClient(config.IMAP_HOST, port=config.IMAP_PORT, ssl=True)
    else:
        server = imapclient.IMAPClient(config.IMAP_HOST, port=config.IMAP_PORT, ssl=False)
        server.starttls()
    server.login(config.IMAP_USER, config.IMAP_PASSWORD)
    return server


def decode_header_value(value):
    if value is None:
        return ""
    decoded_parts = decode_header(value)
    parts = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            parts.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(part)
    return " ".join(parts)


def extract_unsubscribe_from_body(msg):
    body_html = ""
    body_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_html = payload.decode(charset, errors="replace")
            elif content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_text = payload.decode(charset, errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                body_html = content
            else:
                body_text = content

    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for link in soup.find_all("a", href=True):
            text = link.get_text().lower()
            href = link["href"].lower()
            if "unsubscribe" in text or "unsubscribe" in href:
                return True

    if body_text and re.search(r"unsubscribe", body_text, re.IGNORECASE):
        return True

    return False


def scan_mailbox(progress_callback=None):
    server = connect()
    results = defaultdict(lambda: {
        "sender_name": "",
        "sender_email": "",
        "count": 0,
        "first_seen": None,
        "last_seen": None,
        "subjects": [],
        "detection_method": set(),
    })

    try:
        server.select_folder("INBOX", readonly=True)
        since_date = datetime.now(timezone.utc) - timedelta(days=config.SCAN_DAYS)
        message_ids = server.search(["SINCE", since_date.date()])
        total = len(message_ids)

        if progress_callback:
            progress_callback(0, total, "Fetching headers...")

        batch_size = 100
        for i in range(0, total, batch_size):
            batch = message_ids[i:i + batch_size]
            fetched = server.fetch(batch, ["BODY.PEEK[HEADER]", "BODY.PEEK[TEXT]"])

            for msg_id, data in fetched.items():
                header_data = data.get(b"BODY[HEADER]", b"")
                msg = message_from_bytes(header_data)

                from_header = decode_header_value(msg.get("From", ""))
                sender_name, sender_email = parseaddr(from_header)
                sender_email = sender_email.lower().strip()

                if not sender_email:
                    continue

                date_str = msg.get("Date")
                try:
                    msg_date = parsedate_to_datetime(date_str) if date_str else None
                except Exception:
                    msg_date = None

                subject = decode_header_value(msg.get("Subject", ""))

                has_list_unsub = msg.get("List-Unsubscribe") is not None
                has_list_id = msg.get("List-Id") is not None

                entry = results[sender_email]
                entry["sender_name"] = sender_name or entry["sender_name"]
                entry["sender_email"] = sender_email
                entry["count"] += 1

                if msg_date:
                    date_iso = msg_date.isoformat()
                    if entry["first_seen"] is None or date_iso < entry["first_seen"]:
                        entry["first_seen"] = date_iso
                    if entry["last_seen"] is None or date_iso > entry["last_seen"]:
                        entry["last_seen"] = date_iso

                if subject and len(entry["subjects"]) < 3:
                    entry["subjects"].append(subject)

                if has_list_unsub:
                    entry["detection_method"].add("list-unsubscribe-header")
                if has_list_id:
                    entry["detection_method"].add("list-id-header")

                if not has_list_unsub and not has_list_id:
                    body_data = data.get(b"BODY[TEXT]", b"")
                    if body_data:
                        full_raw = header_data + b"\r\n" + body_data
                        full_msg = message_from_bytes(full_raw)
                        if extract_unsubscribe_from_body(full_msg):
                            entry["detection_method"].add("body-unsubscribe-link")

            if progress_callback:
                progress_callback(min(i + batch_size, total), total, "Scanning...")

    finally:
        server.logout()

    subscriptions = []
    for email_addr, info in results.items():
        if not info["detection_method"]:
            continue
        info["detection_method"] = list(info["detection_method"])
        subscriptions.append(info)

    subscriptions.sort(key=lambda s: s["last_seen"] or "", reverse=True)

    save_results(subscriptions)
    return subscriptions


def save_results(subscriptions):
    with open(CACHE_FILE, "w") as f:
        json.dump({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scan_days": config.SCAN_DAYS,
            "account": config.IMAP_USER,
            "subscriptions": subscriptions,
        }, f, indent=2)


def load_cached_results():
    if CACHE_FILE.exists():
        with open(CACHE_FILE) as f:
            return json.load(f)
    return None
