import imaplib
import json
import re
import ssl
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from bs4 import BeautifulSoup

import config

CACHE_FILE = Path(__file__).parent / "scan_results.json"


def connect():
    ctx = ssl.create_default_context()
    if not config.IMAP_VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if config.IMAP_USE_SSL:
        server = imaplib.IMAP4_SSL(config.IMAP_HOST, port=config.IMAP_PORT, ssl_context=ctx)
    else:
        server = imaplib.IMAP4(config.IMAP_HOST, port=config.IMAP_PORT)
        server.starttls(ssl_context=ctx)
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


SUBSCRIPTION_SUBJECT_PATTERNS = re.compile(
    r"(subscription\s+(renew|cancel|expir|confirm|status|will))"
    r"|(membership\s+(renew|expir|cancel|confirm|auto))"
    r"|(auto.?renew)"
    r"|(is\s+renewing)"
    r"|(will\s+renew)"
    r"|(about\s+to\s+renew)"
    r"|(has\s+been\s+renewed)"
    r"|(free\s+trial\s+(end|expir))"
    r"|(your\s+receipt\s+from\s+)"
    r"|(receipt\s+from\s+\S+\s+(for\s+)?\$)"
    r"|(your\s+invoice\s+(from|for|is))"
    r"|(invoice\s+is\s+attached)"
    r"|(billing\s+statement)"
    r"|(your\s+\S+\s+subscription)"
    r"|(purchasing\s+a\s+subscription)"
    r"|(plan\s+is\s+renewing)"
    r"|(line\s+is\s+about\s+to\s+renew)",
    re.IGNORECASE,
)

FOOTER_MARKERS = re.compile(
    r"(unsubscribe|email\s+preferences|privacy\s+policy|opt.?out"
    r"|update\s+your\s+preferences|manage\s+your\s+(email|preferences|subscription|communication)"
    r"|you\s+(are\s+)?receiv(ed|ing)\s+this\s+(email|message|because)"
    r"|no\s+longer\s+wish\s+to\s+receive"
    r"|sent\s+(to|by)\s+\S+@)",
    re.IGNORECASE,
)


def get_body_text(msg):
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
        body_text = soup.get_text(separator=" ", strip=True)

    return strip_footer(body_text)


def strip_footer(text):
    if not text:
        return text
    match = FOOTER_MARKERS.search(text)
    if match:
        return text[:match.start()]
    return text


IGNORE_SUBJECT_PATTERNS = re.compile(
    r"(subscribe\s+&\s+save)"
    r"|(subscription\s+cancelled)"
    r"|(price\s+alert)"
    r"|(charge\s+your\s+)"
    r"|(battery\s+now)"
    r"|(order\s+(confirm|deliver))"
    r"|(shipping|shipment|tracking)"
    r"|(verify|verification\s+code)"
    r"|(welcome\s+to)"
    r"|(transmission\s*\|)"
    r"|(autopay\s+was\s+processed)",
    re.IGNORECASE,
)


def detect_paid_signals(subject):
    if IGNORE_SUBJECT_PATTERNS.search(subject):
        return set()
    if SUBSCRIPTION_SUBJECT_PATTERNS.search(subject):
        return {"subscription-subject"}
    return set()


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
        server.select("INBOX", readonly=True)
        since_date = datetime.now(timezone.utc) - timedelta(days=config.SCAN_DAYS)
        date_str = since_date.strftime("%d-%b-%Y")
        _status, data = server.search(None, f'(SINCE {date_str})')
        message_ids = data[0].split() if data[0] else []
        total = len(message_ids)

        if progress_callback:
            progress_callback(0, total, "Fetching emails...")

        batch_size = 50
        for i in range(0, total, batch_size):
            batch = message_ids[i:i + batch_size]
            batch_str = b",".join(batch).decode()

            _status, header_data = server.fetch(batch_str, "(BODY.PEEK[HEADER])")

            headers_by_id = {}
            for j in range(0, len(header_data), 2):
                if header_data[j] is None:
                    continue
                if isinstance(header_data[j], tuple):
                    meta, payload = header_data[j]
                    msg_num = meta.split()[0]
                    headers_by_id[msg_num] = payload

            for msg_num, raw_header in headers_by_id.items():
                msg = message_from_bytes(raw_header)

                from_header = decode_header_value(msg.get("From", ""))
                sender_name, sender_email = parseaddr(from_header)
                sender_email = sender_email.lower().strip()

                if not sender_email:
                    continue

                msg_date_str = msg.get("Date")
                try:
                    msg_date = parsedate_to_datetime(msg_date_str) if msg_date_str else None
                except Exception:
                    msg_date = None

                subject = decode_header_value(msg.get("Subject", ""))

                signals = detect_paid_signals(subject)
                if not signals:
                    continue

                entry = results[sender_email]
                entry["sender_name"] = sender_name or entry["sender_name"]
                entry["sender_email"] = sender_email
                entry["count"] += 1
                entry["detection_method"].update(signals)

                if msg_date:
                    date_iso = msg_date.isoformat()
                    if entry["first_seen"] is None or date_iso < entry["first_seen"]:
                        entry["first_seen"] = date_iso
                    if entry["last_seen"] is None or date_iso > entry["last_seen"]:
                        entry["last_seen"] = date_iso

                if subject and len(entry["subjects"]) < 5:
                    entry["subjects"].append(subject)

            if progress_callback:
                progress_callback(min(i + batch_size, total), total, "Scanning...")

    finally:
        server.logout()

    merged = {}
    for email_addr, info in results.items():
        if not info["detection_method"]:
            continue
        domain = email_addr.split("@")[-1]
        base_domain = ".".join(domain.split(".")[-2:])
        if base_domain in merged:
            existing = merged[base_domain]
            existing["count"] += info["count"]
            existing["detection_method"].update(info["detection_method"])
            if info["first_seen"] and (not existing["first_seen"] or info["first_seen"] < existing["first_seen"]):
                existing["first_seen"] = info["first_seen"]
            if info["last_seen"] and (not existing["last_seen"] or info["last_seen"] > existing["last_seen"]):
                existing["last_seen"] = info["last_seen"]
            for subj in info["subjects"]:
                if subj not in existing["subjects"] and len(existing["subjects"]) < 5:
                    existing["subjects"].append(subj)
            existing["sender_name"] = existing["sender_name"] or info["sender_name"]
        else:
            merged[base_domain] = info

    subscriptions = []
    for info in merged.values():
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
