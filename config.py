import os
from dotenv import load_dotenv

load_dotenv()

IMAP_HOST = os.getenv("IMAP_HOST", "")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD", "")
IMAP_USE_SSL = os.getenv("IMAP_USE_SSL", "true").lower() == "true"
SCAN_DAYS = int(os.getenv("SCAN_DAYS", "365"))
