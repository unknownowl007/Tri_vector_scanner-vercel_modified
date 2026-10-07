import csv
from pathlib import Path
from urllib.parse import urlsplit


KNOWN_URLS_FILE = (
    Path(__file__).resolve().parent / "datasets" / "known_phishing_urls.csv"
)


def _url_key(value):
    value = str(value).strip()
    try:
        parsed = urlsplit(value if "://" in value else f"http://{value}")
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError):
        return None
    if port and port not in (80, 443):
        hostname = f"{hostname}:{port}"

    path = parsed.path.rstrip("/")
    return f"{hostname}{path}?{parsed.query}" if parsed.query else f"{hostname}{path}"


def load_known_phishing_urls(path=KNOWN_URLS_FILE):
    known_urls = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as csv_file:
        for row in csv.DictReader(csv_file):
            url = row.get("url", "").strip()
            if not url:
                continue
            key = _url_key(url)
            if key:
                known_urls[key] = row.get("source", "local CSV") or "local CSV"
    return known_urls


def check_known_phishing_url(url, known_urls):
    key = _url_key(url)
    source = known_urls.get(key) if key else None
    return {
        "listed": source is not None,
        "source": source,
        "database": "Local labeled URL dataset",
        "note": "A match is a historical dataset entry, not a live reputation check.",
    }
