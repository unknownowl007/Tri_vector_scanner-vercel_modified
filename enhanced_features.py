import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit


BRANDS = (
    "google",
    "facebook",
    "microsoft",
    "amazon",
    "apple",
    "netflix",
    "instagram",
    "paypal",
    "ebay",
    "walmart",
    "outlook",
)
SUSPICIOUS_WORDS = (
    "account",
    "bank",
    "confirm",
    "login",
    "password",
    "secure",
    "support",
    "update",
    "verify",
)
SHORTENERS = ("bit.ly", "goo.gl", "is.gd", "ow.ly", "t.co", "tinyurl.com")
SUSPICIOUS_TLDS = {"click", "country", "gq", "icu", "link", "live", "tk", "top", "work"}
RISKY_EXTENSIONS = (".exe", ".html", ".php", ".scr", ".zip")
FEATURE_COUNT = 35


def _entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )


def extract_enhanced_features(url):
    value = str(url).strip().lower()
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        parsed = urlsplit("")
        hostname = ""
        port = None

    path = parsed.path.rstrip("/")
    query = parsed.query
    userinfo = parsed.netloc.lower().rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    canonical_host = f"{userinfo}{hostname}"
    if port and port not in (80, 443):
        canonical_host += f":{port}"
    canonical_url = canonical_host + path
    if query:
        canonical_url += f"?{query}"
    if parsed.fragment:
        canonical_url += f"#{parsed.fragment}"
    labels = hostname.split(".") if hostname else []
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    return [
        len(canonical_url),
        len(hostname),
        len(path),
        len(query),
        canonical_url.count("."),
        canonical_url.count("-"),
        canonical_url.count("@"),
        canonical_url.count("?"),
        canonical_url.count("_") + canonical_url.count("%"),
        path.count("/"),
        canonical_url.count("="),
        canonical_url.count("&"),
        canonical_url.count(":"),
        max(0, len(labels) - 2),
        0,  # TLS certificate validation is separate; the scheme alone is not a phishing signal.
        is_ip,
        int(port is not None and port not in (80, 443)),
        int("@" in parsed.netloc),
        sum(char.isdigit() for char in canonical_url) / max(len(canonical_url), 1),
        sum(char.isdigit() for char in hostname) / max(len(hostname), 1),
        sum(word in canonical_url for word in SUSPICIOUS_WORDS),
        int(any(brand in hostname for brand in BRANDS)),
        int(any(shortener in hostname for shortener in SHORTENERS)),
        int("xn--" in hostname),
        len([part for part in path.split("/") if part]),
        len([part for part in query.split("&") if part]),
        int(bool(parsed.fragment)),
        canonical_url.count("%"),
        _entropy(hostname),
        _entropy(canonical_url),
        max((len(run) for run in re.findall(r"\d+", canonical_url)), default=0),
        int("//" in path),
        int(hostname.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS if hostname else False),
        int(any(char.isdigit() for char in hostname)),
        int(any(path.endswith(extension) for extension in RISKY_EXTENSIONS)),
    ]
