import difflib
import ipaddress
import socket
import ssl
import unicodedata
from urllib.parse import urljoin, urlsplit, urlunsplit

from domain_checks import DomainCheckError, normalize_domain


MAX_REDIRECTS = 8
REQUEST_TIMEOUT = 5
MAX_HEADER_BYTES = 32 * 1024
BRAND_DOMAINS = {
    # Original brands
    "amazon": "amazon.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "google": "google.com",
    "instagram": "instagram.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "outlook": "outlook.com",
    "paypal": "paypal.com",
    "walmart": "walmart.com",
    # Big tech and social
    "ebay": "ebay.com",
    "gmail": "gmail.com",
    "icloud": "icloud.com",
    "yahoo": "yahoo.com",
    "youtube": "youtube.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "whatsapp": "whatsapp.com",
    "telegram": "telegram.org",
    "snapchat": "snapchat.com",
    "tiktok": "tiktok.com",
    "pinterest": "pinterest.com",
    "reddit": "reddit.com",
    "discord": "discord.com",
    "twitch": "twitch.tv",
    "skype": "skype.com",
    "spotify": "spotify.com",
    # Software, cloud, and developer
    "adobe": "adobe.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
    "atlassian": "atlassian.com",
    "salesforce": "salesforce.com",
    "oracle": "oracle.com",
    "shopify": "shopify.com",
    "cloudflare": "cloudflare.com",
    "godaddy": "godaddy.com",
    "namecheap": "namecheap.com",
    "docusign": "docusign.com",
    "wetransfer": "wetransfer.com",
    "wordpress": "wordpress.org",
    "metamask": "metamask.io",
    # Hardware
    "samsung": "samsung.com",
    "huawei": "huawei.com",
    "lenovo": "lenovo.com",
    "nvidia": "nvidia.com",
    # Banks and payments
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citibank.com",
    "capitalone": "capitalone.com",
    "americanexpress": "americanexpress.com",
    "mastercard": "mastercard.com",
    "usbank": "usbank.com",
    "hsbc": "hsbc.com",
    "barclays": "barclays.co.uk",
    "santander": "santander.com",
    "revolut": "revolut.com",
    "payoneer": "payoneer.com",
    "venmo": "venmo.com",
    "zelle": "zellepay.com",
    "cashapp": "cash.app",
    "stripe": "stripe.com",
    "westernunion": "westernunion.com",
    "moneygram": "moneygram.com",
    "intuit": "intuit.com",
    "schwab": "schwab.com",
    "fidelity": "fidelity.com",
    "vanguard": "vanguard.com",
    "robinhood": "robinhood.com",
    # Crypto
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "kraken": "kraken.com",
    "blockchain": "blockchain.com",
    # Shopping and travel
    "aliexpress": "aliexpress.com",
    "alibaba": "alibaba.com",
    "bestbuy": "bestbuy.com",
    "costco": "costco.com",
    "homedepot": "homedepot.com",
    "wayfair": "wayfair.com",
    "shein": "shein.com",
    "zalando": "zalando.com",
    "flipkart": "flipkart.com",
    "rakuten": "rakuten.com",
    "mercadolibre": "mercadolibre.com",
    "airbnb": "airbnb.com",
    "expedia": "expedia.com",
    "tripadvisor": "tripadvisor.com",
    "doordash": "doordash.com",
    "grubhub": "grubhub.com",
    # Shipping
    "fedex": "fedex.com",
    "royalmail": "royalmail.com",
    "canadapost": "canadapost.ca",
    "aramex": "aramex.com",
    # Streaming and gaming
    "disneyplus": "disneyplus.com",
    "primevideo": "primevideo.com",
    "steampowered": "steampowered.com",
    "epicgames": "epicgames.com",
    "roblox": "roblox.com",
    "playstation": "playstation.com",
    "nintendo": "nintendo.com",
    "blizzard": "blizzard.com",
    "riotgames": "riotgames.com",
    "minecraft": "minecraft.net",
    # Telecom
    "verizon": "verizon.com",
    "tmobile": "tmobile.com",
    "vodafone": "vodafone.com",
    "comcast": "comcast.com",
    "xfinity": "xfinity.com",
    "telstra": "telstra.com",
}

# Other legitimate domains owned by each brand. These are never flagged.
EXTRA_OFFICIAL_DOMAINS = {
    "amazon": ("amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es", "amazon.it",
               "amazon.ca", "amazon.in", "amazon.co.jp", "amazon.com.au", "amazonaws.com"),
    "google": ("google.co.uk", "google.de", "google.fr", "google.es", "google.it",
               "google.ca", "google.co.in", "google.co.jp", "google.com.au",
               "googleapis.com", "googleusercontent.com", "gmail.com"),
    "microsoft": ("microsoftonline.com", "microsoft365.com", "office.com", "live.com"),
    "outlook": ("live.com", "office.com", "office365.com"),
    "facebook": ("fb.com", "fb.me", "facebook.net"),
    "instagram": ("cdninstagram.com",),
    "paypal": ("paypal.me", "paypalobjects.com"),
    "walmart": ("walmart.ca",),
    "ebay": ("ebay.co.uk", "ebay.de", "ebay.fr", "ebay.it", "ebay.es", "ebay.ca", "ebay.com.au"),
    "yahoo": ("yahoo.co.jp","yahoo.fr", "yahoo.co.uk"),
    "youtube": ("youtu.be",),
    "telegram": ("telegram.me",),
    "discord": ("discord.gg", "discordapp.com"),
    "reddit": ("redd.it", "redditmedia.com", "redditstatic.com"),
    "github": ("github.io", "githubusercontent.com"),
    "gitlab": ("gitlab.io",),
    "dropbox": ("dropboxusercontent.com",),
    "adobe": ("adobe.io", "adobelogin.com"),
    "shopify": ("myshopify.com",),
    "wordpress": ("wordpress.com",),
    "alibaba": ("alibabacloud.com",),
    "tiktok": ("tiktokcdn.com",),
}
CONFUSABLES = str.maketrans({
    # Cyrillic lookalikes
    "\u0430": "a", "\u0435": "e", "\u0456": "i", "\u0458": "j",
    "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0443": "y", "\u0455": "s", "\u0501": "d", "\u04bb": "h",
    "\u051b": "q", "\u051d": "w", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u0442": "t", "\u0433": "r", "\u04cf": "l",
    "\u0475": "v", "\u04af": "y", "\u050d": "g",
    # Greek lookalikes
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e",
    "\u03b7": "n", "\u03b9": "i", "\u03ba": "k", "\u03bc": "u",
    "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t",
    "\u03c5": "u", "\u03c7": "x", "\u03c9": "w", "\u03f2": "c",
    "\u03f3": "j",
    # Armenian lookalikes
    "\u0585": "o", "\u057d": "u", "\u0578": "n", "\u0570": "h",
    "\u0581": "g",
    # Latin letters that NFKD does not split into base letter + accent
    "\u0131": "i", "\u0269": "i", "\u026a": "i", "\u0251": "a",
    "\u0261": "g", "\u0262": "g", "\u0266": "h", "\u028b": "v",
    "\u01dd": "e", "\u01c0": "l", "\u0142": "l", "\u00f8": "o",
    "\u0111": "d", "\u0127": "h", "\u0167": "t", "\u0192": "f",
    "\u00df": "ss", "\u00e6": "ae", "\u0153": "oe",
    # Small-capital letters
    "\u1d00": "a", "\u0299": "b", "\u1d04": "c", "\u1d05": "d",
    "\u1d07": "e", "\u029c": "h", "\u1d0a": "j", "\u1d0b": "k",
    "\u029f": "l", "\u1d0d": "m", "\u0274": "n", "\u1d0f": "o",
    "\u1d18": "p", "\u0280": "r", "\ua731": "s", "\u1d1b": "t",
    "\u1d1c": "u", "\u1d20": "v", "\u1d21": "w", "\u028f": "y",
    "\u1d22": "z",
    # ASCII digit lookalikes ("1" is handled separately by ONE_AS_L / ONE_AS_I)
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t",
    "6": "g", "8": "b", "9": "g",
    # "2": "z",  # optional, rarely used; uncomment if you want it
})
# "1" can mean either "l" (paypa1) or "i" (netfl1x), so both are tried.
ONE_AS_L = str.maketrans({"1": "l"})
ONE_AS_I = str.maketrans({"1": "i"})


def _ascii_host(hostname):
    try:
        return hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise ValueError("Enter a valid domain name.") from error


def _public_host_addresses(hostname, port):
    try:
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise DomainCheckError("The URL host could not be resolved.") from error
    if not addresses:
        raise DomainCheckError("The URL host did not resolve to an IP address.")
    for answer in addresses:
        address = ipaddress.ip_address(answer[4][0].split("%", 1)[0])
        if not address.is_global:
            raise DomainCheckError("Redirect analysis cannot access private or local network addresses.")
    return addresses


def _request_headers(url):
    if len(url) > 2048 or any(ord(character) < 32 for character in url):
        raise ValueError("Enter a valid URL.")
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("URLs with credentials or no host cannot be analyzed.")
    hostname = _ascii_host(parsed.hostname)
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        normalized_host = normalize_domain(hostname)
    else:
        if not address.is_global:
            raise DomainCheckError("Redirect analysis cannot access private or local network addresses.")
        normalized_host = address.compressed
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    expected_port = 443 if parsed.scheme.lower() == "https" else 80
    if port != expected_port:
        raise ValueError("Redirect analysis only supports standard HTTP and HTTPS ports.")
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    host_header = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    if parsed.port:
        host_header += f":{parsed.port}"
    return parsed, normalized_host, port, path, host_header


def _fetch_status_and_location(url):
    parsed, hostname, port, path, host_header = _request_headers(url)
    addresses = _public_host_addresses(hostname, port)
    last_error = None
    for family, socktype, protocol, _, address in addresses:
        connection = None
        try:
            connection = socket.socket(family, socktype, protocol)
            connection.settimeout(REQUEST_TIMEOUT)
            connection.connect(address)
            if parsed.scheme.lower() == "https":
                context = ssl.create_default_context()
                connection = context.wrap_socket(connection, server_hostname=hostname)
            request_bytes = (
                f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                "Range: bytes=0-0\r\nConnection: close\r\n"
                "User-Agent: TriVectorSecurityScanner/1.0\r\n\r\n"
            ).encode("ascii", "strict")
            connection.sendall(request_bytes)
            stream = connection.makefile("rb")
            status_line = stream.readline(4096).decode("iso-8859-1").strip()
            pieces = status_line.split(" ", 2)
            if len(pieces) < 2 or not pieces[1].isdigit():
                raise DomainCheckError("The destination returned an invalid HTTP response.")
            status = int(pieces[1])
            headers = {}
            header_bytes = len(status_line) + 2
            while True:
                line = stream.readline(8192)
                header_bytes += len(line)
                if header_bytes > MAX_HEADER_BYTES:
                    raise DomainCheckError("The destination returned oversized response headers.")
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    key, value = line.split(b":", 1)
                    headers[key.decode("iso-8859-1").strip().lower()] = value.decode("iso-8859-1").strip()
            return status, headers.get("location")
        except (OSError, ssl.SSLError, UnicodeError) as error:
            last_error = error
        finally:
            if connection is not None:
                connection.close()
    raise DomainCheckError(f"Could not retrieve response headers: {last_error}")


def analyze_redirect_chain(url):
    current = url.strip()
    if "://" not in current:
        current = f"https://{current}"
    chain = []
    visited = set()
    for _ in range(MAX_REDIRECTS + 1):
        parsed, hostname, _, _, _ = _request_headers(current)
        canonical = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
        if canonical in visited:
            raise DomainCheckError("A redirect loop was detected.")
        visited.add(canonical)
        status, location = _fetch_status_and_location(current)
        hop = {"url": current, "hostname": hostname, "status": status}
        if status not in (301, 302, 303, 307, 308) or not location:
            chain.append(hop)
            return {"chain": chain, "final_url": current, "redirect_count": len(chain) - 1}
        next_url = urljoin(current, location)
        _request_headers(next_url)
        hop["redirect_to"] = next_url
        chain.append(hop)
        current = next_url
    raise DomainCheckError(f"Redirect chain exceeds the {MAX_REDIRECTS}-hop safety limit.")


def _unicode_skeleton(label):
    try:
        decoded = label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError):
        decoded = label
    normalized = unicodedata.normalize("NFKD", decoded).translate(CONFUSABLES)
    return "".join(character for character in normalized if character.isalnum())


def _skeleton_variants(label):
    """Return possible 'de-obfuscated' forms of a domain label."""
    base = _unicode_skeleton(label)
    variants = {base, base.translate(ONE_AS_L), base.translate(ONE_AS_I)}
    variants |= {
        v.replace("rn", "m").replace("vv", "w").replace("cl", "d").replace("nn", "m")
        for v in list(variants)
    }
    return variants


# CHANGE: new helper. True if hostname is the domain itself or one of its subdomains.
def _is_official_host(hostname, official_domains):
    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in official_domains
    )


def check_lookalike_domain(value):
    hostname = normalize_domain(value)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Lookalike checks require a domain name, not an IP address.")

    labels = hostname.split(".")
    candidates = labels[:-1]
    matches = []
    for brand, official_domain in BRAND_DOMAINS.items():
        # CHANGE: skip the brand's own domains (main, regional, and extra ones).
        official_domains = (official_domain,) + EXTRA_OFFICIAL_DOMAINS.get(brand, ())
        if _is_official_host(hostname, official_domains):
            continue
        best_score = 0.0
        best_label = ""
        for label in candidates:
            for skeleton in _skeleton_variants(label):
                score = difflib.SequenceMatcher(None, skeleton, brand).ratio()
                if brand in skeleton and skeleton != brand:
                    score = max(score, 0.9)
                if score > best_score:
                    best_score, best_label = score, label
        if best_score >= 0.78:
            matches.append({
                "brand": brand,
                "lookalike_label": best_label,
                "similarity": round(best_score * 100),
                "official_domain": official_domain,
            })

    matches.sort(key=lambda item: (-item["similarity"], item["brand"]))
    return {
        "domain": hostname,
        "suspicious": bool(matches),
        "matches": matches[:3],
        "message": (
            "This domain resembles a known brand. Similarity is a warning signal, not proof of phishing."
            if matches else "No close match to the built-in brand list was found; this does not guarantee safety."
        ),
    }