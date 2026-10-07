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
}
CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u0456": "i", "\u0458": "j",
    "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0443": "y", "\u03b1": "a", "\u03bf": "o", "\u03c1": "p",
    "\u03c5": "u", "\u03bd": "v",
})


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
        official_labels = official_domain.split(".")
        if labels[-2:] == official_labels:
            continue
        best_score = 0.0
        best_label = ""
        for label in candidates:
            skeleton = _unicode_skeleton(label)
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
