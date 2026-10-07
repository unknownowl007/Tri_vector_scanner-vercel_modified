import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests


CONNECT_TIMEOUT = 5
RDAP_TIMEOUT = (3, 6)
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


class DomainCheckError(Exception):
    pass


def normalize_domain(value):
    value = str(value).strip()
    if not value or len(value) > 2048:
        raise ValueError("Enter a valid domain name or URL.")

    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in the domain field.")
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid domain name or URL.") from error

    if not hostname:
        raise ValueError("Enter a valid domain name or URL.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as error:
            raise ValueError("Enter a valid domain name or URL.") from error
        labels = hostname.split(".")
        if (
            len(hostname) > 253
            or len(labels) < 2
            or any(
                not label
                or len(label) > 63
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or any(not (char.isalnum() or char == "-") for char in label)
                for label in labels
            )
        ):
            raise ValueError("Enter a valid domain name or URL.")
    else:
        hostname = address.compressed

    return hostname


def _public_addresses(hostname):
    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise DomainCheckError("The domain could not be resolved.") from error
    if not addresses:
        raise DomainCheckError("The domain did not resolve to an IP address.")

    if any(not ipaddress.ip_address(item[4][0].split("%", 1)[0]).is_global for item in addresses):
        raise DomainCheckError("Private and local network addresses cannot be scanned.")
    return addresses


def _format_certificate_name(parts):
    return ", ".join(
        f"{key}={value}"
        for group in parts
        for key, value in group
    )


def check_ssl_certificate(hostname):
    addresses = _public_addresses(hostname)
    context = ssl.create_default_context()
    verification_errors = []
    connection_errors = []

    for family, socktype, protocol, _, address in addresses:
        raw_socket = socket.socket(family, socktype, protocol)
        raw_socket.settimeout(CONNECT_TIMEOUT)
        try:
            raw_socket.connect(address)
            with context.wrap_socket(raw_socket, server_hostname=hostname) as connection:
                certificate = connection.getpeercert()
            expires_at = ssl.cert_time_to_seconds(certificate["notAfter"])
            expiry = datetime.fromtimestamp(expires_at, timezone.utc)
            return {
                "valid": True,
                "hostname": hostname,
                "subject": _format_certificate_name(certificate.get("subject", ())),
                "issuer": _format_certificate_name(certificate.get("issuer", ())),
                "expires_at": expiry.isoformat(),
                "days_remaining": (expiry - datetime.now(timezone.utc)).days,
                "subject_alt_names": len(certificate.get("subjectAltName", ())),
            }
        except ssl.SSLCertVerificationError as error:
            verification_errors.append(error)
        except (OSError, ssl.SSLError) as error:
            connection_errors.append(error)
        finally:
            raw_socket.close()

    if verification_errors:
        reason = verification_errors[-1].verify_message
        return {
            "valid": False,
            "hostname": hostname,
            "message": f"Certificate validation failed: {reason}",
        }
    detail = str(connection_errors[-1]) if connection_errors else "No reachable HTTPS service."
    raise DomainCheckError(f"Could not connect to {hostname} on port 443: {detail}")


def _rdap_event(events, action):
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == action:
            date = event.get("eventDate")
            return date if isinstance(date, str) else None
    return None


def _registrar(entities):
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", [])
        if not isinstance(roles, list) or "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                return item[3]
    return None


def _rdap_urls(hostname):
    tld = hostname.rsplit(".", 1)[-1]
    try:
        response = requests.get(RDAP_BOOTSTRAP_URL, timeout=RDAP_TIMEOUT)
        response.raise_for_status()
        bootstrap = response.json()
    except requests.RequestException as error:
        raise DomainCheckError("The domain registration directory is unavailable.") from error
    except ValueError as error:
        raise DomainCheckError("The domain registration directory returned an invalid response.") from error

    if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get("services"), list):
        raise DomainCheckError("The domain registration directory returned an invalid response.")

    urls = []
    for service in bootstrap["services"]:
        if not isinstance(service, list) or len(service) != 2:
            continue
        tlds, bases = service
        if not isinstance(tlds, list) or tld not in tlds or not isinstance(bases, list):
            continue
        urls.extend(
            f"{base.rstrip('/')}/domain/{hostname}"
            for base in bases
            if isinstance(base, str) and base.startswith("https://")
        )
    if not urls:
        raise DomainCheckError(f"No RDAP registration service is listed for .{tld}.")
    return urls


def lookup_whois(hostname):
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("WHOIS lookup requires a domain name, not an IP address.")

    failures = []
    record = None
    found_registration_service = False
    for url in _rdap_urls(hostname):
        found_registration_service = True
        try:
            response = requests.get(
                url,
                headers={"Accept": "application/rdap+json"},
                timeout=RDAP_TIMEOUT,
            )
            if response.status_code == 404:
                continue
            response.raise_for_status()
            candidate = response.json()
        except requests.RequestException as error:
            failures.append(str(error))
            continue
        except ValueError:
            failures.append("A registration server returned an invalid response.")
            continue
        if not isinstance(candidate, dict):
            failures.append("A registration server returned an invalid response.")
            continue
        record = candidate
        break

    if record is None:
        if failures:
            raise DomainCheckError(
                "The registration service could not complete the lookup. Please try again."
            )
        if found_registration_service:
            raise DomainCheckError("No registration record was found for this domain.")
        raise DomainCheckError("No registration service is available for this domain.")

    status = record.get("status", [])
    return {
        "domain": record.get("ldhName", hostname),
        "registrar": _registrar(record.get("entities", [])),
        "created_at": _rdap_event(record.get("events", []), "registration"),
        "updated_at": _rdap_event(record.get("events", []), "last changed"),
        "expires_at": _rdap_event(record.get("events", []), "expiration"),
        "status": [item for item in status if isinstance(item, str)] if isinstance(status, list) else [],
    }
