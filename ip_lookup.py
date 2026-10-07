import ipaddress
from urllib.parse import quote

import requests


LOOKUP_TIMEOUT = (3, 6)
LOOKUP_URL = "https://ipwho.is/{ip}"


class IPLookupError(Exception):
    pass


def lookup_public_ip(value):
    value = str(value).strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from error
    if not address.is_global:
        raise ValueError("Only public IP addresses can be looked up.")

    try:
        response = requests.get(
            LOOKUP_URL.format(ip=quote(address.compressed, safe=":")),
            headers={"Accept": "application/json"},
            timeout=LOOKUP_TIMEOUT,
        )
    except requests.RequestException as error:
        raise IPLookupError("The IP lookup service is unavailable.") from error

    try:
        response.raise_for_status()
        record = response.json()
    except requests.RequestException as error:
        raise IPLookupError("The IP lookup service is unavailable.") from error
    except ValueError as error:
        raise IPLookupError("The IP lookup service returned an invalid response.") from error

    if not isinstance(record, dict) or record.get("success") is not True:
        raise IPLookupError("No public IP information was returned for this address.")

    location = record.get("region") or record.get("city")
    connection = record.get("connection")
    connection = connection if isinstance(connection, dict) else {}
    return {
        "ip": record.get("ip", address.compressed),
        "version": record.get("type", f"IPv{address.version}"),
        "country": record.get("country"),
        "region": location,
        "city": record.get("city"),
        "latitude": record.get("latitude"),
        "longitude": record.get("longitude"),
        "isp": connection.get("isp"),
        "organization": connection.get("org"),
        "asn": connection.get("asn"),
        "provider": "ipwho.is",
    }
