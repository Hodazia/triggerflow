# app/core/webhook_url_security.py

import ipaddress
from urllib.parse import urlsplit


def validate_webhook_url(url: str) -> None:
    parsed = urlsplit(url)

    if parsed.scheme.lower() != "https":
        raise ValueError("Webhook URLs must use HTTPS")

    if not parsed.hostname:
        raise ValueError("Webhook URL must contain a hostname")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in webhook URLs are not allowed")

    if parsed.port not in (None, 443):
        raise ValueError("Only the default HTTPS port is allowed")

    hostname = parsed.hostname.lower().rstrip(".")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost webhook URLs are not allowed")

    if hostname.endswith(".local"):
        raise ValueError("Local network hostnames are not allowed")

    # Reject IP literals instead of accepting them as destinations.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Webhook URLs must use a public hostname")

'''
if a project is not deployed on https, then reject the above validation
only for development purposes

'''