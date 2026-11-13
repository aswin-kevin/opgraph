"""Make tools connect to the IP the scope check pinned, not whatever DNS says later."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from ..scope import CheckedTarget
from ..targets import canonical_ip


def curl_pin(checked: CheckedTarget) -> list[str]:
    """`--connect-to ::IP:PORT`: every connection curl makes goes to the pinned address, however
    curl itself parses the host. TLS SNI and the Host header keep the original name."""
    port = checked.target.port
    if port is None:
        return []
    ip = f"[{checked.ip}]" if ":" in checked.ip else checked.ip
    return ["--connect-to", f"::{ip}:{port}"]


def pinned_url(url: str, checked: CheckedTarget) -> tuple[str, str | None]:
    """For tools without a pinning option: put the pinned IP in a plain-http URL and return the
    original Host header to send.

    HTTPS URLs are returned unchanged because rewriting would break TLS; for those the tool
    resolves the (in-scope) name itself, so DNS rebinding is not prevented.
    """
    t = checked.target
    if t.scheme != "http" or canonical_ip(t.host) is not None:
        return url, None
    parts = urlsplit(url)
    ip = f"[{checked.ip}]" if ":" in checked.ip else checked.ip
    netloc = f"{ip}:{parts.port}" if parts.port else ip
    host_header = f"{t.host}:{parts.port}" if parts.port else t.host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), host_header
