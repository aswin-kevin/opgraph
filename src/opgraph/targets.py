"""Parse and normalise network targets: hosts, host:port pairs and URLs.

Everything that decides scope works on the output of this module, never on raw strings.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ssh": 22}


class TargetError(ValueError):
    """Raised when a string cannot be parsed as a network target."""


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    scheme: str | None  # "http", "https", ... or None for a bare host
    host: str  # lowercase hostname or IP text, no brackets, no userinfo
    port: int | None  # explicit port, or the scheme's default port
    path: str  # "" for bare hosts


def parse_target(raw: str) -> ParsedTarget:
    """Parse a host, host:port, [ipv6]:port or URL. Raises TargetError for anything else.

    Userinfo (``user@host``) is dropped so ``http://good.test@evil.test/`` yields ``evil.test``.
    Hostnames must be plain ASCII (letters, digits, ``-``, ``_``, ``.``): percent-encoding and
    Unicode are rejected, because tools may decode them differently than we do.
    """
    text = raw.strip() if isinstance(raw, str) else ""
    if not text or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise TargetError(f"invalid target: {raw!r}")

    if _is_bare_ipv6(text):
        return ParsedTarget(raw, None, str(ipaddress.ip_address(text)), None, "")

    has_scheme = "://" in text
    try:
        parts = urlsplit(text if has_scheme else "//" + text)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:  # bad port or bracket syntax
        raise TargetError(f"invalid target: {raw!r}") from exc
    if not host:
        raise TargetError(f"no host in target: {raw!r}")
    host = host.lower().rstrip(".")
    if not _HOSTNAME.fullmatch(host) and not _is_ip_text(host):
        raise TargetError(f"invalid host in target: {raw!r}")

    scheme = parts.scheme.lower() if has_scheme else None
    if port is None and scheme:
        port = DEFAULT_PORTS.get(scheme)
    path = parts.path if has_scheme else ""
    return ParsedTarget(raw, scheme, host, port, path)


_HOSTNAME = re.compile(r"[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?")


def _is_ip_text(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_bare_ipv6(text: str) -> bool:
    if text.count(":") < 2 or "/" in text or "[" in text:
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def canonical_ip(host: str) -> IPAddress | None:
    """Return the IP a host string *literally* denotes, or None if it is a hostname.

    Handles the forms tools like curl accept: dotted, decimal (2852039166), hex (0xa9fea9fe),
    octal (0251.0376.0251.0376), short (169.254.43518), and IPv6 forms that embed an IPv4
    address (::ffff:a9fe:a9fe, 64:ff9b::a9fe:a9fe, ::a9fe:a9fe) are reduced to that IPv4 address.
    """
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    if isinstance(ip, ipaddress.IPv6Address):
        return _embedded_ipv4(ip) or ip
    return ip


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv6 forms that reach an IPv4 host: mapped, NAT64 and (deprecated) IPv4-compatible."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if (ip in _NAT64 or ip in _IPV4_COMPATIBLE) and int(ip) & 0xFFFFFFFF and int(ip) > 1:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def system_resolve(host: str) -> str:
    """Resolve a hostname with this machine's resolver; returns the first address."""
    return str(socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0])


def normalize_url(url: str, keep_query: bool = False) -> str:
    """Canonical URL used as a fact identity: lowercase scheme/host, no default port, no fragment."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    target = parse_target(url)
    host = f"[{target.host}]" if ":" in target.host else target.host
    netloc = host
    if target.port is not None and target.port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{target.port}"
    query = parts.query if keep_query else ""
    return urlunsplit((scheme, netloc, parts.path or "/", query, ""))


def base_url(url: str) -> str:
    """``http://h:8080/a/b?x=1`` -> ``http://h:8080``."""
    normal = normalize_url(url)
    parts = urlsplit(normal)
    return f"{parts.scheme}://{parts.netloc}"
