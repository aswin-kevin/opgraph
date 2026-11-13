"""Scope: decide whether a target may be touched, on canonical forms rather than strings."""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .targets import IPAddress, ParsedTarget, TargetError, canonical_ip, parse_target, system_resolve

Resolver = Callable[[str], str]

# Cloud metadata services live here (169.254.169.254, AWS fd00:ec2::254). Blocked unless listed in `nets`.
_METADATA = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


# IPv6 prefixes that carry IPv4 addresses (mapped, NAT64, IPv4-compatible): single addresses are
# translated by canonical_ip, ranges in them are refused.
_V4_IN_V6 = (
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("::/96"),
)


class OutOfScope(Exception):
    def __init__(self, target: str, reason: str, ip: str | None = None):
        self.target, self.reason, self.ip = target, reason, ip
        arrow = f" -> {ip}" if ip else ""
        super().__init__(f"{target}{arrow}: {reason}")


@dataclass(frozen=True)
class CheckedTarget:
    """A target that passed the scope check. `ip` is the pinned address tools must use (for a CIDR
    range it is the normalised network, e.g. ``10.0.0.0/24``)."""

    target: ParsedTarget
    ip: str

    @property
    def host(self) -> str:
        return self.target.host


class Scope:
    """Engagement scope.

    - An IP target is in scope if it is inside `nets`.
    - A hostname is in scope if it equals or is a subdomain of an entry in `domains`. Only such names
      are resolved (never out-of-scope ones, so DNS cannot be used as a side channel); the answer is
      pinned, and must not be loopback, metadata, multicast or reserved space unless listed in `nets`.
    - `exclude` (networks or domains) always wins.
    - A CIDR range (10.0.0.0/24) is in scope only if it lies entirely inside one of `nets` and does
      not overlap `exclude`.
    - If `ports` is set, explicit or scheme-default ports must be in it; a URL whose scheme has no
      known default port must then name its port explicitly.

    Note: when tools are sent through a proxy (e.g. ``config["http_proxy"]``), the proxy resolves
    hostnames itself, so DNS pinning no longer applies to those requests.
    """

    def __init__(
        self,
        nets: Iterable[str] = (),
        domains: Iterable[str] = (),
        exclude: Iterable[str] = (),
        ports: Iterable[int] | None = None,
        resolver: Resolver | None = None,
    ):
        self.nets = [ipaddress.ip_network(n, strict=False) for n in nets]
        self.domains = [_clean_domain(d) for d in domains]
        self.exclude_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.exclude_domains: list[str] = []
        for item in exclude:
            try:
                self.exclude_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                self.exclude_domains.append(_clean_domain(item))
        self.ports = frozenset(ports) if ports is not None else None
        self.resolver = resolver
        self._pins: dict[str, str] = {}
        self._lock = threading.Lock()

    # ---- construction -------------------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict[str, Any], resolver: Resolver | None = None) -> Scope:
        return cls(
            nets=data.get("nets", ()),
            domains=data.get("domains", ()),
            exclude=data.get("exclude", ()),
            ports=data.get("ports"),
            resolver=resolver,
        )

    @classmethod
    def from_file(cls, path: str | Path, resolver: Resolver | None = None) -> Scope:
        """Load a JSON or TOML scope file."""
        path = Path(path)
        text = path.read_text()
        data = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
        return cls.from_dict(data, resolver)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nets": [str(n) for n in self.nets],
            "domains": list(self.domains),
            "exclude": [str(n) for n in self.exclude_nets] + list(self.exclude_domains),
            "ports": sorted(self.ports) if self.ports is not None else None,
        }

    # ---- checks -------------------------------------------------------------------------------

    def check(self, target: str, resolver: Resolver | None = None) -> CheckedTarget:
        """Return the checked target (with the pinned IP tools must use) or raise OutOfScope.

        `resolver` overrides the scope's resolver for this check (e.g. resolve on the attack box).
        """
        try:
            parsed = parse_target(target)
        except TargetError as exc:
            raise OutOfScope(target, str(exc)) from None

        if parsed.is_network:
            return self._check_network(target, parsed)
        if self.ports is not None:
            if parsed.port is not None and parsed.port not in self.ports:
                raise OutOfScope(target, f"port {parsed.port} not in scope")
            if parsed.port is None and parsed.scheme:
                raise OutOfScope(target, f"no known default port for {parsed.scheme}://; give the port")

        literal_ip = canonical_ip(parsed.host)
        if literal_ip is not None:
            self._check_ip(target, literal_ip, domain_ok=False)
            return CheckedTarget(parsed, str(literal_ip))

        if self._matches(parsed.host, self.exclude_domains):
            raise OutOfScope(target, "domain excluded")
        if not self._matches(parsed.host, self.domains):
            raise OutOfScope(target, "hostname not in scope domains")
        ip = self._resolve(target, parsed.host, resolver)
        self._check_ip(target, ip, domain_ok=True)
        return CheckedTarget(parsed, str(ip))

    def allows(self, target: str) -> bool:
        try:
            self.check(target)
        except OutOfScope:
            return False
        return True

    def audit_command(self, command: str) -> list[str]:
        """Advisory only: list targets in a raw shell command that look out of scope.

        Shell strings cannot be checked reliably (encoding, variables, files); this catches the
        obvious cases for logging. Real enforcement needs typed techniques.
        """
        warnings = []
        for token in sorted(set(_CANDIDATES.findall(command))):
            if token.endswith((".txt", ".sh", ".py", ".json", ".xml", ".log")):
                continue
            try:
                self.check(token)
            except OutOfScope as exc:
                warnings.append(str(exc))
        return warnings

    # ---- internals ----------------------------------------------------------------------------

    def _check_network(self, target: str, parsed: ParsedTarget) -> CheckedTarget:
        network = ipaddress.ip_network(parsed.host)
        if isinstance(network, ipaddress.IPv6Network) and any(network.overlaps(n) for n in _V4_IN_V6):
            raise OutOfScope(target, "IPv6 range embedding IPv4 addresses; use the IPv4 range instead")
        if any(network.overlaps(ex) for ex in self.exclude_nets if ex.version == network.version):
            raise OutOfScope(target, "range overlaps excluded addresses; split it around them")
        if not any(network.subnet_of(n) for n in self.nets if n.version == network.version):  # type: ignore[arg-type]
            raise OutOfScope(target, "range is not entirely inside the scope networks")
        return CheckedTarget(parsed, str(network))

    def _check_ip(self, target: str, ip: IPAddress, domain_ok: bool) -> None:
        if any(ip in net for net in self.exclude_nets):
            raise OutOfScope(target, "address excluded", str(ip))
        explicitly_included = any(ip in net for net in self.nets)
        if explicitly_included:
            return
        if any(ip in net for net in _METADATA):
            raise OutOfScope(target, "link-local/metadata address", str(ip))
        if not domain_ok:
            raise OutOfScope(target, "not in scope", str(ip))
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise OutOfScope(target, "domain resolves to loopback/reserved address", str(ip))

    def _resolve(self, target: str, host: str, resolver: Resolver | None) -> IPAddress:
        with self._lock:
            pinned = self._pins.get(host)
        if pinned is None:
            resolve = resolver or self.resolver or system_resolve
            try:
                pinned = resolve(host)
            except (OSError, ValueError) as exc:
                raise OutOfScope(target, f"cannot resolve: {exc}") from None
            with self._lock:
                pinned = self._pins.setdefault(host, pinned)
        ip = canonical_ip(pinned)
        if ip is None:
            raise OutOfScope(target, f"resolver returned a non-IP: {pinned!r}")
        return ip

    @staticmethod
    def _matches(host: str, domains: list[str]) -> bool:
        return any(host == d or host.endswith("." + d) for d in domains)


def _clean_domain(domain: str) -> str:
    return domain.strip().lower().lstrip("*.").rstrip(".")


# URLs, [ipv6] literals, dotted names and IPv4-ish numbers inside a command line.
_CANDIDATES = re.compile(
    r"[a-z][a-z0-9+.-]*://[^\s'\"<>]+"
    r"|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}\b",
    re.IGNORECASE,
)
