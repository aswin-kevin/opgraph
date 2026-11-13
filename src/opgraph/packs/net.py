"""Network techniques: port_scan."""

from __future__ import annotations

import re
from typing import Annotated

from .. import parsers
from ..engagement import Ctx
from ..facts import Fact, service
from ..facts import host as host_fact
from ..render import format_fact
from ..targets import canonical_ip
from ..technique import Host, TechniqueResult, technique

_PORTS = re.compile(r"^(top-\d{1,4}|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$")


@technique(risk="intrusive", attack="T1046", timeout=600)
def port_scan(
    ctx: Ctx,
    host: Host,
    ports: Annotated[str, "'top-100' (default), 'top-1000', or a list like '22,80,8000-8100'"] = "top-100",
) -> TechniqueResult:
    """TCP connect scan with service detection (nmap -sT -sV, polite timing). Yields service facts."""
    if not _PORTS.match(ports):
        raise ValueError("ports must be 'top-N' or a list like '22,80,8000-8100'")
    port_args = ["--top-ports", ports[4:]] if ports.startswith("top-") else ["-p", ports]
    allowed = ctx.scope.ports
    if allowed is not None:  # the scope limits ports: never scan outside them
        if ports.startswith("top-"):
            port_args = ["-p", ",".join(str(p) for p in sorted(allowed))]
        else:
            outside = sorted(expand_ports(ports) - allowed)
            if outside:
                raise ValueError(f"ports outside scope: {outside[:10]}; allowed: {sorted(allowed)}")
    argv = ["nmap", "-sT", "-sV", "-Pn", "-T3", "--max-retries", "2", "--open"]
    argv += ["--script", "http-title,ftp-anon"]
    argv += ["--host-timeout", f"{max(ctx.technique.timeout - 30, 30)}s", "-oX", "-", *port_args]
    argv.append(ctx.targets["host"].ip)  # always an IP: the pinned address

    result = ctx.exec(argv)
    facts = _key_by_name(parsers.nmap_xml(result.stdout), ctx.targets["host"].host)
    services = [f for f in facts if f.kind == "service"]
    lines = [format_fact(s) for s in sorted(services, key=lambda s: s.get("port"))]
    summary = f"{len(services)} open ports on {host}"
    if not result.ok and not facts:
        summary += f"\nnmap error: {result.stderr.strip()[:500]}"
    return TechniqueResult(observation="\n".join([summary, *lines]), facts=facts)


def expand_ports(spec: str) -> set[int]:
    """'22,80,8000-8002' -> {22, 80, 8000, 8001, 8002}. Raises ValueError for invalid ranges."""
    result: set[int] = set()
    for item in spec.split(","):
        low, _, high = item.partition("-")
        start, end = int(low), int(high or low)
        if not 1 <= start <= end <= 65535:
            raise ValueError(f"invalid port range: {item}")
        result.update(range(start, end + 1))
    return result


def _key_by_name(facts: list[Fact], name: str) -> list[Fact]:
    """When the agent scanned a hostname, key facts by that name (IP kept as an attribute), so
    they connect to endpoint facts for URLs that use the same name."""
    if canonical_ip(name) is not None:
        return facts
    out = []
    for f in facts:
        if f.kind == "host":
            out.append(host_fact(name, ip=f.get("host"), **f.attrs))
        elif f.kind == "service":
            attrs = {k: v for k, v in f.attrs.items()}
            out.append(service(name, f.get("port"), f.get("proto"), ip=f.get("host"), **attrs))
        else:
            out.append(f)
    return out
