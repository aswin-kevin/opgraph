"""Web techniques: http_request (the workhorse) and dir_discovery."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from .. import parsers
from ..engagement import Ctx
from ..facts import Fact, FactStore, endpoint
from ..targets import base_url as origin_of
from ..targets import normalize_url
from ..technique import Secret, TechniqueResult, Url, technique
from ._pinning import curl_pin, pinned_url

# Default wordlists (Kali paths). Override or extend with Engagement(config={"wordlists": {...}}).
DEFAULT_WORDLISTS = {
    "small": "/usr/share/wordlists/dirb/small.txt",
    "common": "/usr/share/wordlists/dirb/common.txt",
    "big": "/usr/share/wordlists/dirb/big.txt",
}
_SESSION = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


def _unrequested(fact: Fact) -> dict | None:
    """Endpoints known from links, forms or scans but never fetched are worth a request."""
    if fact.kind == "endpoint" and fact.get("status") is None:
        return {"url": fact.get("url")}
    return None


def _web_root(fact: Fact) -> dict | None:
    if fact.kind == "service" and str(fact.get("name", "")).startswith("http"):
        scheme = "https" if fact.get("name") == "https" or fact.get("tls") else "http"
        host = fact.get("host")
        host = f"[{host}]" if ":" in str(host) else host
        return {"base_url": origin_of(f"{scheme}://{host}:{fact.get('port')}")}
    if fact.kind == "endpoint" and urlsplit(str(fact.get("url"))).path == "/":
        return {"base_url": origin_of(str(fact.get("url")))}
    return None


@technique(risk="intrusive", attack="T1595", timeout=60, suggest=_unrequested)
def http_request(
    ctx: Ctx,
    url: Url,
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET",
    headers: Annotated[dict[str, str] | None, Secret] = None,
    body: Annotated[str, "raw request body; set Content-Type in headers", Secret] = "",
    session: Annotated[
        str, "cookie jar name; cookies persist across calls with the same session"
    ] = "default",
) -> TechniqueResult:
    """Send one HTTP request and show the raw response (status, headers, body).

    Redirects are not followed: a Location header becomes a fact you can request next (it is scope-checked).
    """
    if not _SESSION.match(session):
        raise ValueError("session must be 1-32 letters, digits, '-' or '_'")
    jar = f"{ctx.workdir()}/cookies-{session}.txt"
    max_time = max(ctx.timeout - 5, 5)
    argv = [ctx.tool("curl"), "-sS", "-i", "-k", "--path-as-is", "--max-time", str(max_time)]
    argv += ["--connect-timeout", "10", "-X", method, "-b", jar, "-c", jar]
    argv += curl_pin(ctx.targets["url"]) + proxy_args(ctx, "-x")
    for name, value in merge_headers(configured_headers(ctx), _checked_headers(headers or {})).items():
        argv += ["-H", f"{name}: {value}"]
    if method == "HEAD":
        argv[argv.index("-X") : argv.index("-X") + 2] = ["-I"]
    if body:
        argv += ["--data-binary", "@-"]
    argv += ["--", url]

    result = ctx.exec(argv, stdin=body or None)
    if result.rc != 0 and not result.stdout:
        return TechniqueResult(observation=f"request failed (curl rc={result.rc}): {result.stderr.strip()}")
    return TechniqueResult(observation=result.stdout, facts=parsers.http_response(result.stdout, url))


def configured_headers(ctx: Ctx) -> dict[str, str]:
    """Headers every web request must carry, from ``config["http_headers"]`` (e.g. a bug-bounty
    program's identification header)."""
    return _checked_headers(ctx.config.get("http_headers", {}))


def merge_headers(mandatory: dict[str, str], requested: dict[str, str]) -> dict[str, str]:
    """Requested headers plus the mandatory ones; mandatory headers win (case-insensitively), so a
    model cannot drop or change an operator-required header."""
    taken = {name.lower() for name in mandatory}
    return {**{k: v for k, v in requested.items() if k.lower() not in taken}, **mandatory}


def proxy_args(ctx: Ctx, flag: str) -> list[str]:
    """Route traffic through ``config["http_proxy"]`` (e.g. Burp). The proxy then resolves names."""
    proxy = ctx.config.get("http_proxy")
    return [flag, str(proxy)] if proxy else []


def _checked_headers(headers: dict[str, str]) -> dict[str, str]:
    for name, value in headers.items():
        if not _HEADER_NAME.match(str(name)) or not isinstance(value, str) or "\r" in value or "\n" in value:
            raise ValueError(f"invalid header: {name!r}")
    return dict(headers)


def _bounded(value: object, low: int, high: int, name: str) -> int:
    number = int(value)  # type: ignore[arg-type]
    if not low <= number <= high:
        raise ValueError(f"{name} option must be between {low} and {high}")
    return number


def has_web(facts: FactStore) -> list:
    """Precondition: a known HTTP(S) service or endpoint."""
    web = [s for s in facts.query("service") if str(s.get("name", "")).startswith("http")]
    return web or facts.query("endpoint")


@technique(risk="intrusive", attack="T1595.003", needs=has_web, timeout=300, suggest=_web_root)
def dir_discovery(
    ctx: Ctx,
    base_url: Url,
    wordlist: Annotated[
        str, "small, common, big, or a name from the engagement's wordlist config"
    ] = "common",
    extensions: Annotated[str, "comma-separated extensions to also try, e.g. 'php,txt'"] = "",
) -> TechniqueResult:
    """Discover files and directories under a base URL with ffuf (gentle rate). Yields endpoint facts."""
    if extensions and not re.fullmatch(r"[A-Za-z0-9]{1,8}(,[A-Za-z0-9]{1,8}){0,9}", extensions):
        raise ValueError("extensions must look like 'php,txt'")
    if "FUZZ" in base_url:
        raise ValueError("base_url must not contain the ffuf keyword FUZZ; it is appended automatically")
    base = normalize_url(base_url).rstrip("/")  # lowercased host, no query: what scope checked
    wordlists = {**DEFAULT_WORDLISTS, **ctx.config.get("wordlists", {})}
    if wordlist not in wordlists:
        raise ValueError(f"unknown wordlist {wordlist!r}; available: {sorted(wordlists)}")
    threads = _bounded(ctx.options.get("threads", 10), 1, 200, "threads")
    rate = _bounded(ctx.options.get("rate", 50), 1, 10_000, "rate")
    match_codes = str(ctx.options.get("match_codes", "200,201,204,301,302,307,308,401,403,405,500"))
    if not re.fullmatch(r"(all|\d{3}(,\d{3})*)", match_codes):
        raise ValueError("match_codes option must look like '200,301' or 'all'")
    target, host_header = pinned_url(base + "/FUZZ", ctx.targets["base_url"])
    argv = [ctx.tool("ffuf"), "-u", target, "-w", str(wordlists[wordlist]), "-json", "-s", "-noninteractive"]
    max_time = max(ctx.timeout - 10, 10)
    argv += ["-t", str(threads), "-rate", str(rate), "-maxtime", str(max_time), "-timeout", "10"]
    argv += ["-mc", match_codes, *proxy_args(ctx, "-x")]
    for name, value in configured_headers(ctx).items():
        argv += ["-H", f"{name}: {value}"]
    if host_header:
        argv += ["-H", f"Host: {host_header}"]
    if extensions:
        argv += ["-e", ",".join("." + e for e in extensions.split(","))]

    result = ctx.exec(argv)
    facts = parsers.ffuf_json(result.stdout)
    if host_header:  # report URLs under the name the agent used, not the pinned IP
        facts = _restore_origin(facts, base)
    lines = [f"{f.get('url')} [{f.get('status')}] length={f.get('length')}" for f in facts]
    summary = f"{len(facts)} paths found with wordlist '{wordlist}'"
    if result.timed_out:
        summary += " (stopped at time limit)"
    if not result.ok and not facts:
        summary += f"\nffuf error: {result.stderr.strip()[:500]}"
    return TechniqueResult(observation="\n".join([summary, *lines]), facts=facts)


def _restore_origin(facts: list[Fact], original_url: str) -> list[Fact]:
    origin = origin_of(original_url)
    return [endpoint(origin + urlsplit(f.get("url")).path, **f.attrs) for f in facts]
