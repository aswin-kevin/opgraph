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

WORDLISTS = {
    "small": "/usr/share/wordlists/dirb/small.txt",
    "common": "/usr/share/wordlists/dirb/common.txt",
    "big": "/usr/share/wordlists/dirb/big.txt",
}
_SESSION = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


@technique(risk="intrusive", attack="T1595", timeout=60)
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
    max_time = max(ctx.technique.timeout - 5, 5)
    argv = ["curl", "-sS", "-i", "-k", "--path-as-is", "--max-time", str(max_time)]
    argv += ["--connect-timeout", "10", "-X", method, "-b", jar, "-c", jar]
    argv += curl_pin(ctx.targets["url"])
    for name, value in (headers or {}).items():
        if not _HEADER_NAME.match(name) or "\r" in value or "\n" in value:
            raise ValueError(f"invalid header: {name!r}")
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


def _has_web(facts: FactStore) -> list:
    web = [s for s in facts.query("service") if str(s.get("name", "")).startswith("http")]
    return web or facts.query("endpoint")


@technique(risk="intrusive", attack="T1595.003", needs=_has_web, timeout=300)
def dir_discovery(
    ctx: Ctx,
    base_url: Url,
    wordlist: Literal["small", "common", "big"] = "common",
    extensions: Annotated[str, "comma-separated extensions to also try, e.g. 'php,txt'"] = "",
) -> TechniqueResult:
    """Discover files and directories under a base URL with ffuf (gentle rate). Yields endpoint facts."""
    if extensions and not re.fullmatch(r"[A-Za-z0-9]{1,8}(,[A-Za-z0-9]{1,8}){0,9}", extensions):
        raise ValueError("extensions must look like 'php,txt'")
    if "FUZZ" in base_url:
        raise ValueError("base_url must not contain the ffuf keyword FUZZ; it is appended automatically")
    base = normalize_url(base_url).rstrip("/")  # lowercased host, no query: what scope checked
    target, host_header = pinned_url(base + "/FUZZ", ctx.targets["base_url"])
    argv = ["ffuf", "-u", target, "-w", WORDLISTS[wordlist], "-json", "-s", "-noninteractive"]
    max_time = max(ctx.technique.timeout - 10, 10)
    argv += ["-t", "10", "-rate", "50", "-maxtime", str(max_time), "-timeout", "10"]
    argv += ["-mc", "200,201,204,301,302,307,308,401,403,405,500"]
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
