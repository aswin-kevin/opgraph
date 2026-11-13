"""Built-in checks for `Engagement.verify`: deterministic proof, never the model's opinion."""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING
from urllib.parse import unquote

from .facts import Fact
from .targets import TargetError, parse_target

if TYPE_CHECKING:
    from .engagement import Engagement, Evidence


class RegexCheck:
    """Confirms a finding when a pattern appears in any observation (e.g. a captured flag or a
    database error string). Evidence records the call and the matched text."""

    def __init__(self, pattern: str, name: str = "regex", flags: int = 0):
        self.pattern = re.compile(pattern, flags)
        self.name = name

    def __call__(self, eng: Engagement, finding: Fact) -> Evidence | None:
        from .engagement import Evidence

        for call_id, text in eng.observations():
            match = self.pattern.search(text)
            if match:
                return Evidence(self.name, f"{call_id}: {match.group(0)[:200]}")
        return None


class CanaryCheck:
    """Confirms a finding when a canary token (from `Engagement.canary`) comes back from the
    finding's host in output the agent did not produce: stored input rendered later, a file read
    back, an out-of-band hit. It proves the token was stored and returned, nothing more.

    Ignored: output of raw-shell calls (the agent controls it), output of calls whose own arguments
    carried the token in any common encoding (plain reflection, unless `allow_reflection`), and
    output from other hosts. `techniques` restricts which techniques' output may count.
    `sources` are callables returning texts from outside the engagement, e.g. an out-of-band
    DNS/HTTP listener's log.
    """

    def __init__(
        self,
        token: str,
        *,
        allow_reflection: bool = False,
        techniques: Iterable[str] | None = None,
        sources: Iterable[Callable[[], Iterable[str]]] = (),
        name: str = "canary",
    ):
        if len(token) < 12:
            raise ValueError("token too short to be unguessable; use Engagement.canary()")
        self.token = token
        self.allow_reflection = allow_reflection
        self.techniques = frozenset(techniques) if techniques is not None else None
        self.sources = list(sources)
        self.name = name

    def __call__(self, eng: Engagement, finding: Fact) -> Evidence | None:
        from .engagement import Evidence

        host = _host_of(str(finding.key[1])) if len(finding.key) > 1 else None
        calls = {e["call_id"]: e for e in list(eng.ledger.events) if e["event"] == "call"}
        for call_id, text in eng.observations():
            call = calls.get(call_id)
            if call is None or self.token not in text or not self._counts(call, host):
                continue
            return Evidence(self.name, f"{call_id} ({call.get('technique')}): canary returned in output")
        for source in self.sources:
            if any(self.token in str(text) for text in source()):
                return Evidence(self.name, f"canary seen by {getattr(source, '__name__', 'external source')}")
        return None

    def _counts(self, call: dict, host: str | None) -> bool:
        if call.get("risk") == "raw_shell":
            return False
        if self.techniques is not None and call.get("technique") not in self.techniques:
            return False
        if host is not None and host not in {str(h).lower() for h in call.get("hosts") or ()}:
            return False
        return self.allow_reflection or not carries_token(
            json.dumps(call.get("args"), default=str), self.token
        )


def carries_token(text: str, token: str) -> bool:
    """Whether text contains the token literally or in a common encoding (case-insensitive)."""
    variants = {text, unquote(text), unquote(unquote(text)), html.unescape(text)}
    for chunk in re.findall(r"[A-Za-z0-9+/_-]{16,}={0,2}", text):
        variants.add(_hex(chunk))
        for offset in range(4):  # the run may be glued to other letters: try every alignment
            variants.add(_b64(chunk[offset:]))
    needle = token.lower()
    return any(needle in v.lower() for v in variants)


def _b64(chunk: str) -> str:
    try:
        return base64.b64decode(chunk + "=" * (-len(chunk) % 4), altchars=b"-_").decode("latin-1")
    except (binascii.Error, ValueError):
        return ""


def _hex(chunk: str) -> str:
    try:
        return bytes.fromhex(chunk).decode("latin-1")
    except ValueError:
        return ""


def _host_of(target: str) -> str | None:
    try:
        return parse_target(target).host
    except TargetError:
        return None
