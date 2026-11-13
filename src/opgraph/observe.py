"""Make tool output safe to show an LLM: strip terminal junk, cap size, mark as untrusted data."""

from __future__ import annotations

import re
import secrets

_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")  # window titles, hyperlinks
_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")  # colours, cursor movement
_OTHER_ESC = re.compile(r"\x1b[@-Z\\-_]?")
# C0/C1 controls except \t and \n, plus bidi overrides and zero-width characters that can hide text.
_INVISIBLE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
_TAG = re.compile(r"<(/?)untrusted-data", re.IGNORECASE)


def sanitize(text: str) -> str:
    """Remove ANSI/OSC escapes and invisible characters; resolve carriage-return progress lines."""
    text = _OSC.sub("", text)
    text = _CSI.sub("", text)
    text = _OTHER_ESC.sub("", text)
    text = text.replace("\r\n", "\n")
    # A terminal shows only what follows the last \r on a line (progress bars).
    text = "\n".join(line.rsplit("\r", 1)[-1] for line in text.split("\n"))
    return _INVISIBLE.sub("", text)


def cap(text: str, limit: int) -> str:
    """Keep the head and tail of long text, with a marker saying how much was cut."""
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    omitted = len(text) - head - tail
    return f"{text[:head]}\n[... {omitted} chars omitted ...]\n{text[-tail:] if tail else ''}"


def untrusted(text: str, limit: int = 6000, nonce: str | None = None) -> str:
    """Sanitize, cap and wrap target-controlled text.

    The closing tag carries a random nonce, so content cannot fake the end of the block.
    """
    nonce = nonce or secrets.token_hex(4)
    body = _TAG.sub(r"<\1untrusted_data", cap(sanitize(text), limit))
    return f'<untrusted-data id="{nonce}">\n{body}\n</untrusted-data id="{nonce}">'


def clean_value(value: object, limit: int = 80) -> str:
    """One-line, length-limited form of a target-derived value, for the world view."""
    text = " ".join(sanitize(str(value)).split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text
