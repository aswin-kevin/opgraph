"""Vault: secrets stay out of the model's context; it only ever sees handles like {{cred:1}}."""

from __future__ import annotations

import re
import threading
from typing import Any

_HANDLE = re.compile(r"\{\{cred:(\d+)\}\}")
_MIN_REDACT_LENGTH = 4  # shorter secrets would redact ordinary text


class Vault:
    """Thread-safe store of secrets addressed by handles.

    Operators can preload credentials (``eng.vault.store("s3cret")`` returns ``{{cred:1}}``) and tell
    the agent the handle; credentials found by techniques are stored automatically.
    """

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._lock = threading.Lock()

    def store(self, secret: str) -> str:
        """Keep a secret and return its handle (the same handle for the same secret)."""
        with self._lock:
            for number, known in self._secrets.items():
                if known == secret:
                    return handle(number)
            number = str(len(self._secrets) + 1)
            self._secrets[number] = secret
        return handle(number)

    def resolve(self, value: Any) -> Any:
        """Replace handles with real secrets in strings, lists and dicts (unknown handles stay)."""
        if isinstance(value, str):
            with self._lock:
                secrets = dict(self._secrets)
            return _HANDLE.sub(lambda m: secrets.get(m.group(1), m.group(0)), value)
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        return value

    def redact(self, value: Any) -> Any:
        """Replace known secrets with their handles in strings, lists, tuples and dicts."""
        with self._lock:
            pairs = [(s, handle(n)) for n, s in self._secrets.items() if len(s) >= _MIN_REDACT_LENGTH]
        return _replace_all(value, pairs) if pairs else value

    def __len__(self) -> int:
        with self._lock:
            return len(self._secrets)


def handle(number: str) -> str:
    return "{{cred:" + number + "}}"


def _replace_all(value: Any, pairs: list[tuple[str, str]]) -> Any:
    if isinstance(value, str):
        for old, new in pairs:
            value = value.replace(old, new)
        return value
    if isinstance(value, list | tuple):
        return type(value)(_replace_all(v, pairs) for v in value)
    if isinstance(value, dict):
        return {k: _replace_all(v, pairs) for k, v in value.items()}
    return value
