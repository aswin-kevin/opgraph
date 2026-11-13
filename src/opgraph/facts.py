"""Facts: typed, deduplicated knowledge with provenance, linked into a graph.

A fact's identity is ``kind:key``. Re-adding the same fact merges attributes instead of duplicating.
Each fact may name a ``parent`` fact (service -> host, endpoint -> service, ...); those links form the
operations graph that the world view and evidence chains are built from.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

from .targets import base_url, normalize_url, parse_target

# Names for the parts of each built-in kind's key, so `fact.get("port")` and
# `store.query("service", port=80)` work. Custom kinds simply have positional keys.
KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("host",),
    "service": ("host", "port", "proto"),
    "endpoint": ("url",),
    "param": ("url", "location", "name"),
    "tech": ("base_url", "name"),
    "credential": ("service", "username"),
    "finding": ("vuln_class", "target"),
    "artifact": ("target", "name"),
    "note": ("id",),
}
_BUILTIN_KINDS = frozenset(KEY_FIELDS)

Confidence = str  # "high" | "medium" | "low"


def define_kind(kind: str, key_fields: tuple[str, ...]) -> None:
    """Name the key parts of a custom fact kind, so `fact.get(...)` and `store.query(...)` can use
    them, e.g. ``define_kind("vhost", ("ip", "name"))`` then ``store.query("vhost", name="dev")``.

    Kinds are open strings: facts of an undefined kind work too, with positional keys only.
    Definitions are process-wide (like a schema); built-in kinds cannot be redefined and a custom
    kind cannot be redefined with different fields.
    """
    if kind in _BUILTIN_KINDS:
        raise ValueError(f"{kind!r} is a built-in kind")
    if not key_fields or not all(isinstance(f, str) and f for f in key_fields):
        raise ValueError("key_fields must be a non-empty tuple of names")
    existing = KEY_FIELDS.get(kind)
    if existing is not None and existing != tuple(key_fields):
        raise ValueError(f"{kind!r} is already defined with key fields {existing}")
    KEY_FIELDS[kind] = tuple(key_fields)


@dataclass(frozen=True, eq=False)
class Fact:
    kind: str
    key: tuple[Any, ...]
    attrs: Mapping[str, Any] = field(default_factory=dict)
    parent: str | None = None  # id of the parent fact, if any
    source: str = "unknown"  # technique or parser that produced it
    call_id: str | None = None  # call that produced it
    target_derived: bool = True  # built from bytes the target controls (taint)
    confidence: Confidence = "high"
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", tuple(self.key))
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))

    @property
    def id(self) -> str:
        return f"{self.kind}:" + "|".join(str(part) for part in self.key)

    def get(self, name: str, default: Any = None) -> Any:
        """Look up a named key part first, then an attribute."""
        names = KEY_FIELDS.get(self.kind, ())
        if name in names:
            return self.key[names.index(name)]
        return self.attrs.get(name, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key": list(self.key),
            "attrs": dict(self.attrs),
            "parent": self.parent,
            "source": self.source,
            "call_id": self.call_id,
            "target_derived": self.target_derived,
            "confidence": self.confidence,
            "ts": self.ts,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Fact:
        return cls(
            kind=data["kind"],
            key=tuple(data["key"]),
            attrs=data.get("attrs", {}),
            parent=data.get("parent"),
            source=data.get("source", "unknown"),
            call_id=data.get("call_id"),
            target_derived=data.get("target_derived", True),
            confidence=data.get("confidence", "high"),
            ts=data.get("ts", time.time()),
        )

    def __repr__(self) -> str:
        return f"Fact({self.id!r}, {dict(self.attrs)!r})"


# ---- constructors for the built-in kinds ----------------------------------------------------------


def host(name: str, **attrs: Any) -> Fact:
    """A host, by IP or hostname."""
    return Fact("host", (parse_target(name).host,), attrs)


def service(host_name: str, port: int, proto: str = "tcp", **attrs: Any) -> Fact:
    h = parse_target(host_name).host
    return Fact("service", (h, int(port), proto), attrs, parent=f"host:{h}")


def endpoint(url: str, **attrs: Any) -> Fact:
    """A URL without query string. Parent is the service it is served from."""
    url = normalize_url(url)
    t = parse_target(url)
    return Fact("endpoint", (url,), attrs, parent=f"service:{t.host}|{t.port}|tcp")


def param(url: str, location: str, name: str, **attrs: Any) -> Fact:
    """An input: location is one of query, body, header, cookie, path."""
    url = normalize_url(url)
    return Fact("param", (url, location, name), attrs, parent=f"endpoint:{url}")


def tech(url: str, name: str, **attrs: Any) -> Fact:
    base = base_url(url)
    t = parse_target(base)
    return Fact("tech", (base, name.lower()), attrs, parent=f"service:{t.host}|{t.port}|tcp")


def credential(target: str, username: str, secret: str | None = None, **attrs: Any) -> Fact:
    """A credential for a service or URL. The secret is moved to a vault by the Engagement and
    replaced with a handle, so it never appears in rendered context or logs."""
    t = parse_target(target)
    svc = f"{t.host}|{t.port}|tcp" if t.port else t.host
    if secret is not None:
        attrs["secret"] = secret
    parent = f"service:{svc}" if t.port else f"host:{t.host}"
    return Fact("credential", (svc, username), attrs, parent=parent)


def finding(vuln_class: str, target: str, **attrs: Any) -> Fact:
    """A claimed weakness. Starts as `proposed`; only verified evidence makes it `confirmed`."""
    attrs.setdefault("status", "proposed")
    parent = None
    if "://" in target:
        parent = f"endpoint:{normalize_url(target)}"
    return Fact("finding", (vuln_class, target), attrs, parent=parent)


def artifact(target: str, name: str, **attrs: Any) -> Fact:
    """Something an action created on a target (file, account, process) that must be cleaned up."""
    return Fact("artifact", (target, name), attrs)


def note(text: str, **attrs: Any) -> Fact:
    """Free text written by the agent itself (not target-derived)."""
    digest = hashlib.sha256(text.encode()).hexdigest()[:12]
    return Fact("note", (digest,), {"text": text, **attrs}, target_derived=False)


# ---- the store ------------------------------------------------------------------------------------

Listener = Callable[[str, Fact], None]  # (event, fact) where event is "new" or "updated"


class FactStore:
    """Thread-safe store of facts keyed by id."""

    def __init__(self) -> None:
        self._facts: dict[str, Fact] = {}
        self._listeners: list[Listener] = []
        self._lock = threading.RLock()

    def add(self, facts: Iterable[Fact]) -> list[Fact]:
        """Add facts; return only the ones that were new. Existing facts get attributes merged
        (newer non-empty values win, nothing is deleted)."""
        new: list[Fact] = []
        events: list[tuple[str, Fact]] = []
        with self._lock:
            for fact in facts:
                old = self._facts.get(fact.id)
                if old is None:
                    self._facts[fact.id] = fact
                    new.append(fact)
                    events.append(("new", fact))
                    continue
                merged = _merge(old, fact)
                if merged is not old:
                    self._facts[fact.id] = merged
                    events.append(("updated", merged))
            listeners = list(self._listeners)
        for event, fact in events:
            for listener in listeners:
                listener(event, fact)
        return new

    def get(self, fact_id: str) -> Fact | None:
        with self._lock:
            return self._facts.get(fact_id)

    def query(self, kind: str | None = None, **where: Any) -> list[Fact]:
        """Facts of a kind whose named key parts or attributes equal the given values."""
        with self._lock:
            facts = list(self._facts.values())
        return [
            f
            for f in facts
            if (kind is None or f.kind == kind)
            and all(f.get(name, _MISSING) == value for name, value in where.items())
        ]

    def children(self, fact_id: str) -> list[Fact]:
        with self._lock:
            return [f for f in self._facts.values() if f.parent == fact_id]

    def chain(self, fact_id: str) -> list[Fact]:
        """The fact and its ancestors, root first (e.g. host -> service -> endpoint -> finding)."""
        out: list[Fact] = []
        seen: set[str] = set()
        current = self.get(fact_id)
        while current is not None and current.id not in seen:
            out.append(current)
            seen.add(current.id)
            current = self.get(current.parent) if current.parent else None
        return out[::-1]

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        """Call `listener(event, fact)` on every new or updated fact. Returns an unsubscribe function."""
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def to_jsonl(self) -> str:
        return "".join(json.dumps(f.to_dict(), default=str) + "\n" for f in self)

    def __iter__(self) -> Iterator[Fact]:
        with self._lock:
            return iter(list(self._facts.values()))

    def __len__(self) -> int:
        with self._lock:
            return len(self._facts)

    def __contains__(self, fact_id: object) -> bool:
        with self._lock:
            return fact_id in self._facts


_MISSING = object()


def _merge(old: Fact, new: Fact) -> Fact:
    updates = {k: v for k, v in new.attrs.items() if v not in (None, "") and old.attrs.get(k) != v}
    parent = old.parent or new.parent
    if not updates and parent == old.parent:
        return old
    return replace(old, attrs={**old.attrs, **updates}, parent=parent)
