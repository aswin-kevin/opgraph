"""Render the fact graph as compact text for an LLM, within a token budget."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable

from .facts import Fact, FactStore
from .observe import clean_value
from .technique import Technique

_KIND_ORDER = ["host", "service", "tech", "endpoint", "credential", "artifact", "finding", "note"]
_HIDDEN_ATTRS = {"secret", "text", "status", "rationale", "evidence"}


def format_fact(fact: Fact, params: Iterable[Fact] = ()) -> str:
    """One line describing a fact.

    Every value is cleaned to a single line; target-derived values that contain anything beyond
    plain URL/identifier characters are JSON-quoted, so target text can never pose as structure
    or instructions in the world view.
    """
    u = fact.target_derived

    def part(name: str) -> str:
        return _value(fact.get(name), u)

    k = fact.kind
    if k == "host":
        head = f"HOST {part('host')}"
    elif k == "service":
        head = f"SVC {part('port')}/{part('proto')}"
    elif k == "endpoint":
        status = fact.attrs.get("status")
        head = f"EP {part('url')}" + (f" [{_value(status, u)}]" if status is not None else "")
    elif k == "tech":
        head = f"TECH {part('name')}"
    elif k == "credential":
        head = f"CRED {part('username')} @ {part('service')}"
    elif k == "finding":
        status = _value(fact.attrs.get("status", "proposed"), u)
        head = f"FINDING [{status}] {part('vuln_class')} {part('target')}"
    elif k == "artifact":
        head = f"ARTIFACT {part('name')} on {part('target')}"
    elif k == "note":
        return f"NOTE {clean_value(fact.attrs.get('text', ''), 200)}"
    else:
        head = " ".join([_value(k.upper(), True), *(_value(p, u) for p in fact.key)])

    parts = [head]
    for name, value in fact.attrs.items():
        if name in _HIDDEN_ATTRS or (k == "endpoint" and name == "status"):
            continue
        if _SAFE.fullmatch(name):
            parts.append(f"{name}={_value(value, u)}")
    names = [f"{_value(p.get('location'), True)}:{_value(p.get('name'), True)}" for p in params]
    if names:
        parts.append("params=" + ",".join(sorted(names)))
    if k == "finding" and fact.attrs.get("evidence"):
        parts.append(f"evidence={_value(fact.attrs['evidence'], True, force_quotes=True)}")
    if fact.confidence != "high":
        parts.append(f"({fact.confidence} confidence)")
    return " ".join(parts)


# Characters that cannot form sentences or markup: URLs, paths, identifiers, versions.
_SAFE = re.compile(r"[A-Za-z0-9_.:/\-\[\]@%?=&+~#{}]*")


def _value(value: object, untrusted: bool, force_quotes: bool = False) -> str:
    if isinstance(value, bool | int | float):
        return str(value)
    text = clean_value(value)
    if force_quotes or (untrusted and not _SAFE.fullmatch(text)):
        return json.dumps(text)
    return text


def world(
    store: FactStore,
    techniques: Iterable[Technique] = (),
    budget_tokens: int = 1500,
    extra: Iterable[str] = (),
) -> str:
    """The world view: the fact graph as an indented tree, then the actions currently available.

    Budget is approximate (4 chars per token). Actions are always shown; facts are cut first.
    """
    techniques = list(techniques)
    footer = "\n".join([*extra, _actions(store, techniques)])
    budget_chars = max(budget_tokens * 4 - len(footer), 200)

    body = _tree_lines(store)
    out: list[str] = []
    used = 0
    for i, line in enumerate(body):
        if used + len(line) + 1 > budget_chars:
            out.append(f"[... {len(body) - i} more lines not shown: query specific facts ...]")
            break
        out.append(line)
        used += len(line) + 1
    facts_text = "\n".join(out) if out else "(no facts yet)"
    return f"KNOWN FACTS ({len(store)}):\n{facts_text}\n\n{footer}"


def _tree_lines(store: FactStore) -> list[str]:
    facts = list(store)
    ids = {f.id for f in facts}
    children: dict[str | None, list[Fact]] = defaultdict(list)
    for f in facts:
        children[f.parent if f.parent in ids else None].append(f)

    def order(f: Fact) -> tuple[int, str]:
        rank = _KIND_ORDER.index(f.kind) if f.kind in _KIND_ORDER else len(_KIND_ORDER)
        return rank, f.id

    lines: list[str] = []

    def walk(parent: str | None, depth: int) -> None:
        for f in sorted(children.get(parent, []), key=order):
            if f.kind == "param" and parent is not None:
                continue  # shown on the endpoint line
            params = [c for c in children.get(f.id, []) if c.kind == "param"]
            lines.append("  " * depth + format_fact(f, params))
            walk(f.id, depth + 1)

    walk(None, 0)
    return lines


def _actions(store: FactStore, techniques: list[Technique]) -> str:
    ready = [t for t in techniques if t.is_available(store)]
    locked = [t.name for t in techniques if t not in ready]
    lines = ["AVAILABLE ACTIONS:"]
    lines += [f"- {t.name} ({t.risk}): {t.description}" for t in ready] or ["- (none)"]
    if locked:
        lines.append("LOCKED (preconditions not met yet): " + ", ".join(locked))
    return "\n".join(lines)
