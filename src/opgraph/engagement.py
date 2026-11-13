"""Engagement: ties scope, policy, techniques, facts, cleanup and the event log together.

Every tool call from any agent framework goes through `Engagement.call(name, args)`, which:
    1. finds the technique and validates arguments against its signature
    2. checks preconditions (`needs`) against known facts
    3. checks every Target-typed argument against the scope (pinned IPs)
    4. asks the policy (allow / approve / deny) based on risk
    5. runs the technique, records coverage and events
    6. stores resulting facts, registers cleanup for artifacts
    7. returns a sanitized, capped observation plus the new facts
Blocked calls never raise; they return a result explaining why.
"""

from __future__ import annotations

import itertools
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, get_args, get_origin

from .effects import EffectStack
from .executors import ExecResult, Executor, LocalExecutor
from .facts import Fact, FactStore, finding
from .ledger import Ledger, read_events
from .observe import sanitize, untrusted
from .policy import ApprovalRequest, Policy
from .render import format_fact, world
from .scope import CheckedTarget, OutOfScope, Scope
from .technique import Host, Technique, TechniqueResult, Url, _strip, collect, target_type

_SECRET_REF = re.compile(r"\{\{cred:(\d+)\}\}")
_MAX_LOGGED_OBSERVATION = 50_000


@dataclass
class CallResult:
    technique: str
    call_id: str
    ok: bool
    text: str = ""  # sanitized, capped observation (or error message)
    new_facts: list[Fact] = field(default_factory=list)
    blocked: str | None = None  # reason, if the call never ran

    def to_tool_text(self) -> str:
        """The text adapters hand back to the model."""
        if self.blocked:
            return f"[blocked] {self.technique} call={self.call_id} reason={self.blocked}"
        status = "ok" if self.ok else "error"
        parts = [f"[{status}] {self.technique} call={self.call_id}"]
        if self.text:
            parts.append(self.text)
        if self.new_facts:
            parts.append(f"NEW FACTS ({len(self.new_facts)}):")
            parts.extend(f"  {format_fact(f)}" for f in self.new_facts[:50])
            if len(self.new_facts) > 50:
                parts.append(f"  [... {len(self.new_facts) - 50} more; call world to see all ...]")
        return "\n".join(parts)


@dataclass
class Evidence:
    check: str  # name of the check that produced it
    detail: str  # short human-readable proof


Check = Callable[["Engagement", Fact], Evidence | None]


class Ctx:
    """What a technique gets as its first argument (`ctx`)."""

    def __init__(
        self, eng: Engagement, technique: Technique, call_id: str, targets: dict[str, CheckedTarget]
    ):
        self._eng = eng
        self.technique = technique
        self.call_id = call_id
        self.targets = targets  # checked target per Target-typed argument (with pinned IP)

    @property
    def facts(self) -> FactStore:
        return self._eng.facts

    @property
    def scope(self) -> Scope:
        return self._eng.scope

    def exec(self, argv: list[str], timeout: int | None = None, stdin: str | None = None) -> ExecResult:
        """Run argv on the engagement's executor. Never pass a shell string."""
        result = self._eng.executor.run(argv, timeout or self.technique.timeout, stdin)
        self._eng.ledger.record(
            "exec",
            call_id=self.call_id,
            argv=self._eng._redact(argv),
            rc=result.rc,
            duration=round(result.duration, 3),
            timed_out=result.timed_out,
        )
        return result

    def workdir(self) -> str:
        """A private temp directory on the executor, removed when the engagement is disposed."""
        return self._eng.workdir()

    def defer(self, label: str, undo: Callable[[], object]) -> None:
        """Register cleanup for something this call created."""
        self._eng.effects.push(label, undo)

    def log(self, message: str) -> None:
        self._eng.ledger.record("log", call_id=self.call_id, message=message)


class Engagement:
    def __init__(
        self,
        scope: Scope,
        *,
        techniques: Iterable[Any] = (),
        policy: Policy | None = None,
        executor: Executor | None = None,
        name: str = "engagement",
        log_path: str | Path | None = None,
        observation_cap: int = 6000,
    ):
        self.name = name
        self.scope = scope
        self.policy = policy or Policy.safe()
        self.executor: Executor = executor or LocalExecutor()
        self.facts = FactStore()
        self.ledger = Ledger(log_path)
        self.effects = EffectStack()
        self.observation_cap = observation_cap
        self.techniques: dict[str, Technique] = {}
        self._vault: dict[str, str] = {}  # handle number -> secret
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._workdir_lock = threading.Lock()
        self._workdir: str | None = None
        self.started = time.time()
        self.facts.subscribe(self._log_fact)
        self.ledger.record("start", name=name, scope=scope.to_dict())
        self.add(*techniques)

    def _log_fact(self, event: str, fact: Fact) -> None:
        self.ledger.record("fact", change=event, fact=fact.to_dict())

    # ---- registration --------------------------------------------------------------------------

    def add(self, *items: Any) -> None:
        """Register techniques (functions, Technique objects, modules, or lists of those)."""
        for t in collect(*items):
            if t.name in self.techniques and self.techniques[t.name] is not t:
                raise ValueError(f"duplicate technique name: {t.name}")
            self.techniques[t.name] = t

    def available(self) -> list[Technique]:
        """Techniques whose preconditions currently hold."""
        return [t for t in self.techniques.values() if t.is_available(self.facts)]

    # ---- the call path -------------------------------------------------------------------------

    def call(self, name: str, args: dict[str, Any] | None = None) -> CallResult:
        """Run one technique call. Never raises: blocked calls and failures come back as results."""
        call_id = self._next_id()
        try:
            return self._call(name, dict(args or {}), call_id)
        except Exception as exc:  # last line of defence; the agent loop must keep running
            message = self._redact(f"internal error: {type(exc).__name__}: {exc}")
            self.ledger.record("error", call_id=call_id, technique=name, error=message)
            return CallResult(name, call_id, ok=False, text=message)

    def _call(self, name: str, args: dict[str, Any], call_id: str) -> CallResult:
        t = self.techniques.get(name)
        if t is None:
            return self._blocked(name, call_id, args, f"unknown technique; known: {sorted(self.techniques)}")

        bound = _bind(t, args)
        if isinstance(bound, str):
            return self._blocked(name, call_id, args, f"invalid arguments: {bound}")
        if not t.is_available(self.facts):
            return self._blocked(
                name, call_id, args, "preconditions not met (call world to see what is available)"
            )

        # Resolve on the executor (where tools connect from) unless the scope brings its own resolver.
        resolver = None if self.scope.resolver else self.executor.resolve
        checked: dict[str, CheckedTarget] = {}
        for pname in t.target_params():
            value = bound.get(pname)
            if value is None:
                continue
            try:
                checked[pname] = self.scope.check(value, resolver)
            except OutOfScope as exc:
                return self._blocked(name, call_id, args, f"out_of_scope: {exc}")
        # Credential handles are swapped for real secrets only in parameters declared as Secret.
        resolved = {k: self._resolve_secrets(v) if k in t.secret_params() else v for k, v in bound.items()}

        reason = self.policy.check(ApprovalRequest(name, bound, t.risk))
        if reason:
            return self._blocked(name, call_id, args, reason)

        target = next(iter(checked.values())).target.raw if checked else ""
        self.ledger.count(name, target)
        self.ledger.record(
            "call", call_id=call_id, technique=name, args=bound, risk=str(t.risk), attack=t.attack
        )
        ctx = Ctx(self, t, call_id, checked)
        try:
            raw = t.fn(ctx, **resolved) if t.takes_ctx else t.fn(**resolved)
            result = _as_result(raw)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            self.ledger.record("error", call_id=call_id, technique=name, error=message)
            return CallResult(name, call_id, ok=False, text=self._redact(message))

        new = self._ingest(t, call_id, result)
        observation = self._redact(sanitize(result.observation))
        self.ledger.record(
            "result",
            call_id=call_id,
            new_facts=len(new),
            observation=observation[:_MAX_LOGGED_OBSERVATION],
        )
        text = untrusted(observation, self.observation_cap) if observation.strip() else ""
        return CallResult(name, call_id, ok=True, text=text, new_facts=new)

    def _blocked(self, name: str, call_id: str, args: dict[str, Any], reason: str) -> CallResult:
        reason = self._redact(reason)
        self.ledger.record("blocked", call_id=call_id, technique=name, args=self._redact(args), reason=reason)
        return CallResult(name, call_id, ok=False, blocked=reason)

    def _ingest(self, t: Technique, call_id: str, result: TechniqueResult) -> list[Fact]:
        facts = [self._prepare(f, t.name, call_id) for f in result.facts]
        artifacts = [self._prepare(f, t.name, call_id) for f in result.artifacts]
        new = self.facts.add(facts + artifacts)
        for art in artifacts:
            self.effects.push(f"{art.id} (by {t.name} {call_id})", self._undo_for(t, art, call_id))
        return new

    def _prepare(self, fact: Fact, source: str, call_id: str) -> Fact:
        attrs = dict(fact.attrs)
        if fact.kind == "credential" and "secret" in attrs:
            attrs["secret_ref"] = self._store_secret(str(attrs.pop("secret")))
        if fact.kind == "finding" and attrs.get("status") == "confirmed" and not attrs.get("evidence"):
            attrs["status"] = "proposed"  # no finding without evidence
        source = fact.source if fact.source != "unknown" else source
        return replace(
            fact,
            key=self._redact(fact.key),
            attrs=self._redact(attrs),
            source=source,
            call_id=fact.call_id or call_id,
        )

    def _undo_for(self, t: Technique, art: Fact, call_id: str) -> Callable[[], object]:
        def undo() -> object:
            if t.undo is None:
                raise RuntimeError("technique declares no undo; manual cleanup required")
            result = t.undo(Ctx(self, t, call_id, {}), art)
            self.facts.add([replace(art, attrs={**art.attrs, "cleaned": True})])
            return result

        return undo

    # ---- secrets -------------------------------------------------------------------------------

    def _store_secret(self, secret: str) -> str:
        with self._lock:
            for handle, known in self._vault.items():
                if known == secret:
                    return _handle(handle)
            handle = str(len(self._vault) + 1)
            self._vault[handle] = secret
        return _handle(handle)

    def _resolve_secrets(self, value: Any) -> Any:
        if isinstance(value, str):
            return _SECRET_REF.sub(lambda m: self._vault.get(m.group(1), m.group(0)), value)
        if isinstance(value, list):
            return [self._resolve_secrets(v) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve_secrets(v) for k, v in value.items()}
        return value

    def _redact(self, value: Any) -> Any:
        """Replace known secrets with their handles in strings, lists, tuples and dicts."""
        with self._lock:
            known = [(secret, _handle(h)) for h, secret in self._vault.items() if len(secret) >= 4]
        return _replace_all(value, known) if known else value

    # ---- world, findings -----------------------------------------------------------------------

    def world(self, budget_tokens: int = 1500) -> str:
        return world(self.facts, self.techniques.values(), budget_tokens)

    def propose_finding(self, vuln_class: str, target: str, rationale: str = "") -> Fact:
        """Record a claimed weakness. It stays `proposed` until `verify` finds evidence."""
        fact = replace(finding(vuln_class, target, rationale=rationale), source="agent", target_derived=False)
        self.facts.add([fact])
        self.ledger.record("finding", id=fact.id, status="proposed", rationale=rationale)
        return self.facts.get(fact.id) or fact

    def verify(self, finding_id: str, check: Check) -> Fact:
        """Run a check; if it returns Evidence the finding becomes `confirmed`."""
        fact = self.facts.get(finding_id)
        if fact is None or fact.kind != "finding":
            raise KeyError(f"no finding {finding_id!r}")
        evidence = check(self, fact)
        name = getattr(check, "name", getattr(check, "__name__", "check"))
        if evidence is None:
            attrs = {**fact.attrs, "last_check": name}
        else:
            attrs = {
                **fact.attrs,
                "status": "confirmed",
                "evidence": evidence.detail,
                "verified_by": evidence.check,
            }
        updated = replace(fact, attrs=attrs)
        self.facts.add([updated])
        self.ledger.record(
            "finding",
            id=finding_id,
            status=attrs["status"],
            check=name,
            evidence=attrs.get("evidence"),
        )
        return self.facts.get(finding_id) or updated

    def reject(self, finding_id: str, reason: str) -> Fact:
        fact = self.facts.get(finding_id)
        if fact is None or fact.kind != "finding":
            raise KeyError(f"no finding {finding_id!r}")
        updated = replace(fact, attrs={**fact.attrs, "status": "rejected", "reason": reason})
        self.facts.add([updated])
        self.ledger.record("finding", id=finding_id, status="rejected", reason=reason)
        return updated

    def observations(self) -> Iterator[tuple[str, str]]:
        """(call_id, sanitized observation) for every successful call so far."""
        for row in list(self.ledger.events):
            if row["event"] == "result":
                yield row["call_id"], row["observation"]

    # ---- cleanup -------------------------------------------------------------------------------

    def workdir(self) -> str:
        """A private temp directory on the executor, created on first use and removed by dispose().
        It lives for the whole engagement (phases do not remove it)."""
        with self._workdir_lock:
            if self._workdir is None:
                result = self.executor.run(["mktemp", "-d", "-t", "opgraph.XXXXXXXX"], 30)
                path = result.stdout.strip()
                if not result.ok or not path.startswith("/") or "/opgraph." not in path:
                    raise RuntimeError(f"could not create workdir: {result.output.strip()}")
                self._workdir = path
                self.effects.push(f"workdir {path}", lambda: self._remove_workdir(path), root=True)
            return self._workdir

    def _remove_workdir(self, path: str) -> None:
        with self._workdir_lock:
            self._workdir = None
        result = self.executor.run(["rm", "-rf", "--", path], 60)
        if not result.ok:
            raise RuntimeError(result.output.strip())

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        """Effects created inside the block are cleaned up when it exits."""
        self.ledger.record("phase", name=name, state="enter")
        with self.effects.phase(name):
            yield
        self.ledger.record("phase", name=name, state="exit")

    def dispose(self) -> list[str]:
        """Kill switch / end of engagement: undo every owned effect, newest first."""
        lines = self.effects.dispose()
        self.ledger.record("dispose", lines=lines)
        return lines

    def close(self) -> list[str]:
        lines = self.dispose()
        self.ledger.close()
        return lines

    def __enter__(self) -> Engagement:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- reporting -----------------------------------------------------------------------------

    def report(self) -> dict[str, Any]:
        events = self.ledger.events
        by_kind: dict[str, int] = {}
        for f in self.facts:
            by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        return {
            "name": self.name,
            "duration_s": round(time.time() - self.started, 1),
            "scope": self.scope.to_dict(),
            "stats": {
                "calls": sum(1 for e in events if e["event"] == "call"),
                "blocked": sum(1 for e in events if e["event"] == "blocked"),
                "errors": sum(1 for e in events if e["event"] == "error"),
                "facts": len(self.facts),
                "facts_by_kind": by_kind,
            },
            "findings": [
                {**f.to_dict(), "chain": [c.id for c in self.facts.chain(f.id)]}
                for f in self.facts.query("finding")
            ],
            "coverage": [
                {"technique": tech, "target": target, "count": n}
                for (tech, target), n in sorted(self.ledger.coverage.items())
            ],
            "pending_cleanup": self.effects.pending(),
            "residue": self.effects.residue,
        }

    @classmethod
    def replay(cls, log_path: str | Path, scope: Scope, **kwargs: Any) -> Engagement:
        """Rebuild an engagement's facts from its event log (secrets are not restored)."""
        facts = [Fact.from_dict(row["fact"]) for row in read_events(log_path) if row["event"] == "fact"]
        eng = cls(scope, **kwargs)
        eng.facts.add(facts)
        return eng

    def _next_id(self) -> str:
        with self._lock:
            return f"c{next(self._ids)}"


def _handle(number: str) -> str:
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


# ---- helpers ----------------------------------------------------------------------------------------


def _as_result(raw: Any) -> TechniqueResult:
    if isinstance(raw, TechniqueResult):
        return raw
    if raw is None:
        return TechniqueResult()
    if isinstance(raw, str):
        return TechniqueResult(observation=raw)
    if isinstance(raw, list) and all(isinstance(f, Fact) for f in raw):
        return TechniqueResult(facts=raw)
    raise TypeError(f"technique returned {type(raw).__name__}; expected TechniqueResult, list[Fact] or str")


def _bind(t: Technique, args: dict[str, Any]) -> dict[str, Any] | str:
    """Validate and coerce LLM-provided arguments. Returns the bound args or an error string."""
    names = {p.name for p in t.params}
    unknown = sorted(set(args) - names)
    if unknown:
        return f"unknown parameter(s) {unknown}; expected {sorted(names)}"
    out: dict[str, Any] = {}
    for p in t.params:
        if p.name not in args:
            if p.default is p.empty:
                return f"missing required parameter {p.name!r}"
            continue
        try:
            out[p.name] = _coerce(t.param_type(p.name), args[p.name])
        except (TypeError, ValueError, OverflowError) as exc:
            return f"{p.name}: {exc}"
    return out


def _coerce(annotation: Any, value: Any) -> Any:
    if value is None:
        return None
    tp = _strip(annotation)
    target_cls = target_type(tp)
    if target_cls is not None:
        return _make_target(target_cls, value)
    if get_origin(tp) is Literal:
        if value not in get_args(tp):
            raise ValueError(f"must be one of {list(get_args(tp))}")
        return value
    if tp is bool:
        if isinstance(value, str) and value.lower() in ("true", "false", "1", "0", "yes", "no"):
            return value.lower() in ("true", "1", "yes")
        if not isinstance(value, bool):
            raise TypeError("expected a boolean")
        return value
    if tp is int:
        if isinstance(value, bool):
            raise TypeError("expected an integer")
        return int(value)
    if tp is float:
        return float(value)
    if tp is str:
        if not isinstance(value, str | int | float):
            raise TypeError("expected a string")
        return str(value)
    if get_origin(tp) is list:
        if not isinstance(value, list):
            raise TypeError("expected a list")
        (item,) = get_args(tp) or (str,)
        return [_coerce(item, v) for v in value]
    if get_origin(tp) is dict:
        if not isinstance(value, dict):
            raise TypeError("expected an object")
        _, item = get_args(tp) or (str, str)
        return {str(k): _coerce(item, v) for k, v in value.items()}
    return value


def _make_target(cls: type, value: Any) -> Any:
    if not isinstance(value, str) or not value.strip():
        raise TypeError("expected a non-empty string target")
    value = value.strip()
    if issubclass(cls, Url) and not re.match(r"(?i)^https?://", value):
        raise ValueError("expected an http:// or https:// URL")
    if issubclass(cls, Host) and ("://" in value or "/" in value):
        raise ValueError("expected a hostname or IP, not a URL")
    return cls(value)
