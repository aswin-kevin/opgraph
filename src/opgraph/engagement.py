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

import inspect
import itertools
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .effects import EffectStack
from .executors import ExecResult, Executor, LocalExecutor
from .facts import Fact, FactStore, finding
from .ledger import Ledger, read_events
from .observe import sanitize, untrusted
from .policy import ApprovalRequest, Policy
from .render import format_fact, world
from .scope import CheckedTarget, OutOfScope, Scope
from .technique import Technique, TechniqueResult, as_result, collect
from .vault import Vault

_VULN_CLASS = re.compile(r"[a-z0-9_.-]{1,64}")
_MAX_LOGGED_OBSERVATION = 50_000


@dataclass
class CallResult:
    technique: str
    call_id: str
    ok: bool
    text: str = ""  # sanitized, capped observation (or error message)
    new_facts: list[Fact] = field(default_factory=list)
    blocked: str | None = None  # reason, if the call never ran

    def to_dict(self) -> dict[str, Any]:
        """Structured form, for builders who return JSON to their model or UI."""
        return {
            "technique": self.technique,
            "call_id": self.call_id,
            "ok": self.ok,
            "blocked": self.blocked,
            "text": self.text,
            "new_facts": [f.to_dict() for f in self.new_facts],
        }

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
        self,
        eng: Engagement,
        technique: Technique,
        call_id: str,
        targets: dict[str, CheckedTarget],
        target_lists: dict[str, list[CheckedTarget]] | None = None,
    ):
        self._eng = eng
        self.technique = technique
        self.call_id = call_id
        self.targets = targets  # checked target per Target-typed argument (with pinned IP)
        self.target_lists = target_lists or {}  # checked targets per list[Target] argument

    @property
    def facts(self) -> FactStore:
        return self._eng.facts

    @property
    def scope(self) -> Scope:
        return self._eng.scope

    @property
    def config(self) -> Mapping[str, Any]:
        """The engagement's configuration (read-only)."""
        return self._eng.config

    @property
    def options(self) -> Mapping[str, Any]:
        """This technique's own options: ``config[<technique name>]`` (empty if not set)."""
        value = self._eng.config.get(self.technique.name, {})
        return value if isinstance(value, Mapping) else {}

    @property
    def timeout(self) -> int:
        """This technique's timeout: ``config["timeouts"][<name>]`` or the declared default."""
        timeouts = self._eng.config.get("timeouts", {})
        return int(timeouts.get(self.technique.name, self.technique.timeout))

    def tool(self, name: str) -> str:
        """Executable to run for a tool: ``config["tools"][name]`` or the name itself."""
        return str(self._eng.config.get("tools", {}).get(name, name))

    def exec(
        self,
        argv: list[str],
        timeout: int | None = None,
        stdin: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        """Run argv on the engagement's executor. Never pass a shell string."""
        if env:
            if not _accepts_env(self._eng.executor):
                raise TypeError(f"{type(self._eng.executor).__name__}.run() does not accept env=")
            result = self._eng.executor.run(argv, timeout or self.timeout, stdin, env=env)  # type: ignore[call-arg]
        else:
            result = self._eng.executor.run(argv, timeout or self.timeout, stdin)
        self._eng.ledger.record(
            "exec",
            call_id=self.call_id,
            argv=self._eng.vault.redact(argv),
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


def _accepts_env(executor: Executor) -> bool:
    params = inspect.signature(executor.run).parameters
    return "env" in params or any(p.kind is p.VAR_KEYWORD for p in params.values())


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
        config: Mapping[str, Any] | None = None,
    ):
        """
        `config` is free-form settings for techniques, read through `Ctx`. Built-in packs use:
        ``tools`` (executable per tool name), ``timeouts`` (seconds per technique), ``wordlists``
        (name -> path), ``http_proxy`` (e.g. Burp), ``http_headers`` (sent with every web request,
        e.g. a bug-bounty identification header), and a dict of options per technique name.
        """
        self.name = name
        self.scope = scope
        self.policy = policy or Policy.safe()
        self.executor: Executor = executor or LocalExecutor()
        self.facts = FactStore()
        self.ledger = Ledger(log_path)
        self.effects = EffectStack()
        self.observation_cap = observation_cap
        self.config: Mapping[str, Any] = MappingProxyType(dict(config or {}))
        self.techniques: dict[str, Technique] = {}
        self.vault = Vault()  # secrets; the model only sees {{cred:N}} handles
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._workdir_lock = threading.Lock()
        self._workdir: str | None = None
        self._closed = False
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
            message = self.vault.redact(f"internal error: {type(exc).__name__}: {exc}")
            self.ledger.record("error", call_id=call_id, technique=name, error=message)
            return CallResult(name, call_id, ok=False, text=message)

    def _call(self, name: str, args: dict[str, Any], call_id: str) -> CallResult:
        if self._closed:
            return self._blocked(name, call_id, args, "engagement is closed")
        t = self.techniques.get(name)
        if t is None:
            return self._blocked(name, call_id, args, f"unknown technique; known: {sorted(self.techniques)}")

        bound = t.bind(args)
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
                checked[pname] = self._check_target(t, pname, value, resolver)
            except OutOfScope as exc:
                return self._blocked(name, call_id, args, f"out_of_scope: {exc}")
        checked_lists: dict[str, list[CheckedTarget]] = {}
        for pname in t.target_list_params():
            try:
                checked_lists[pname] = [
                    self._check_target(t, pname, v, resolver) for v in bound.get(pname) or []
                ]
            except OutOfScope as exc:
                return self._blocked(name, call_id, args, f"out_of_scope: {exc}")
        # Credential handles are swapped for real secrets only in parameters declared as Secret.
        resolved = {k: self.vault.resolve(v) if k in t.secret_params() else v for k, v in bound.items()}

        all_checked = [*checked.values(), *(c for group in checked_lists.values() for c in group)]
        targets = tuple(c.target.raw for c in all_checked)
        request = ApprovalRequest(name, bound, t.risk, attack=t.attack, tags=t.tags, targets=targets)
        reason = self.policy.check(request)
        if reason:
            return self._blocked(name, call_id, args, reason)

        for target in targets or ("",):
            self.ledger.count(name, target)
        self.ledger.record(
            "call", call_id=call_id, technique=name, args=bound, risk=str(t.risk), attack=t.attack
        )
        ctx = Ctx(self, t, call_id, checked, checked_lists)
        try:
            raw = t.fn(ctx, **resolved) if t.takes_ctx else t.fn(**resolved)
            result = as_result(raw)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            self.ledger.record("error", call_id=call_id, technique=name, error=message)
            return CallResult(name, call_id, ok=False, text=self.vault.redact(message))

        new = self._ingest(t, call_id, result)
        if self._closed:  # closed while this call ran: clean up whatever it just created
            self.effects.dispose()
        observation = self.vault.redact(sanitize(result.observation))
        self.ledger.record(
            "result",
            call_id=call_id,
            new_facts=len(new),
            observation=observation[:_MAX_LOGGED_OBSERVATION],
        )
        text = untrusted(observation, self.observation_cap) if observation.strip() else ""
        return CallResult(name, call_id, ok=True, text=text, new_facts=new)

    def _check_target(
        self, t: Technique, pname: str, value: str, resolver: Callable[[str], str] | None
    ) -> CheckedTarget:
        checked = self.scope.check(value, resolver)
        if checked.target.is_network and not t.accepts_ranges(pname):
            raise OutOfScope(value, f"{pname!r} takes a single target; only Network parameters take ranges")
        return checked

    def _blocked(self, name: str, call_id: str, args: dict[str, Any], reason: str) -> CallResult:
        reason = self.vault.redact(reason)
        self.ledger.record(
            "blocked", call_id=call_id, technique=name, args=self.vault.redact(args), reason=reason
        )
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
            attrs["secret_ref"] = self.vault.store(str(attrs.pop("secret")))
        if fact.kind == "finding" and attrs.get("status") == "confirmed" and not attrs.get("evidence"):
            attrs["status"] = "proposed"  # no finding without evidence
        source = fact.source if fact.source != "unknown" else source
        return replace(
            fact,
            key=self.vault.redact(fact.key),
            attrs=self.vault.redact(attrs),
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

    # ---- world, findings -----------------------------------------------------------------------

    def world(self, budget_tokens: int = 1500) -> str:
        """The fact graph and available actions as compact text for a model."""
        return world(self.facts, self.techniques.values(), budget_tokens)

    def snapshot(self) -> dict[str, Any]:
        """Structured state for custom prompts and UIs: all facts plus each technique's availability."""
        return {
            "facts": [f.to_dict() for f in self.facts],
            "techniques": [
                {
                    "name": t.name,
                    "description": t.description,
                    "risk": str(t.risk),
                    "attack": t.attack,
                    "tags": sorted(t.tags),
                    "available": t.is_available(self.facts),
                }
                for t in self.techniques.values()
            ],
        }

    def propose_finding(self, vuln_class: str, target: str, rationale: str = "") -> Fact:
        """Record a claimed weakness. It stays `proposed` until `verify` finds evidence.

        Proposing an existing finding again returns it unchanged, so a model cannot undo a
        verification or revive a rejected finding by repeating itself.
        """
        if not _VULN_CLASS.fullmatch(vuln_class):
            raise ValueError("vuln_class must be 1-64 chars of a-z, 0-9, '_', '-', '.'")
        # Model-written text may echo target content, so it is treated as untrusted when rendered.
        fact = replace(finding(vuln_class, target, rationale=rationale), source="agent")
        existing = self.facts.get(fact.id)
        if existing is not None:
            return existing
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
            if self._closed:
                raise RuntimeError("engagement is closed")
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
        """End the engagement: refuse new calls, stop running commands, clean up, close the log."""
        self._closed = True
        kill_running = getattr(self.executor, "kill_running", None)
        if kill_running:
            kill_running()
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
