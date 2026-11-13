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
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .budget import Budget, Usage, refusal, signature, status, summary_line
from .effects import EffectStack
from .executors import ExecResult, Executor, LocalExecutor
from .facts import Fact, FactStore, finding
from .ledger import Ledger, read_events
from .observe import clean_value, sanitize, untrusted
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
        """Register cleanup for something this call created. Prefer returning artifacts from the
        technique (with an `undo`): those cleanups survive a crash via `Engagement.resume`."""
        self._eng._own(f"{label} (by {self.technique.name} {self.call_id})", undo, kind="deferred")

    def log(self, message: str) -> None:
        self._eng.ledger.record("log", call_id=self.call_id, message=message)


def _format_args(args: dict[str, Any]) -> str:
    return ", ".join(f"{k}={json.dumps(clean_value(v, 160))}" for k, v in args.items())


# What `mktemp -d -t opgraph.XXXXXXXX` produces on Linux and macOS; anything else is never deleted.
_WORKDIR = re.compile(r"/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*/)*opgraph\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)?")


def _is_workdir(path: str) -> bool:
    return bool(_WORKDIR.fullmatch(path)) and "/../" not in path and "/./" not in path


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
        budget: Budget | None = None,
    ):
        """
        `config` is free-form settings for techniques, read through `Ctx`. Built-in packs use:
        ``tools`` (executable per tool name), ``timeouts`` (seconds per technique), ``wordlists``
        (name -> path), ``http_proxy`` (e.g. Burp), ``http_headers`` (sent with every web request,
        e.g. a bug-bounty identification header), and a dict of options per technique name.

        `budget` sets stop conditions (calls, time, per technique, per target) and the repetition
        limit; the default only refuses a 4th identical call.
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
        self.budget = budget or Budget()
        self.usage = Usage()
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._workdir_lock = threading.Lock()
        self._workdir: str | None = None
        self._closed = False
        self._labels: dict[str, int] = {}  # cleanup label -> registrations, for unique labels
        self.started = time.time()
        self._stop_fact_log = self.facts.subscribe(self._log_fact)
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
        hosts = tuple(c.target.host for c in all_checked)
        sig = signature(name, bound)
        refused = self._budget_refusal(name, hosts, sig)  # before asking anyone to approve
        if refused:
            return self._blocked(name, call_id, args, refused)
        request = ApprovalRequest(name, bound, t.risk, attack=t.attack, tags=t.tags, targets=targets)
        reason = self.policy.check(request)
        if reason:
            return self._blocked(name, call_id, args, reason)
        with self._lock:  # re-check and spend in one step, so parallel calls cannot overshoot
            refused = refusal(self.budget, self.usage, name, hosts, sig, time.time() - self.started)
            if not refused:
                self.usage.record(name, hosts, sig)
        if refused:
            return self._blocked(name, call_id, args, refused)

        for target in targets or ("",):
            self.ledger.count(name, target)
        self.ledger.record(
            "call",
            call_id=call_id,
            technique=name,
            args=bound,
            risk=str(t.risk),
            attack=t.attack,
            targets=list(targets),
            hosts=list(hosts),
            signature=sig,
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
        with self._lock:
            self.usage.succeed(sig, call_id)
        text = untrusted(observation, self.observation_cap) if observation.strip() else ""
        return CallResult(name, call_id, ok=True, text=text, new_facts=new)

    def _budget_refusal(self, name: str, hosts: tuple[str, ...], sig: str) -> str | None:
        with self._lock:
            return refusal(self.budget, self.usage, name, hosts, sig, time.time() - self.started)

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
            label = f"{art.id} (by {t.name} {call_id})"
            self._own(label, self._undo_for(t, art, call_id), kind="artifact", technique=t.name,
                      call_id=call_id, fact=art.to_dict())  # fmt: skip
        return new

    def _own(
        self, label: str, undo: Callable[[], object], kind: str, root: bool = False, **meta: Any
    ) -> None:
        """Register a cleanup; its registration and outcome go to the log so `resume` can finish it.
        Labels are made unique, so each obligation is tracked on its own."""
        with self._lock:
            self._labels[label] = self._labels.get(label, 0) + 1
            if self._labels[label] > 1:
                label = f"{label} #{self._labels[label]}"
                self._labels[label] = 1
        self.ledger.record("cleanup_registered", label=label, kind=kind, root=root, **meta)

        def logged() -> object:
            try:
                result = undo()
            except Exception as exc:
                self.ledger.record("cleanup", label=label, ok=False, error=f"{type(exc).__name__}: {exc}")
                raise
            self.ledger.record("cleanup", label=label, ok=True)
            return result

        self.effects.push(label, logged, root=root)

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
        """The fact graph, untried suggestions, budget and available actions as text for a model."""
        extra = []
        line = summary_line(self.budget, self.usage, time.time() - self.started)
        if line:
            extra.append(line)
        if any(t.suggest for t in self.techniques.values()):
            untried, any_in_scope = self._coverage(limit=8)
            if untried:
                extra.append(f"UNTRIED (suggested next, {len(untried)} shown; untrusted target data):")
                extra += [f"- {u['technique']}({_format_args(u['args'])})" for u in untried]
            elif any_in_scope:
                extra.append("UNTRIED: none (every in-scope suggestion has been tried)")
        return world(self.facts, self.techniques.values(), budget_tokens, extra)

    def untried(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Suggested calls (from techniques' `suggest`) that look in scope and have not been tried.

        The scope test here is lexical (no DNS) to keep it cheap; `call()` still does the full
        check. A broken `suggest` function is skipped, never raised.
        """
        return self._coverage(limit)[0]

    def _coverage(self, limit: int | None) -> tuple[list[dict[str, Any]], bool]:
        """(untried suggestions, whether any in-scope suggestion exists at all)."""
        out: list[dict[str, Any]] = []
        any_in_scope = False
        for t in self.available():
            try:
                suggestions = t.suggestions(self.facts)
            except Exception:
                continue
            for args in suggestions:
                bound = t.bind(args) if isinstance(args, dict) else "not a dict"
                if isinstance(bound, str) or not self._looks_in_scope(t, bound):
                    continue
                any_in_scope = True
                with self._lock:
                    tried = self.usage.attempted[signature(t.name, bound)] > 0
                if not tried:
                    out.append({"technique": t.name, "args": bound})
                    if limit is not None and len(out) >= limit:
                        return out, True
        return out, any_in_scope

    def _looks_in_scope(self, t: Technique, bound: dict[str, Any]) -> bool:
        values = [(p, bound.get(p)) for p in t.target_params() if bound.get(p) is not None]
        values += [(p, v) for p in t.target_list_params() for v in bound.get(p) or []]
        for pname, value in values:
            if not self.scope.allows_without_dns(str(value)):
                return False
            if "/" in str(value) and "://" not in str(value) and not t.accepts_ranges(pname):
                return False
        return True

    def budget_status(self) -> dict[str, Any]:
        with self._lock:
            return status(self.budget, self.usage, time.time() - self.started)

    def canary(self, label: str = "") -> str:
        """A unique, unguessable token to plant in a target (stored input, file, callback URL).

        Verify with ``eng.verify(finding_id, CanaryCheck(token))``: seeing the token come back
        somewhere the agent could not have produced it is strong evidence.
        """
        token = "opgc" + secrets.token_hex(10)
        self.facts.add(
            [Fact("canary", (token,), {"label": label[:200]}, source="agent", target_derived=False)]
        )
        self.ledger.record("canary", token=token, label=label[:200])
        return token

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
                if not result.ok or not _is_workdir(path):
                    raise RuntimeError(f"could not create workdir: {result.output.strip()}")
                self._workdir = path
                self._own(f"workdir {path}", lambda: self._remove_workdir(path), "workdir", True, path=path)
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
    def resume(cls, log_path: str | Path, scope: Scope, **kwargs: Any) -> Engagement:
        """Continue an interrupted engagement from its event log (appending to the same log).

        Restores facts, findings, coverage, budget usage and call numbering, and re-registers every
        cleanup that had not succeeded, so whatever the previous run created on targets is still
        removed by `dispose()`. Pass the same techniques so their `undo` functions can run.
        Secrets are never logged: store credentials in `eng.vault` again if needed.

        The log is trusted input here: keep it where only the operator can write. As a safeguard,
        only paths shaped like this library's temp dirs are ever deleted, and artifacts are only
        cleaned automatically when their target is in the scope passed to `resume`.
        """
        rows = list(read_events(log_path))
        kwargs.pop("log_path", None)
        eng = cls(scope, log_path=log_path, **kwargs)
        eng.ledger.load(rows)
        eng._stop_fact_log()  # restored facts are already in the log
        eng.facts.add(Fact.from_dict(r["fact"]) for r in rows if r["event"] == "fact")
        eng._stop_fact_log = eng.facts.subscribe(eng._log_fact)

        starts = [r["ts"] for r in rows if r["event"] == "start"]
        eng.started = min(starts) if starts else eng.started
        last_id = 0
        signatures: dict[str, str] = {}
        for row in rows:
            if row["event"] == "call":
                targets = tuple(row.get("targets") or ())
                sig = row.get("signature") or signature(row["technique"], row.get("args") or {})
                signatures[row["call_id"]] = sig
                eng.usage.record(row["technique"], tuple(row.get("hosts") or targets), sig)
                for target in targets or ("",):
                    eng.ledger.count(row["technique"], target)
                digits = re.fullmatch(r"c(\d+)", str(row["call_id"]))
                last_id = max(last_id, int(digits.group(1)) if digits else 0)
            elif row["event"] == "result" and row.get("call_id") in signatures:
                eng.usage.succeed(signatures[row["call_id"]], row["call_id"])
        eng._ids = itertools.count(last_id + 1)

        done = {r["label"] for r in rows if r["event"] == "cleanup" and r.get("ok")}
        registered = {r["label"]: r for r in rows if r["event"] == "cleanup_registered"}  # latest wins
        pending = [r for label, r in registered.items() if label not in done]
        for row in pending:
            eng._restore_cleanup(row)
        eng.ledger.record("resume", pending_cleanup=[r["label"] for r in pending])
        return eng

    def _restorable(self, row: dict[str, Any]) -> bool:
        """An artifact from the log is only cleaned automatically if its target is in today's scope."""
        try:
            target = str(Fact.from_dict(row["fact"]).key[0])
        except (KeyError, IndexError, TypeError):
            return False
        return self.scope.allows_without_dns(target)

    def mark_cleaned(self, label: str, note: str = "") -> bool:
        """Record that a pending cleanup (e.g. a RESIDUE line) was handled manually."""
        removed = self.effects.remove(label)
        if removed:
            self.ledger.record("cleanup", label=label, ok=True, manual=True, note=note[:500])
        return removed

    def _restore_cleanup(self, row: dict[str, Any]) -> None:
        label, kind = row["label"], row.get("kind")
        if kind == "workdir":
            path = str(row.get("path", ""))
            if _is_workdir(path):  # the log is input: never delete anything else
                self._own(label, lambda: self._remove_workdir(path), "workdir", True, path=path)
                return
        if kind == "artifact" and row.get("technique") in self.techniques and self._restorable(row):
            t = self.techniques[row["technique"]]
            art = Fact.from_dict(row["fact"])
            self._own(label, self._undo_for(t, art, row.get("call_id", "")), "artifact",
                      technique=t.name, call_id=row.get("call_id"), fact=row["fact"])  # fmt: skip
            return

        def cannot_restore() -> None:
            raise RuntimeError("registered by a previous run and cannot be restored; clean up manually")

        self._own(label, cannot_restore, kind or "unknown")

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
