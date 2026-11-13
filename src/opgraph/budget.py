"""Budgets: bounded work and no loops.

Agents repeat themselves (lost context, stuck loops) and run until something stops them. A Budget
gives every engagement explicit stop conditions, enforced on each call:

    Budget(max_calls=200, max_seconds=3600, per_technique={"dir_discovery": 5}, per_target=50)

`repeat_limit` (default 3) refuses a call identical to one that already succeeded that many times,
pointing the agent back to the earlier result instead of re-running it. Failed calls (errors,
timeouts) do not count, so retries stay possible. Per-target budgets count per host.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Budget:
    max_calls: int | None = None  # executed calls, all techniques together
    max_seconds: float | None = None  # wall time since the engagement first started (resumes included)
    per_technique: Mapping[str, int] = field(default_factory=dict)  # executed calls per technique
    per_target: int | None = None  # executed calls per target host (all techniques)
    repeat_limit: int | None = 3  # identical successful calls (same technique and arguments); None disables


@dataclass
class Usage:
    """What has been spent so far. Not thread-safe on its own: the Engagement serialises access."""

    calls: int = 0
    by_technique: Counter[str] = field(default_factory=Counter)
    by_target: Counter[str] = field(default_factory=Counter)
    attempted: Counter[str] = field(default_factory=Counter)  # signature -> calls started
    succeeded: Counter[str] = field(default_factory=Counter)  # signature -> calls that worked
    last_call: dict[str, str] = field(default_factory=dict)  # signature -> latest successful call id

    def record(self, technique: str, hosts: tuple[str, ...], signature: str) -> None:
        """Spend budget for a call that is about to run."""
        self.calls += 1
        self.by_technique[technique] += 1
        self.by_target.update(set(hosts))
        self.attempted[signature] += 1

    def succeed(self, signature: str, call_id: str) -> None:
        self.succeeded[signature] += 1
        self.last_call[signature] = call_id


def signature(technique: str, args: Mapping[str, Any]) -> str:
    """Identity of a call for repetition checks: technique plus canonical arguments."""
    return json.dumps({"technique": technique, "args": args}, sort_keys=True, default=str)


def refusal(
    budget: Budget, usage: Usage, technique: str, hosts: tuple[str, ...], sig: str, elapsed: float
) -> str | None:
    """Why this call must not run, or None if it fits the budget."""
    if budget.max_seconds is not None and elapsed >= budget.max_seconds:
        return f"budget exhausted (time limit {budget.max_seconds:.0f}s); summarize findings and stop"
    if budget.max_calls is not None and usage.calls >= budget.max_calls:
        return f"budget exhausted ({budget.max_calls} calls); summarize findings and stop"
    limit = budget.per_technique.get(technique)
    if limit is not None and usage.by_technique[technique] >= limit:
        return f"budget for {technique} exhausted ({limit} calls); use other techniques"
    if budget.per_target is not None:
        for host in hosts:
            if usage.by_target[host] >= budget.per_target:
                return f"budget for target {host} exhausted ({budget.per_target} calls)"
    if budget.repeat_limit is not None and usage.succeeded[sig] >= budget.repeat_limit:
        return (
            f"repeated: this exact call already succeeded {usage.succeeded[sig]} time(s) "
            f"(last: {usage.last_call.get(sig)}); its results are in the facts (call world). "
            "Change the arguments or try something else"
        )
    return None


def status(budget: Budget, usage: Usage, elapsed: float) -> dict[str, Any]:
    return {
        "calls": usage.calls,
        "max_calls": budget.max_calls,
        "seconds": round(elapsed, 1),
        "max_seconds": budget.max_seconds,
        "by_technique": dict(usage.by_technique),
        "per_technique": dict(budget.per_technique),
    }


def summary_line(budget: Budget, usage: Usage, elapsed: float) -> str:
    """One line for the world view, only for limits that are set."""
    parts = []
    if budget.max_calls is not None:
        parts.append(f"calls {usage.calls}/{budget.max_calls}")
    if budget.max_seconds is not None:
        parts.append(f"time {elapsed:.0f}/{budget.max_seconds:.0f}s")
    for name, limit in budget.per_technique.items():
        parts.append(f"{name} {usage.by_technique[name]}/{limit}")
    return "BUDGET: " + ", ".join(parts) if parts else ""
