"""Policy: what each risk level is allowed to do, enforced outside the model."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Risk(StrEnum):
    SAFE = "safe"  # passive or read-only (parsing, notes, banner reads)
    INTRUSIVE = "intrusive"  # sends active traffic (scans, fuzzing, requests)
    DESTRUCTIVE = "destructive"  # changes target state (writes, account creation, exploits)
    RAW_SHELL = "raw_shell"  # arbitrary commands: cannot be scope-checked


class Decision(StrEnum):
    ALLOW = "allow"
    APPROVE = "approve"  # ask the approver
    DENY = "deny"


@dataclass(frozen=True)
class ApprovalRequest:
    """Everything a policy or approver may base a decision on."""

    technique: str
    args: dict[str, Any]
    risk: Risk
    reason: str = ""
    attack: str = ""  # MITRE ATT&CK id of the technique
    tags: frozenset[str] = frozenset()
    targets: tuple[str, ...] = ()  # the scope-checked targets of this call


Approver = Callable[[ApprovalRequest], bool]


def deny_all(request: ApprovalRequest) -> bool:
    return False


@dataclass
class Policy:
    """Maps each Risk to a Decision. Unknown risks are denied.

    `rate_limit_per_min` throttles calls (waits, never fails) to avoid overloading targets or tools.
    """

    rules: Mapping[Risk, Decision] = field(
        default_factory=lambda: {
            Risk.SAFE: Decision.ALLOW,
            Risk.INTRUSIVE: Decision.ALLOW,
            Risk.DESTRUCTIVE: Decision.APPROVE,
            Risk.RAW_SHELL: Decision.APPROVE,
        }
    )
    approver: Approver = deny_all
    rate_limit_per_min: int | None = None
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    @classmethod
    def safe(cls, approver: Approver = deny_all) -> Policy:
        """Default: active testing allowed; destructive actions and raw shell need approval."""
        return cls(approver=approver)

    @classmethod
    def production(cls, approver: Approver = deny_all) -> Policy:
        """For live client systems: active traffic needs approval; destructive and raw shell denied."""
        return cls(
            rules={
                Risk.SAFE: Decision.ALLOW,
                Risk.INTRUSIVE: Decision.APPROVE,
                Risk.DESTRUCTIVE: Decision.DENY,
                Risk.RAW_SHELL: Decision.DENY,
            },
            approver=approver,
        )

    @classmethod
    def lab(cls) -> Policy:
        """Everything allowed (still logged). Only for isolated labs, CTFs and benchmarks."""
        return cls(rules=dict.fromkeys(Risk, Decision.ALLOW))

    def decide(self, request: ApprovalRequest) -> Decision:
        """Decision for one call. The default looks only at risk; override this in a subclass to
        decide on anything in the request (technique name, tags, targets, arguments, time of day...)."""
        return self.rules.get(request.risk, Decision.DENY)

    def check(self, request: ApprovalRequest) -> str | None:
        """Return None if the call may proceed, else the reason it is blocked."""
        try:
            decision = Decision(self.decide(request))  # accept plain strings from subclasses
        except ValueError:
            decision = Decision.DENY  # anything unrecognised fails closed
        if decision is Decision.DENY:
            return f"denied by policy ({request.risk})"
        if decision is Decision.APPROVE:
            try:
                approved = bool(self.approver(request))
            except Exception as exc:  # a broken approver must fail closed
                return f"approval failed ({type(exc).__name__})"
            if not approved:
                return f"approval required ({request.risk}) and not granted"
        self._throttle()
        return None

    def _throttle(self) -> None:
        if not self.rate_limit_per_min:
            return
        with self._lock:
            now = self.clock()
            while self._calls and now - self._calls[0] >= 60:
                self._calls.popleft()
            wait = 0.0
            if len(self._calls) >= self.rate_limit_per_min:
                wait = 60 - (now - self._calls[0])
            self._calls.append(now + wait)
        if wait > 0:
            self.sleep(wait)
