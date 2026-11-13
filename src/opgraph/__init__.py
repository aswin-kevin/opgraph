"""opgraph: typed actions, a shared fact graph, enforced scope and owned cleanup for agentic pentest
systems. Bring your own agent framework."""

from .checks import RegexCheck
from .engagement import CallResult, Ctx, Engagement, Evidence
from .executors import ExecResult, Executor, LocalExecutor, SSHExecutor
from .facts import (
    Fact,
    FactStore,
    artifact,
    credential,
    endpoint,
    finding,
    host,
    note,
    param,
    service,
    tech,
)
from .policy import ApprovalRequest, Decision, Policy, Risk
from .scope import CheckedTarget, OutOfScope, Scope
from .technique import Host, Secret, Target, Technique, TechniqueResult, Url, technique

__version__ = "0.1.0"

__all__ = [
    "ApprovalRequest",
    "CallResult",
    "CheckedTarget",
    "Ctx",
    "Decision",
    "Engagement",
    "Evidence",
    "ExecResult",
    "Executor",
    "Fact",
    "FactStore",
    "Host",
    "LocalExecutor",
    "OutOfScope",
    "Policy",
    "RegexCheck",
    "Risk",
    "SSHExecutor",
    "Scope",
    "Secret",
    "Target",
    "Technique",
    "TechniqueResult",
    "Url",
    "__version__",
    "artifact",
    "credential",
    "endpoint",
    "finding",
    "host",
    "note",
    "param",
    "service",
    "tech",
    "technique",
]
