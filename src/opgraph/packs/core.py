"""Core techniques: the raw shell escape hatch and agent notes."""

from __future__ import annotations

import shlex

from .. import parsers
from ..engagement import Ctx
from ..facts import note as note_fact
from ..technique import TechniqueResult, technique


@technique(risk="raw_shell", attack="T1059.004", timeout=120)
def shell(ctx: Ctx, command: str) -> TechniqueResult:
    """Run a bash command in a private temp directory. Use only when no typed tool fits.

    Raw commands cannot be scope-checked, so they need approval unless the policy allows them.
    """
    warnings = ctx.scope.audit_command(command)
    for warning in warnings:
        ctx.log(f"shell scope warning: {warning}")
    result = ctx.exec([ctx.tool("bash"), "-c", f"cd {shlex.quote(ctx.workdir())} && {command}"])
    parts = [result.output]
    if result.timed_out:
        parts.append(f"[timed out after {ctx.timeout}s]")
    elif result.rc:
        parts.append(f"[exit code {result.rc}]")
    if warnings:
        parts.append("[scope warning] " + "; ".join(warnings))
    output = "\n".join(p for p in parts if p)
    return TechniqueResult(observation=output, facts=parsers.generic(result.stdout))


@technique(risk="safe")
def note(text: str) -> TechniqueResult:
    """Save a short note to the shared memory (ideas, leads, things to try later)."""
    return TechniqueResult(facts=[note_fact(text[:2000])])
