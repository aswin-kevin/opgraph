"""Expose an Engagement as LLM tools, without any framework.

    specs = openai_tools(eng)                 # Chat Completions / Ollama / vLLM / LiteLLM format
    specs = anthropic_tools(eng)              # Anthropic Messages format
    text = run_tool(eng, name, arguments)     # execute any tool call; never raises

Besides every registered technique, two meta-tools are always offered:
`world` (what is known and what can be done next) and `propose_finding`.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from .engagement import Engagement

WORLD = "world"
PROPOSE_FINDING = "propose_finding"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema of the arguments
    risk: str  # the technique's risk level; "safe" for meta-tools


_META = [
    ToolSpec(
        WORLD,
        "Show everything known so far (hosts, services, endpoints, credentials, findings) and which "
        "actions are available now. Call it first, and whenever you are unsure what to do next.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "safe",
    ),
    ToolSpec(
        PROPOSE_FINDING,
        "Record a suspected vulnerability. It stays 'proposed' until verified with evidence; "
        "never claim a finding is confirmed yourself.",
        {
            "type": "object",
            "properties": {
                "vuln_class": {
                    "type": "string",
                    "description": "short lowercase class, e.g. sqli, xss, idor, rce",
                },
                "target": {"type": "string", "description": "URL or host:port affected"},
                "rationale": {"type": "string", "description": "why you suspect it, citing call ids"},
            },
            "required": ["vuln_class", "target"],
            "additionalProperties": False,
        },
        "safe",
    ),
]


def tool_specs(
    eng: Engagement, names: Collection[str] | None = None, include_meta: bool = True
) -> list[ToolSpec]:
    """Techniques plus the meta-tools, in a framework-neutral form.

    `names` exposes only those techniques (e.g. a recon sub-agent gets recon tools only);
    `include_meta=False` leaves out `world` and `propose_finding` if you bring your own.
    """
    techniques = list(eng.techniques.values())
    if isinstance(names, str):
        raise TypeError("names must be a collection of technique names, not a string")
    if names is not None:
        unknown = set(names) - set(eng.techniques)
        if unknown:
            raise ValueError(f"unknown techniques: {sorted(unknown)}")
        techniques = [t for t in techniques if t.name in set(names)]
    specs = [ToolSpec(t.name, t.doc, t.schema(), str(t.risk)) for t in techniques]
    if not include_meta:
        return specs
    clash = {s.name for s in specs} & {m.name for m in _META}
    if clash:
        raise ValueError(f"technique names reserved for meta-tools: {sorted(clash)}")
    return specs + _META


def openai_tools(
    eng: Engagement, names: Collection[str] | None = None, include_meta: bool = True
) -> list[dict[str, Any]]:
    """Tool definitions for OpenAI-compatible Chat Completions APIs (OpenAI, Ollama, vLLM, ...)."""
    return [
        {
            "type": "function",
            "function": {"name": s.name, "description": s.description, "parameters": s.parameters},
        }
        for s in tool_specs(eng, names, include_meta)
    ]


def anthropic_tools(
    eng: Engagement, names: Collection[str] | None = None, include_meta: bool = True
) -> list[dict[str, Any]]:
    """Tool definitions for the Anthropic Messages API."""
    return [
        {"name": s.name, "description": s.description, "input_schema": s.parameters}
        for s in tool_specs(eng, names, include_meta)
    ]


def run_tool(
    eng: Engagement,
    name: str,
    arguments: dict[str, Any] | str | None = None,
    *,
    names: Collection[str] | None = None,
    include_meta: bool = True,
) -> str:
    """Execute one tool call and return the text to give back to the model.

    `arguments` may be a dict or the raw JSON string a model produced. Pass the same `names` /
    `include_meta` used for the tool definitions, so a model cannot call tools it was not given.
    Model input never makes this raise: bad arguments and internal errors come back as
    `[error] ...` text. (Passing a plain string as `names` is a programming error and raises.)
    """
    if isinstance(names, str):
        raise TypeError("names must be a collection of technique names, not a string")
    is_meta = include_meta and name in (WORLD, PROPOSE_FINDING)
    if not is_meta and names is not None and name not in frozenset(names):
        return f"[blocked] {name}: this tool is not available to this agent"
    try:
        args = _parse_arguments(arguments)
    except ValueError as exc:
        return f"[error] {name}: {exc}"
    try:
        if is_meta and name == WORLD:
            return eng.world()
        if is_meta and name == PROPOSE_FINDING:
            return _propose(eng, args)
        return eng.call(name, args).to_tool_text()
    except Exception as exc:  # adapters must never crash the agent loop
        return eng.vault.redact(f"[error] {name}: internal error ({type(exc).__name__}: {exc})")


def _parse_arguments(arguments: dict[str, Any] | str | None) -> dict[str, Any]:
    if arguments is None or arguments == "":
        return {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise ValueError(f"arguments are not valid JSON ({exc.msg})") from None
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a JSON object")
    return arguments


def _propose(eng: Engagement, args: dict[str, Any]) -> str:
    vuln_class = args.get("vuln_class")
    target = args.get("target")
    rationale = args.get("rationale", "")
    if not isinstance(vuln_class, str) or not vuln_class.strip():
        return f"[error] {PROPOSE_FINDING}: vuln_class is required"
    if not isinstance(target, str) or not target.strip():
        return f"[error] {PROPOSE_FINDING}: target is required"
    try:
        fact = eng.propose_finding(vuln_class.strip().lower(), target.strip()[:500], str(rationale)[:2000])
    except ValueError as exc:
        return f"[error] {PROPOSE_FINDING}: {exc}"
    return f"[ok] {PROPOSE_FINDING}: recorded {fact.id} (status: {fact.get('status')})"
