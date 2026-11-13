"""Expose an Engagement as LLM tools, without any framework.

    specs = openai_tools(eng)                 # Chat Completions / Ollama / vLLM / LiteLLM format
    specs = anthropic_tools(eng)              # Anthropic Messages format
    text = run_tool(eng, name, arguments)     # execute any tool call; never raises

Besides every registered technique, two meta-tools are always offered:
`world` (what is known and what can be done next) and `propose_finding`.
"""

from __future__ import annotations

import json
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


def tool_specs(eng: Engagement) -> list[ToolSpec]:
    """Every technique plus the meta-tools, in a framework-neutral form."""
    specs = [ToolSpec(t.name, t.doc, t.schema(), str(t.risk)) for t in eng.techniques.values()]
    clash = {s.name for s in specs} & {m.name for m in _META}
    if clash:
        raise ValueError(f"technique names reserved for meta-tools: {sorted(clash)}")
    return specs + _META


def openai_tools(eng: Engagement) -> list[dict[str, Any]]:
    """Tool definitions for OpenAI-compatible Chat Completions APIs (OpenAI, Ollama, vLLM, ...)."""
    return [
        {
            "type": "function",
            "function": {"name": s.name, "description": s.description, "parameters": s.parameters},
        }
        for s in tool_specs(eng)
    ]


def anthropic_tools(eng: Engagement) -> list[dict[str, Any]]:
    """Tool definitions for the Anthropic Messages API."""
    return [
        {"name": s.name, "description": s.description, "input_schema": s.parameters} for s in tool_specs(eng)
    ]


def run_tool(eng: Engagement, name: str, arguments: dict[str, Any] | str | None = None) -> str:
    """Execute one tool call and return the text to give back to the model.

    `arguments` may be a dict or the raw JSON string a model produced. This never raises:
    bad input and internal errors come back as `[error] ...` text the model can react to.
    """
    try:
        args = _parse_arguments(arguments)
    except ValueError as exc:
        return f"[error] {name}: {exc}"
    try:
        if name == WORLD:
            return eng.world()
        if name == PROPOSE_FINDING:
            return _propose(eng, args)
        return eng.call(name, args).to_tool_text()
    except Exception as exc:  # adapters must never crash the agent loop
        return eng._redact(f"[error] {name}: internal error ({type(exc).__name__}: {exc})")


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
