"""OpenAI Agents SDK adapter (`pip install opgraph[openai-agents]`).

    from agents import Agent
    from opgraph.adapters.openai_agents import to_function_tools

    agent = Agent(name="pentester", instructions=PROMPT, tools=to_function_tools(eng))

Techniques whose preconditions do not hold yet are hidden from the model (`is_enabled`), and
appear as soon as the facts they need are discovered.

Note: a cancelled or timed-out SDK tool call cannot stop the worker thread; the underlying
command still ends at its own timeout, and `Engagement.close()` kills it immediately.
"""

from __future__ import annotations

import asyncio
from collections.abc import Collection
from typing import Any

try:
    from agents import FunctionTool
except ImportError as exc:  # pragma: no cover - depends on installed extras
    raise ImportError(
        "this adapter needs the openai-agents extra: pip install 'opgraph[openai-agents]'"
    ) from exc

from ..engagement import Engagement
from ..tools import ToolSpec, run_tool, tool_specs


def to_function_tools(
    eng: Engagement, names: Collection[str] | None = None, include_meta: bool = True
) -> list[FunctionTool]:
    """One FunctionTool per technique (optionally only `names`), plus the meta-tools."""
    specs = tool_specs(eng, names, include_meta)
    return [_tool(eng, spec, names, include_meta) for spec in specs]


def _tool(eng: Engagement, spec: ToolSpec, names: Collection[str] | None, include_meta: bool) -> FunctionTool:
    async def invoke(ctx: Any, raw_arguments: str) -> str:
        return await asyncio.to_thread(
            run_tool, eng, spec.name, raw_arguments, names=names, include_meta=include_meta
        )

    def enabled(ctx: Any, agent: Any) -> bool:
        technique = eng.techniques.get(spec.name)
        return technique is None or technique.is_available(eng.facts)

    return FunctionTool(
        name=spec.name,
        description=spec.description,
        params_json_schema=spec.parameters,
        on_invoke_tool=invoke,
        strict_json_schema=False,  # our schemas have optional parameters with defaults
        is_enabled=enabled,
    )
