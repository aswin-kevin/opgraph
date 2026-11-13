"""Live smoke tests with a real LLM over an OpenAI-compatible API (run with: uv run pytest -m live).

Configuration (environment or a local .env file, never committed):
    OPGRAPH_LLM_API_KEY   API key (falls back to OLLAMA_API_KEY)
    OPGRAPH_LLM_BASE_URL  default https://ollama.com/v1
    OPGRAPH_LIVE_MODEL    default gpt-oss:120b

No network targets are touched: the engagement uses a fake executor.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from opgraph import Engagement, ExecResult, Policy, Scope
from opgraph.packs import core, web
from opgraph.tools import openai_tools, run_tool

pytestmark = pytest.mark.live

TASK = (
    "First call the `world` tool. Then call the `note` tool exactly once with the text "
    "'smoke test ok'. Then reply with the single word DONE."
)


def _settings() -> tuple[str, str, str]:
    env = dict(os.environ)
    dotenv = Path(__file__).parent.parent / ".env"
    if dotenv.exists():
        for line in dotenv.read_text().splitlines():
            name, sep, value = line.partition("=")
            if sep and not name.startswith("#"):
                env.setdefault(name.strip(), value.strip().strip("\"'"))
    key = env.get("OPGRAPH_LLM_API_KEY") or env.get("OLLAMA_API_KEY") or ""
    if not key:
        pytest.skip("no LLM API key configured")
    base_url = env.get("OPGRAPH_LLM_BASE_URL", "https://ollama.com/v1")
    return key, base_url, env.get("OPGRAPH_LIVE_MODEL", "gpt-oss:120b")


class NoopExecutor:
    def run(self, argv: list[str], timeout: int = 120, stdin: str | None = None) -> ExecResult:
        return ExecResult(argv, 1, "", "executor disabled in live tests", 0.0)

    def resolve(self, host: str) -> str:
        return "127.0.0.1"


def _engagement() -> Engagement:
    return Engagement(
        Scope(nets=["127.0.0.1/32"]), techniques=[web, core], executor=NoopExecutor(), policy=Policy.safe()
    )


def _noted(eng: Engagement) -> bool:
    return any("smoke test ok" in str(f.get("text", "")).lower() for f in eng.facts.query("note"))


def test_plain_chat_completions_loop() -> None:
    openai = pytest.importorskip("openai")
    key, base_url, model = _settings()
    client = openai.OpenAI(api_key=key, base_url=base_url, timeout=120)
    eng = _engagement()
    messages: list = [{"role": "user", "content": TASK}]
    for _ in range(6):
        reply = client.chat.completions.create(
            model=model, messages=messages, tools=openai_tools(eng), temperature=0
        )
        message = reply.choices[0].message
        messages.append(message.model_dump(exclude_none=True))
        if not message.tool_calls:
            break
        for call in message.tool_calls:
            text = run_tool(eng, call.function.name, call.function.arguments)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": text})
    assert _noted(eng), messages


def test_openai_agents_sdk() -> None:
    pytest.importorskip("agents")
    from agents import Agent, OpenAIChatCompletionsModel, Runner, set_tracing_disabled
    from openai import AsyncOpenAI

    from opgraph.adapters.openai_agents import to_function_tools

    key, base_url, model = _settings()
    set_tracing_disabled(True)
    eng = _engagement()
    agent = Agent(
        name="smoke",
        instructions="You follow instructions exactly.",
        model=OpenAIChatCompletionsModel(
            model=model, openai_client=AsyncOpenAI(api_key=key, base_url=base_url)
        ),
        tools=to_function_tools(eng),
    )
    asyncio.run(Runner.run(agent, TASK, max_turns=8))
    assert _noted(eng)
