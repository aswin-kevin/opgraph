"""Tool exposure: the generic tools module and each framework adapter, invoked through the
framework's own call path (no LLM involved)."""

from __future__ import annotations

import asyncio
import contextlib
import json

import pytest

from opgraph import Engagement, ExecResult, Policy, Scope, technique
from opgraph.packs import core, net, web
from opgraph.tools import anthropic_tools, openai_tools, run_tool, tool_specs


class FakeExecutor:
    def run(self, argv: list[str], timeout: int = 120, stdin: str | None = None) -> ExecResult:
        if argv[0] == "mktemp":
            return ExecResult(argv, 0, "/tmp/opgraph.TEST\n", "", 0.0)
        if argv[0] == "curl":
            return ExecResult(argv, 0, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Home</title>", "", 0.0)
        return ExecResult(argv, 0, "", "", 0.0)

    def resolve(self, host: str) -> str:
        return "127.0.0.1"


@pytest.fixture
def eng() -> Engagement:
    return Engagement(
        Scope(nets=["127.0.0.1/32"]),
        techniques=[web, net, core],
        executor=FakeExecutor(),
        policy=Policy.safe(),
    )


# ---- generic ----------------------------------------------------------------------------------------


def test_specs_cover_techniques_and_meta(eng: Engagement) -> None:
    names = [s.name for s in tool_specs(eng)]
    assert names == [
        "http_request",
        "dir_discovery",
        "port_scan",
        "shell",
        "note",
        "world",
        "propose_finding",
    ]
    http = next(s for s in tool_specs(eng) if s.name == "http_request")
    assert "Redirects are not followed" in http.description  # full docstring, not just the first line
    assert openai_tools(eng)[0]["function"]["parameters"]["required"] == ["url"]
    assert anthropic_tools(eng)[0]["input_schema"]["required"] == ["url"]


def test_meta_tool_names_are_reserved(eng: Engagement) -> None:
    @technique()
    def world() -> str:
        """Clashes."""
        return ""

    eng.add(world)
    with pytest.raises(ValueError, match="reserved"):
        tool_specs(eng)


def test_run_tool_never_raises(eng: Engagement) -> None:
    assert run_tool(eng, "world").startswith("KNOWN FACTS (0)")
    assert run_tool(eng, "http_request", '{"url": "http://127.0.0.1/"}').startswith("[ok] http_request")
    assert run_tool(eng, "http_request", "{not json").startswith("[error] http_request: arguments are not")
    assert run_tool(eng, "http_request", "[1, 2]").startswith("[error]")
    assert run_tool(eng, "http_request", {"url": "http://10.0.0.1/"}).startswith("[blocked]")
    assert run_tool(eng, "shell", {"command": "id"}).startswith("[blocked]")
    assert run_tool(eng, "nope").startswith("[blocked] nope")


def test_propose_finding(eng: Engagement) -> None:
    text = run_tool(eng, "propose_finding", {"vuln_class": "xss", "target": "http://127.0.0.1/q"})
    assert text == "[ok] propose_finding: recorded finding:xss|http://127.0.0.1/q (status: proposed)"
    assert run_tool(eng, "propose_finding", {"target": "x"}).startswith("[error]")
    assert "FINDING [proposed] xss" in run_tool(eng, "world")


# ---- OpenAI Agents SDK ------------------------------------------------------------------------------


def test_openai_agents_adapter(eng: Engagement) -> None:
    pytest.importorskip("agents")
    from opgraph.adapters.openai_agents import to_function_tools

    tools = {t.name: t for t in to_function_tools(eng)}
    assert set(tools) >= {"http_request", "world", "propose_finding"}
    assert tools["http_request"].params_json_schema["required"] == ["url"]

    # masking: dir_discovery is disabled until a web service or endpoint is known
    enabled = tools["dir_discovery"].is_enabled
    assert callable(enabled) and enabled(None, None) is False
    out = asyncio.run(tools["http_request"].on_invoke_tool(None, json.dumps({"url": "http://127.0.0.1/"})))  # type: ignore[arg-type]
    assert out.startswith("[ok] http_request")
    assert enabled(None, None) is True


# ---- MCP --------------------------------------------------------------------------------------------


def test_mcp_server_in_memory(eng: Engagement) -> None:
    pytest.importorskip("mcp")
    from mcp.client import Client

    from opgraph.adapters.mcp_server import create_server

    async def scenario() -> tuple[list, str, bool, str]:
        async with Client(create_server(eng)) as client:
            listed = await client.list_tools()
            ok = await client.call_tool("http_request", {"url": "http://127.0.0.1/"})
            blocked = await client.call_tool("http_request", {"url": "http://169.254.169.254/"})
            return listed.tools, ok.content[0].text, bool(blocked.is_error), blocked.content[0].text  # type: ignore[union-attr]

    tools, ok_text, blocked_is_error, blocked_text = asyncio.run(scenario())
    by_name = {t.name: t for t in tools}
    assert set(by_name) >= {"http_request", "port_scan", "shell", "world", "propose_finding"}
    assert by_name["shell"].annotations.destructive_hint is True
    assert by_name["note"].annotations.read_only_hint is True
    assert ok_text.startswith("[ok] http_request")
    assert blocked_is_error and "out_of_scope" in blocked_text


def test_mcp_cli_builds_engagement(tmp_path) -> None:
    pytest.importorskip("mcp")
    from opgraph.adapters.mcp_server import build_engagement, parse_args

    scope = tmp_path / "scope.json"
    scope.write_text('{"nets": ["127.0.0.1/32"]}')
    args = parse_args(["--scope", str(scope), "--pack", "web", "--policy", "lab"])
    built = build_engagement(args)
    assert sorted(built.techniques) == ["dir_discovery", "http_request"]
    assert built.scope.allows("http://127.0.0.1:8000/")
    built.close()


def test_mcp_cli_over_stdio(tmp_path) -> None:
    pytest.importorskip("mcp")
    import sys

    from mcp.client import Client
    from mcp.client.stdio import StdioServerParameters

    scope = tmp_path / "scope.json"
    scope.write_text('{"nets": ["127.0.0.1/32"]}')
    log = tmp_path / "events.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "opgraph.adapters.mcp_server", "--scope", str(scope), "--log", str(log)],
    )

    async def scenario() -> tuple[set[str], str]:
        async with Client(params) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            world = await client.call_tool("world", {})
            return tools, world.content[0].text  # type: ignore[union-attr]

    tools, world_text = asyncio.run(scenario())
    assert {"http_request", "port_scan", "dir_discovery", "shell", "note", "world"} <= tools
    assert world_text.startswith("KNOWN FACTS (0)")
    events = [json.loads(line)["event"] for line in log.read_text().splitlines()]
    assert events[0] == "start" and events[-1] == "dispose"  # cleanup ran when the server stopped


def test_meta_tool_annotations(eng: Engagement) -> None:
    pytest.importorskip("mcp")
    from opgraph.adapters.mcp_server import _annotations

    assert _annotations("world", "safe").read_only_hint is True
    assert _annotations("propose_finding", "safe").read_only_hint is False


def _cli(tmp_path, *extra: str) -> tuple[list[str], object]:
    import sys

    scope = tmp_path / "scope.json"
    scope.write_text('{"nets": ["127.0.0.1/32"]}')
    log = tmp_path / "events.jsonl"
    argv = [sys.executable, "-m", "opgraph.adapters.mcp_server", "--scope", str(scope), "--log", str(log)]
    return [*argv, *extra], log


def test_mcp_cli_cleans_up_on_sigterm(tmp_path) -> None:
    pytest.importorskip("mcp")
    import signal
    import subprocess
    import time

    argv, log = _cli(tmp_path)
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):  # wait until the engagement has started
        if log.exists() and log.read_text():  # type: ignore[union-attr]
            break
        time.sleep(0.05)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)
    proc.stdin.close()  # type: ignore[union-attr]
    proc.stdout.close()  # type: ignore[union-attr]
    proc.stderr.close()  # type: ignore[union-attr]
    events = [json.loads(line)["event"] for line in log.read_text().splitlines()]  # type: ignore[union-attr]
    assert events[-1] == "dispose"


def test_mcp_cli_cleans_up_when_client_leaves_mid_call(tmp_path) -> None:
    pytest.importorskip("mcp")
    import os
    import time

    from mcp.client import Client
    from mcp.client.stdio import StdioServerParameters

    argv, log = _cli(tmp_path, "--policy", "lab", "--pack", "core")
    params = StdioServerParameters(command=argv[0], args=argv[1:])

    async def scenario() -> None:
        async with Client(params) as client:
            call = asyncio.ensure_future(client.call_tool("shell", {"command": "sleep 30"}))
            await asyncio.sleep(1.5)
            call.cancel()

    started = time.monotonic()
    with contextlib.suppress(Exception):  # the cancelled call may surface as an exception group
        asyncio.run(scenario())
    assert time.monotonic() - started < 15
    for _ in range(100):
        rows = [json.loads(line) for line in log.read_text().splitlines()]  # type: ignore[union-attr]
        if rows and rows[-1]["event"] == "dispose":
            break
        time.sleep(0.1)
    assert rows[-1]["event"] == "dispose"
    workdirs = [line.split()[-1] for line in rows[-1]["lines"] if "workdir" in line]
    assert workdirs and not any(os.path.exists(path) for path in workdirs)


def test_mcp_cli_custom_pack_and_config(tmp_path) -> None:
    pytest.importorskip("mcp")
    from opgraph.adapters.mcp_server import build_engagement, parse_args

    scope = tmp_path / "scope.json"
    scope.write_text('{"nets": ["127.0.0.1/32"]}')
    config = tmp_path / "config.toml"
    config.write_text('http_proxy = "http://127.0.0.1:8080"\n[timeouts]\nshell = 30\n')
    args = parse_args(["--scope", str(scope), "--pack", "opgraph.packs.core", "--config", str(config)])
    built = build_engagement(args)
    assert sorted(built.techniques) == ["note", "shell"]
    assert built.config["timeouts"]["shell"] == 30
    built.close()
    with pytest.raises(SystemExit):
        parse_args(["--scope", str(scope), "--pack", "os; rm -rf /"])
