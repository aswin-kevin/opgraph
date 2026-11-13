"""The extension points builders rely on: config, custom policies, networks, list targets,
custom schemas, env, events, structured output and tool filtering."""

from __future__ import annotations

import json
from typing import Annotated

import pytest

from opgraph import (
    Ctx,
    Engagement,
    ExecResult,
    Host,
    LocalExecutor,
    Network,
    Policy,
    Scope,
    Target,
    endpoint,
    technique,
)
from opgraph.executors import remote_command
from opgraph.packs import core, net, web
from opgraph.tools import openai_tools, run_tool, tool_specs


class FakeExecutor:
    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.calls: list[dict] = []
        self.outputs = outputs or {}

    def run(self, argv, timeout=120, stdin=None, env=None) -> ExecResult:  # type: ignore[no-untyped-def]
        self.calls.append({"argv": argv, "timeout": timeout, "env": env})
        if argv[0] == "mktemp":
            return ExecResult(argv, 0, "/tmp/opgraph.TEST\n", "", 0.0)
        return ExecResult(argv, 0, self.outputs.get(argv[0], ""), "", 0.0)

    def resolve(self, host: str) -> str:
        return "10.0.0.5"

    def argv(self, tool: str) -> list[str]:
        return next(c["argv"] for c in reversed(self.calls) if c["argv"][0] == tool)


def make(ex: FakeExecutor, techniques=(web, net, core), **kw) -> Engagement:  # type: ignore[no-untyped-def]
    scope = Scope(nets=["10.0.0.0/24"], domains=["lab.test"])
    return Engagement(scope, techniques=techniques, executor=ex, **kw)


# ---- networks and schemes ---------------------------------------------------------------------------


def test_cidr_ranges_checked_as_a_whole() -> None:
    scope = Scope(nets=["10.0.0.0/16"], exclude=["10.0.9.0/24"])
    assert scope.check("10.0.1.0/24").ip == "10.0.1.0/24"
    assert scope.allows("10.0.1.7/24")  # host bits are normalised away
    assert not scope.allows("10.0.0.0/8")  # larger than the scope
    assert not scope.allows("10.0.8.0/23")  # overlaps an exclusion
    assert not scope.allows("192.168.0.0/24")


def test_unknown_scheme_needs_explicit_port_when_ports_restricted() -> None:
    scope = Scope(nets=["10.0.0.0/24"], ports=[6379, 8080])
    assert scope.allows("redis://10.0.0.5/")  # known default port 6379
    assert not scope.allows("mysql://10.0.0.5/")  # 3306 not allowed
    assert not scope.allows("weird://10.0.0.5/")  # unknown default port: fail closed
    assert scope.allows("weird://10.0.0.5:8080/")
    assert Scope(nets=["10.0.0.0/24"]).allows("weird://10.0.0.5/")  # no port restriction


def test_port_scan_accepts_ranges() -> None:
    ex = FakeExecutor()
    eng = make(ex)
    assert eng.call("port_scan", {"host": "10.0.0.0/28"}).ok
    assert ex.argv("nmap")[-1] == "10.0.0.0/28"
    assert eng.call("port_scan", {"host": "10.0.0.0/8"}).blocked


# ---- technique definitions --------------------------------------------------------------------------


@technique(risk="intrusive")
def ping_all(ctx: Ctx, hosts: list[Host]) -> str:
    """Ping several hosts."""
    return " ".join(c.ip for c in ctx.target_lists["hosts"])


def test_list_targets_are_scope_checked() -> None:
    eng = make(FakeExecutor(), techniques=[ping_all])
    r = eng.call("ping_all", {"hosts": ["10.0.0.5", "app.lab.test"]})
    assert r.ok and "10.0.0.5 10.0.0.5" in r.text
    blocked = eng.call("ping_all", {"hosts": ["10.0.0.5", "8.8.8.8"]})
    assert blocked.blocked and "8.8.8.8" in blocked.blocked
    assert {"technique": "ping_all", "target": "app.lab.test", "count": 1} in eng.report()["coverage"]


def test_nested_targets_rejected_at_definition() -> None:
    with pytest.raises(TypeError, match="cannot be scope-checked"):

        @technique()
        def bad(targets: dict[str, Host]) -> str:
            """Nope."""
            return ""


def test_custom_schema() -> None:
    schema = {"type": "object", "properties": {"query": {"type": "object"}}, "required": ["query"]}

    @technique(schema=schema)
    def graphql(query: dict) -> str:
        """Send a GraphQL query."""
        return json.dumps(query)

    eng = make(FakeExecutor(), techniques=[graphql])
    assert tool_specs(eng, include_meta=False)[0].parameters == schema
    assert eng.call("graphql", {"query": {"q": "{ me }"}}).ok


def test_policy_subclass_sees_targets_and_tags() -> None:
    class NoProduction(Policy):
        def decide(self, request):  # type: ignore[no-untyped-def]
            if any(t.startswith("10.0.0.5") for t in request.targets):
                return "deny"
            return super().decide(request)

    eng = make(FakeExecutor(), policy=NoProduction())
    assert eng.call("port_scan", {"host": "10.0.0.5"}).blocked
    assert eng.call("port_scan", {"host": "10.0.0.6"}).ok

    class Broken(Policy):
        def decide(self, request):  # type: ignore[no-untyped-def]
            return "maybe"

    assert make(FakeExecutor(), policy=Broken()).call("note", {"text": "x"}).blocked


# ---- config -----------------------------------------------------------------------------------------


def test_config_drives_tools_timeouts_and_options() -> None:
    ex = FakeExecutor()
    config = {
        "tools": {"nmap": "/opt/nmap/bin/nmap", "ffuf": "/opt/ffuf"},
        "timeouts": {"port_scan": 90},
        "port_scan": {"timing": "T2", "scripts": ""},
        "dir_discovery": {"threads": 2, "rate": 5},
        "wordlists": {"api": "/data/api-words.txt"},
        "http_proxy": "http://127.0.0.1:8080",
        "http_headers": {"X-Bug-Bounty": "researcher-123"},
    }
    eng = make(ex, config=config)
    eng.call("port_scan", {"host": "10.0.0.5"})
    nmap = ex.argv("/opt/nmap/bin/nmap")
    assert "-T2" in nmap and "--script" not in nmap
    assert next(c["timeout"] for c in ex.calls if c["argv"][0].endswith("nmap")) == 90

    eng.facts.add([endpoint("http://10.0.0.5/")])
    assert eng.call("dir_discovery", {"base_url": "http://10.0.0.5", "wordlist": "api"}).ok
    ffuf = ex.argv("/opt/ffuf")
    assert ffuf[ffuf.index("-w") + 1] == "/data/api-words.txt"
    assert ffuf[ffuf.index("-t") + 1] == "2" and ffuf[ffuf.index("-rate") + 1] == "5"
    assert ffuf[ffuf.index("-x") + 1] == "http://127.0.0.1:8080"
    assert "X-Bug-Bounty: researcher-123" in ffuf
    assert (
        "unknown wordlist" in eng.call("dir_discovery", {"base_url": "http://10.0.0.5", "wordlist": "x"}).text
    )

    eng.call("http_request", {"url": "http://10.0.0.5/"})
    curl = ex.argv("curl")
    assert "X-Bug-Bounty: researcher-123" in curl and curl[curl.index("-x") + 1] == "http://127.0.0.1:8080"


def test_invalid_options_are_rejected() -> None:
    eng = make(FakeExecutor(), config={"port_scan": {"timing": "T9"}})
    assert "timing option" in eng.call("port_scan", {"host": "10.0.0.5"}).text


# ---- env, events, structured output -----------------------------------------------------------------


def test_env_reaches_executor() -> None:
    @technique()
    def with_env(ctx: Ctx) -> str:
        """Uses an env var."""
        return ctx.exec(["tool"], env={"API_TOKEN": "x"}).stdout

    ex = FakeExecutor()
    make(ex, techniques=[with_env]).call("with_env")
    assert ex.calls[-1]["env"] == {"API_TOKEN": "x"}
    assert LocalExecutor().run(["sh", "-c", "echo $OPGRAPH_T"], env={"OPGRAPH_T": "v"}).stdout == "v\n"
    assert remote_command(["id"], 5, {"A": "b c"}) == "timeout -k 5 5 env 'A=b c' id"
    with pytest.raises(ValueError):
        remote_command(["id"], 5, {"BAD-NAME": "x"})


def test_events_snapshot_and_dicts() -> None:
    eng = make(FakeExecutor())
    seen: list[str] = []
    unsubscribe = eng.ledger.subscribe(lambda e: seen.append(e["event"]))
    eng.ledger.subscribe(lambda e: 1 / 0)  # a broken observer must not break anything
    r = eng.call("note", {"text": "hello"})
    unsubscribe()
    assert "call" in seen and "result" in seen
    assert r.to_dict()["new_facts"][0]["kind"] == "note"
    snap = eng.snapshot()
    available = {t["name"]: t["available"] for t in snap["techniques"]}
    assert available["note"] is True and available["dir_discovery"] is False
    assert snap["facts"][0]["kind"] == "note"


# ---- tool filtering ---------------------------------------------------------------------------------


def test_tool_filtering_is_enforced() -> None:
    eng = make(FakeExecutor())
    recon = ["port_scan", "note"]
    assert [t["function"]["name"] for t in openai_tools(eng, recon, include_meta=False)] == recon
    assert run_tool(eng, "shell", {"command": "id"}, names=recon).startswith("[blocked] shell: this tool")
    assert run_tool(eng, "world", names=recon, include_meta=False).startswith("[blocked]")
    assert run_tool(eng, "note", {"text": "x"}, names=recon).startswith("[ok]")
    with pytest.raises(ValueError, match="unknown techniques"):
        tool_specs(eng, ["nope"])


def test_network_type_rejects_urls() -> None:
    @technique()
    def sweep(target: Annotated[Network, "range"]) -> str:
        """Sweep."""
        return ""

    eng = make(FakeExecutor(), techniques=[sweep])
    assert "not a URL" in (eng.call("sweep", {"target": "http://10.0.0.5/"}).blocked or "")


# ---- review regressions -----------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["app.lab.test/8", "10.5/8", "evil/0"])
def test_name_with_cidr_suffix_is_refused(value: str) -> None:
    eng = make(FakeExecutor())
    assert eng.call("port_scan", {"host": value}).blocked


@pytest.mark.parametrize("value", ["::ffff:169.254.0.0/112", "64:ff9b::a9fe:0/112", "::ffff:10.0.0.0/120"])
def test_ipv6_ranges_embedding_ipv4_refused(value: str) -> None:
    scope = Scope(nets=["::/0", "10.0.0.0/24"], exclude=["10.0.0.6"])
    assert not scope.allows(value)


def test_target_defaults_rejected() -> None:
    with pytest.raises(TypeError, match="cannot have a default"):

        @technique()
        def bad(hosts: list[Host] = ["8.8.8.8"]) -> str:  # noqa: B006
            """Nope."""
            return ""


def test_ranges_only_for_network_params() -> None:
    @technique()
    def generic(t: Target) -> str:
        """Takes any target."""
        return ""

    eng = make(FakeExecutor(), techniques=[generic, ping_all])
    assert "only Network parameters take ranges" in (eng.call("generic", {"t": "10.0.0.5/32"}).blocked or "")
    assert eng.call("ping_all", {"hosts": ["10.0.0.0/30"]}).blocked


def test_scanner_parsers_survive_garbage() -> None:
    from opgraph import parsers

    rows = [
        {"template-id": "a", "info": "str", "matched-at": "http://h/a"},
        {"template-id": "b", "info": {}, "matched-at": "http://[bad/"},
        {"template-id": "c", "info": {"tags": "technology"}, "matched-at": "http://h/c"},
    ]
    facts = parsers.nuclei_jsonl("\n".join(json.dumps(r) for r in rows))
    assert {f.get("vuln_class") for f in facts if f.kind == "finding"} == {"a", "c"}
    httpx = [{"url": "http://a b/"}, {"url": "http://h/", "tech": "nginx"}]
    facts = parsers.httpx_jsonl("\n".join(json.dumps(r) for r in httpx))
    assert [f.get("name") for f in facts if f.kind == "tech"] == ["nginx"]


def test_report_escapes_status_and_odd_keys() -> None:
    from opgraph import Fact
    from opgraph.report import to_markdown

    @technique()
    def emit() -> list:
        """Emits odd findings."""
        return [
            Fact("finding", ("xss", "http://10.0.0.5/"), {"status": "**CONFIRMED** <img src=x>"}),
            Fact("finding", ("solo",), {"status": "proposed"}),
        ]

    eng = make(FakeExecutor(), techniques=[emit])
    eng.call("emit")
    md = to_markdown(eng)
    assert "### UNKNOWN: `xss` at `http://10.0.0.5/`" in md and "<img" not in md
    assert "### PROPOSED: `solo`" in md


def test_mandatory_headers_win() -> None:
    ex = FakeExecutor()
    eng = make(ex, config={"http_headers": {"X-Bug-Bounty": "researcher-123"}})
    eng.call("http_request", {"url": "http://10.0.0.5/", "headers": {"x-bug-bounty": "", "A": "b"}})
    curl = ex.argv("curl")
    assert "X-Bug-Bounty: researcher-123" in curl and "x-bug-bounty: " not in curl and "A: b" in curl


def test_names_must_not_be_a_string() -> None:
    eng = make(FakeExecutor())
    with pytest.raises(TypeError):
        run_tool(eng, "note", {"text": "x"}, names="xnotex")  # type: ignore[arg-type]


def test_listeners_get_copies_and_kinds_are_stable() -> None:
    from opgraph.facts import define_kind

    eng = make(FakeExecutor())
    eng.ledger.subscribe(lambda e: e.update(event="tampered"))
    eng.call("note", {"text": "x"})
    assert "tampered" not in {e["event"] for e in eng.ledger.events}
    define_kind("smb_share", ("host", "share"))
    define_kind("smb_share", ("host", "share"))  # same definition: fine
    with pytest.raises(ValueError, match="already defined"):
        define_kind("smb_share", ("share",))


def test_env_on_executor_without_env_support() -> None:
    class Minimal:
        def run(self, argv, timeout=120, stdin=None):  # type: ignore[no-untyped-def]
            return ExecResult(argv, 0, "", "", 0.0)

        def resolve(self, host: str) -> str:
            return "10.0.0.5"

    @technique()
    def needs_env(ctx: Ctx) -> str:
        """Uses env."""
        return ctx.exec(["x"], env={"A": "b"}).stdout

    r = make(FakeExecutor(), techniques=[needs_env]).call("needs_env")
    assert r.ok
    eng = Engagement(Scope(), techniques=[needs_env], executor=Minimal())  # type: ignore[arg-type]
    assert "does not accept env=" in eng.call("needs_env").text


def test_technique_named_like_meta_tool_when_meta_disabled() -> None:
    @technique()
    def world() -> str:
        """My own world tool."""
        return "custom world"

    eng = make(FakeExecutor(), techniques=[world])
    assert "custom world" in run_tool(eng, "world", include_meta=False)
