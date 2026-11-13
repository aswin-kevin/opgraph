"""Built-in techniques build the right argv and parse results (fake executor, no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opgraph import Engagement, ExecResult, LocalExecutor, Policy, Scope, endpoint
from opgraph.executors import remote_command
from opgraph.packs import core, net, web

FIXTURES = Path(__file__).parent / "fixtures"


class FakeExecutor:
    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.outputs = outputs or {}

    def run(self, argv: list[str], timeout: int = 120, stdin: str | None = None) -> ExecResult:
        self.calls.append((argv, stdin))
        if argv[0] == "mktemp":
            return ExecResult(argv, 0, "/tmp/opgraph.TEST\n", "", 0.0)
        return ExecResult(argv, 0, self.outputs.get(argv[0], ""), "", 0.0)

    def resolve(self, host: str) -> str:
        return "127.0.0.1"

    def last(self, tool: str) -> tuple[list[str], str | None]:
        return next(c for c in reversed(self.calls) if c[0][0] == tool)


def make(ex: FakeExecutor, policy: Policy | None = None) -> Engagement:
    scope = Scope(nets=["127.0.0.1/32"], domains=["lab.test"])
    return Engagement(scope, techniques=[web, net, core], executor=ex, policy=policy)


def test_http_request_argv() -> None:
    ex = FakeExecutor({"curl": (FIXTURES / "curl.txt").read_text()})
    eng = make(ex)
    r = eng.call(
        "http_request",
        {
            "url": "http://app.lab.test:8000/login",
            "method": "POST",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "u=admin&p=x",
            "session": "admin",
        },
    )
    assert r.ok, r.to_tool_text()
    argv, stdin = ex.last("curl")
    assert "-L" not in argv and "--location" not in argv
    assert argv[argv.index("--connect-to") + 1] == "::127.0.0.1:8000"
    assert argv[argv.index("-b") + 1] == "/tmp/opgraph.TEST/cookies-admin.txt"
    assert argv[argv.index("-X") + 1] == "POST"
    assert argv[-2:] == ["--", "http://app.lab.test:8000/login"]
    assert stdin == "u=admin&p=x"
    assert "Acme Admin Portal" in r.text
    assert eng.facts.query("endpoint")


def test_http_request_rejects_bad_input() -> None:
    eng = make(FakeExecutor())
    bad_header = eng.call("http_request", {"url": "http://127.0.0.1/", "headers": {"X": "a\r\nInjected: 1"}})
    assert "invalid header" in bad_header.text
    assert "session" in eng.call("http_request", {"url": "http://127.0.0.1/", "session": "../x"}).text
    assert eng.call("http_request", {"url": "http://169.254.169.254/"}).blocked


def test_dir_discovery_needs_web_and_uses_ffuf() -> None:
    rows = [{"url": "http://127.0.0.1:8000/admin", "status": 301, "length": 0, "redirectlocation": "/admin/"}]
    ex = FakeExecutor({"ffuf": "\n".join(json.dumps(r) for r in rows)})
    eng = make(ex)
    assert eng.call("dir_discovery", {"base_url": "http://127.0.0.1:8000/"}).blocked
    eng.facts.add([endpoint("http://127.0.0.1:8000/")])
    r = eng.call("dir_discovery", {"base_url": "http://127.0.0.1:8000/", "extensions": "php,txt"})
    assert r.ok
    argv, _ = ex.last("ffuf")
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1:8000/FUZZ"
    assert argv[argv.index("-t") + 1] == "10" and argv[argv.index("-rate") + 1] == "50"
    assert argv[argv.index("-e") + 1] == ".php,.txt"
    assert "1 paths found" in r.text
    assert eng.facts.get("endpoint:http://127.0.0.1:8000/admin") is not None


def test_dir_discovery_pins_hostname_for_http() -> None:
    rows = [{"url": "http://127.0.0.1:8000/secret", "status": 200, "length": 5}]
    ex = FakeExecutor({"ffuf": json.dumps(rows[0])})
    eng = make(ex)
    eng.facts.add([endpoint("http://app.lab.test:8000/")])
    assert eng.call("dir_discovery", {"base_url": "http://app.lab.test:8000"}).ok
    argv, _ = ex.last("ffuf")
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1:8000/FUZZ"
    assert "Host: app.lab.test:8000" in argv
    assert eng.facts.get("endpoint:http://app.lab.test:8000/secret") is not None


def test_port_scan_argv_and_facts() -> None:
    ex = FakeExecutor({"nmap": (FIXTURES / "nmapA.xml").read_text()})
    eng = make(ex)
    r = eng.call("port_scan", {"host": "127.0.0.1", "ports": "21,80,8000-8100"})
    assert r.ok
    argv, _ = ex.last("nmap")
    assert argv[argv.index("-p") + 1] == "21,80,8000-8100"
    assert "-T3" in argv and argv[-1] == "127.0.0.1"
    assert "5 open ports" in r.text
    assert "ports must be" in eng.call("port_scan", {"host": "127.0.0.1", "ports": "1; rm -rf /"}).text


def test_port_scan_keys_by_hostname() -> None:
    ex = FakeExecutor({"nmap": (FIXTURES / "nmapA.xml").read_text()})
    eng = make(ex)
    eng.call("port_scan", {"host": "app.lab.test"})
    svc = eng.facts.query("service")[0]
    assert svc.get("host") == "app.lab.test" and svc.get("ip")
    assert ex.last("nmap")[0][-1] == "127.0.0.1"


def test_shell_needs_approval_and_audits_scope() -> None:
    ex = FakeExecutor({"bash": "found http://127.0.0.1:8000/hidden\n"})
    assert make(ex).call("shell", {"command": "id"}).blocked
    eng = make(ex, Policy.lab())
    r = eng.call("shell", {"command": "curl http://127.0.0.1:8000/ ; curl http://10.1.1.1/"})
    argv, _ = ex.last("bash")
    assert argv[:2] == ["bash", "-c"] and argv[2].startswith("cd /tmp/opgraph.TEST && ")
    assert "[scope warning]" in r.text and "10.1.1.1" in r.text
    assert eng.facts.get("endpoint:http://127.0.0.1:8000/hidden") is not None


def test_note() -> None:
    eng = make(FakeExecutor())
    eng.call("note", {"text": "try default creds on /admin"})
    assert "NOTE try default creds on /admin" in eng.world()


def test_local_executor() -> None:
    ex = LocalExecutor()
    r = ex.run(["echo", "hi"])
    assert r.ok and r.stdout == "hi\n"
    r = ex.run(["cat"], stdin="piped")
    assert r.stdout == "piped"
    r = ex.run(["sleep", "5"], timeout=1)
    assert r.timed_out and not r.ok and r.duration < 4
    r = ex.run(["definitely-not-a-binary-xyz"])
    assert r.rc == 127
    with pytest.raises(TypeError):
        ex.run("echo hi")  # type: ignore[arg-type]


def test_remote_command_quoting() -> None:
    cmd = remote_command(["curl", "-H", "X: a b", "http://h/?a=1&b=$(id)"], 30)
    assert cmd == "timeout -k 5 30 curl -H 'X: a b' 'http://h/?a=1&b=$(id)'"


def test_http_request_secret_handles_in_headers() -> None:
    ex = FakeExecutor({"curl": "HTTP/1.1 200 OK\r\n\r\n"})
    eng = make(ex)
    eng._store_secret("Bearer s3cr3t-token")
    eng.call("http_request", {"url": "http://127.0.0.1/", "headers": {"Authorization": "{{cred:1}}"}})
    argv, _ = ex.last("curl")
    assert "Authorization: Bearer s3cr3t-token" in argv  # the tool gets the real value
    logged = [e for e in eng.ledger.events if e["event"] == "exec" and e["argv"][0] == "curl"]
    assert "Authorization: {{cred:1}}" in logged[-1]["argv"]  # the log only has the handle


def test_dir_discovery_rejects_fuzz_keyword_and_normalises() -> None:
    ex = FakeExecutor()
    eng = make(ex)
    eng.facts.add([endpoint("http://127.0.0.1:8000/")])
    r = eng.call("dir_discovery", {"base_url": "http://127.0.0.1:8000/FUZZ/"})
    assert "FUZZ" in r.text and not any(c[0][0] == "ffuf" for c in ex.calls)
    eng.call("dir_discovery", {"base_url": "HTTP://127.0.0.1:8000/App?x=1"})
    argv, _ = ex.last("ffuf")
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1:8000/App/FUZZ"


def test_port_scan_respects_scope_ports() -> None:
    ex = FakeExecutor({"nmap": ""})
    eng = Engagement(Scope(nets=["127.0.0.1/32"], ports=[80, 443]), techniques=[net], executor=ex)
    r = eng.call("port_scan", {"host": "127.0.0.1", "ports": "1-65535"})
    assert "ports outside scope" in r.text and not any(c[0][0] == "nmap" for c in ex.calls)
    eng.call("port_scan", {"host": "127.0.0.1"})  # top-100 becomes exactly the scope's ports
    argv, _ = ex.last("nmap")
    assert argv[argv.index("-p") + 1] == "80,443" and "--top-ports" not in argv
    assert eng.call("port_scan", {"host": "127.0.0.1", "ports": "80"}).ok
