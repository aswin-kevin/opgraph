"""Loop guard, budgets, coverage gaps, durable resume and canary validation."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from opgraph import (
    Budget,
    CanaryCheck,
    Ctx,
    Engagement,
    ExecResult,
    Fact,
    Host,
    Policy,
    Scope,
    TechniqueResult,
    artifact,
    endpoint,
    service,
    technique,
)
from opgraph.packs import core, web
from opgraph.tools import run_tool


class FakeExecutor:
    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.outputs = outputs or {}
        self._lock = threading.Lock()

    def run(self, argv: list[str], timeout: int = 120, stdin: str | None = None) -> ExecResult:
        with self._lock:
            self.calls.append(argv)
        if argv[0] == "mktemp":
            return ExecResult(argv, 0, "/tmp/opgraph.RESUME\n", "", 0.0)
        return ExecResult(argv, 0, self.outputs.get(argv[0], ""), "", 0.0)

    def resolve(self, host: str) -> str:
        return "10.0.0.5"


@technique(risk="safe")
def probe(host: Host, mode: str = "a") -> str:
    """Probe a host."""
    return f"probed {host} {mode}"


def make(ex: FakeExecutor | None = None, **kw) -> Engagement:  # type: ignore[no-untyped-def]
    kw.setdefault("techniques", [probe, web, core])
    return Engagement(Scope(nets=["10.0.0.0/24"]), executor=ex or FakeExecutor(), **kw)


# ---- loop guard -------------------------------------------------------------------------------------


def test_identical_calls_are_refused_after_the_limit() -> None:
    eng = make()
    for _ in range(3):
        assert eng.call("probe", {"host": "10.0.0.5"}).ok
    r = eng.call("probe", {"host": "10.0.0.5"})
    assert r.blocked and r.blocked.startswith("repeated") and "last: c3" in r.blocked
    assert eng.call("probe", {"host": "10.0.0.5", "mode": "b"}).ok  # different arguments are fine
    unlimited = make(budget=Budget(repeat_limit=None))
    assert all(unlimited.call("probe", {"host": "10.0.0.5"}).ok for _ in range(6))


# ---- budgets ----------------------------------------------------------------------------------------


def test_budgets_stop_work() -> None:
    eng = make(budget=Budget(max_calls=3, per_technique={"probe": 2}, per_target=10))
    assert eng.call("probe", {"host": "10.0.0.5"}).ok
    assert eng.call("probe", {"host": "10.0.0.6"}).ok
    r = eng.call("probe", {"host": "10.0.0.7"})
    assert r.blocked and "budget for probe exhausted" in r.blocked
    assert eng.call("note", {"text": "x"}).ok
    r = eng.call("note", {"text": "y"})
    assert r.blocked and "summarize findings and stop" in r.blocked
    assert eng.call("probe", {"host": "8.8.8.8"}).blocked  # refused calls never spend budget
    assert eng.budget_status()["calls"] == 3
    assert "BUDGET: calls 3/3, probe 2/2" in eng.world()


def test_per_target_and_time_budgets() -> None:
    eng = make(budget=Budget(per_target=1))
    assert eng.call("probe", {"host": "10.0.0.5"}).ok
    assert "budget for target 10.0.0.5" in (
        eng.call("probe", {"host": "10.0.0.5", "mode": "b"}).blocked or ""
    )
    timed = make(budget=Budget(max_seconds=60))
    timed.started = time.time() - 61
    assert "time limit" in (timed.call("probe", {"host": "10.0.0.5"}).blocked or "")


def test_budget_holds_under_parallel_calls() -> None:
    eng = make(budget=Budget(max_calls=5, repeat_limit=None))
    results = []
    threads = [
        threading.Thread(target=lambda i=i: results.append(eng.call("probe", {"host": f"10.0.0.{i}"})))
        for i in range(1, 21)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r.ok for r in results) == 5


# ---- coverage gaps ----------------------------------------------------------------------------------


def test_untried_suggestions_and_saturation() -> None:
    ex = FakeExecutor({"curl": "HTTP/1.1 200 OK\r\n\r\n"})
    eng = make(ex)
    eng.facts.add(
        [
            service("10.0.0.5", 8080, name="http"),
            endpoint("http://10.0.0.5:8080/login"),  # discovered, never requested
            endpoint("http://10.0.0.9:9999/other"),
            endpoint("http://203.0.113.1/outside"),  # out of scope: never suggested
        ]
    )
    untried = eng.untried()
    assert {"technique": "dir_discovery", "args": {"base_url": "http://10.0.0.5:8080"}} in untried
    assert {"technique": "http_request", "args": {"url": "http://10.0.0.5:8080/login"}} in untried
    assert not any("203.0.113.1" in json.dumps(u) for u in untried)
    assert "UNTRIED (suggested next" in eng.world()

    for u in untried:
        eng.call(u["technique"], u["args"])
    assert eng.untried() == []
    assert "UNTRIED: none (every in-scope suggestion has been tried)" in eng.world()


# ---- durable resume ---------------------------------------------------------------------------------

REMOVED: list[str] = []


def _remove(ctx: Ctx, art: Fact) -> None:
    REMOVED.append(art.get("name"))


@technique(risk="destructive", undo=_remove)
def plant(ctx: Ctx, host: Host, name: str) -> TechniqueResult:
    """Create a file on the target."""
    ctx.workdir()
    return TechniqueResult(observation="planted", artifacts=[artifact(host, name)])


@technique(risk="destructive")
def deferring(ctx: Ctx) -> str:
    """Registers an ad-hoc cleanup."""
    ctx.defer("temp user", lambda: None)
    return "ok"


def test_resume_restores_state_and_cleanup_obligations(tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    first_ex = FakeExecutor()
    first = make(first_ex, techniques=[probe, plant, deferring], policy=Policy.lab(), log_path=log)
    for _ in range(3):
        first.call("probe", {"host": "10.0.0.5"})
    first.call("plant", {"host": "10.0.0.5", "name": "webshell.php"})
    with first.phase("probe-write"):  # cleaned when the phase ends, before the crash
        first.call("plant", {"host": "10.0.0.5", "name": "canary.txt"})
    first.call("deferring")
    first.ledger.close()  # crash: no dispose

    REMOVED.clear()
    ex = FakeExecutor()
    eng = Engagement.resume(
        log,
        Scope(nets=["10.0.0.0/24"]),
        techniques=[probe, plant, deferring],
        executor=ex,
        policy=Policy.lab(),
    )
    assert eng.facts.get("artifact:10.0.0.5|webshell.php") is not None
    assert eng.call("probe", {"host": "10.0.0.5"}).blocked  # repetition count survived
    assert eng.call("note_missing").call_id == "c8"  # numbering continues after c7
    lines = eng.dispose()
    assert REMOVED == ["webshell.php"]  # cleaned in the earlier run, so not again
    assert any(line.startswith("cleaned  workdir /tmp/opgraph.RESUME") for line in lines)
    assert any("temp user" in line and line.startswith("RESIDUE") for line in lines)
    assert ["rm", "-rf", "--", "/tmp/opgraph.RESUME"] in ex.calls
    fact_rows = [json.loads(x) for x in log.read_text().splitlines() if '"event": "fact"' in x]
    assert len(fact_rows) == len({(r["change"], json.dumps(r["fact"]["key"]), r["seq"]) for r in fact_rows})
    second = Engagement.resume(log, Scope(nets=["10.0.0.0/24"]), techniques=[probe, plant, deferring])
    # only the cleanup that needs a human is still pending; an operator can acknowledge it
    assert second.effects.pending() == ["temp user (by deferring c6)"]
    assert second.mark_cleaned("temp user (by deferring c6)", note="deleted the account by hand")
    second.close()
    third = Engagement.resume(log, Scope(nets=["10.0.0.0/24"]), techniques=[probe, plant, deferring])
    assert third.effects.pending() == []
    third.close()


# ---- canaries ---------------------------------------------------------------------------------------


def test_canary_confirms_only_unfakeable_returns() -> None:
    ex = FakeExecutor()
    eng = make(ex, policy=Policy.lab())
    token = eng.canary("stored comment")
    finding = eng.propose_finding("stored-xss", "http://10.0.0.5/comments")

    ex.outputs["curl"] = f"HTTP/1.1 200 OK\r\n\r\nthanks {token}"  # echoed in the submitting call
    eng.call("http_request", {"url": "http://10.0.0.5/comments", "method": "POST", "body": f"c={token}"})
    ex.outputs["bash"] = token
    eng.call("shell", {"command": f"echo {token}"})  # the agent printing it proves nothing
    assert eng.verify(finding.id, CanaryCheck(token)).get("status") == "proposed"

    ex.outputs["curl"] = f"HTTP/1.1 200 OK\r\n\r\n<li>{token}</li>"  # shows up on a later page
    eng.call("http_request", {"url": "http://10.0.0.5/comments"})
    confirmed = eng.verify(finding.id, CanaryCheck(token))
    assert confirmed.get("status") == "confirmed" and "canary returned" in confirmed.get("evidence")


def test_canary_external_source_and_meta_tool() -> None:
    eng = make()
    text = run_tool(eng, "canary", {"label": "ssrf callback"})
    token = text.split()[2]
    assert token.startswith("opgc") and len(token) == 24
    finding = eng.propose_finding("ssrf", "http://10.0.0.5/fetch")

    def oob_log() -> list[str]:
        return [f"GET /{token} from 10.0.0.5"]

    assert eng.verify(finding.id, CanaryCheck(token, sources=[oob_log])).get("status") == "confirmed"


# ---- review regressions -----------------------------------------------------------------------------


def test_canary_not_faked_by_encodings_or_other_hosts() -> None:
    import base64
    from urllib.parse import quote

    ex = FakeExecutor()
    eng = make(ex, techniques=[web], policy=Policy.lab())
    token = eng.canary()
    f = eng.propose_finding("stored-xss", "http://10.0.0.5/comments")
    other = eng.propose_finding("rce", "http://10.0.0.99/")
    ex.outputs["curl"] = f"HTTP/1.1 200 OK\r\n\r\n{token}"
    encoded = "".join(f"%{ord(c):02x}" for c in token)
    eng.call("http_request", {"url": f"http://10.0.0.5/echo?q={encoded}"})
    b64 = base64.b64encode(token.encode()).decode()
    eng.call("http_request", {"url": "http://10.0.0.5/b64", "body": f"d={b64}", "method": "POST"})
    eng.call("http_request", {"url": f"http://10.0.0.5/x?{quote(token.upper())}"})
    assert eng.verify(f.id, CanaryCheck(token)).get("status") == "proposed"
    eng.call("http_request", {"url": "http://10.0.0.5/comments"})  # genuinely stored and returned
    assert eng.verify(other.id, CanaryCheck(token)).get("status") == "proposed"  # wrong host
    assert eng.verify(f.id, CanaryCheck(token, techniques={"shell"})).get("status") == "proposed"
    assert eng.verify(f.id, CanaryCheck(token)).get("status") == "confirmed"


def test_resume_refuses_dangerous_paths_and_out_of_scope_artifacts(tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    rows = [
        {"seq": 0, "ts": 1.0, "event": "start", "name": "x", "scope": {}},
        {"seq": 1, "ts": 1.0, "event": "cleanup_registered", "label": "workdir evil", "kind": "workdir",
         "root": True, "path": "/tmp/opgraph.x/../../../Users/victim"},
        {"seq": 2, "ts": 1.0, "event": "cleanup_registered", "label": "artifact elsewhere",
         "kind": "artifact", "technique": "plant", "call_id": "c1",
         "fact": artifact("203.0.113.7", "shell.php").to_dict()},
    ]  # fmt: skip
    log.write_text("".join(json.dumps(r) + "\n" for r in rows) + '{"seq": 3, "event": "cal')  # torn line
    REMOVED.clear()
    ex = FakeExecutor()
    eng = Engagement.resume(log, Scope(nets=["10.0.0.0/24"]), techniques=[plant], executor=ex)
    lines = eng.dispose()
    assert not any(c[0] == "rm" for c in ex.calls)
    assert REMOVED == [] and all(line.startswith("RESIDUE") for line in lines)
    assert all(json.loads(x) for x in log.read_text().splitlines()[4:])  # new events on fresh lines


def test_failed_calls_do_not_count_as_repeats() -> None:
    @technique()
    def flaky(host: Host) -> str:
        """Always times out."""
        raise TimeoutError("timed out")

    eng = make(techniques=[flaky])
    results = [eng.call("flaky", {"host": "10.0.0.5"}) for _ in range(5)]
    assert all(r.blocked is None for r in results)


def test_broken_suggest_never_breaks_world_and_world_does_no_dns() -> None:
    def broken(fact: Fact) -> dict:
        raise RuntimeError("bug in third-party code")

    @technique(suggest=broken)
    def scan(host: Host) -> str:
        """Scan."""
        return ""

    lookups: list[str] = []

    class CountingExecutor(FakeExecutor):
        def resolve(self, host: str) -> str:
            lookups.append(host)
            return "10.0.0.5"

    eng = Engagement(Scope(domains=["lab.test"]), techniques=[scan, web], executor=CountingExecutor())
    eng.facts.add([endpoint(f"http://h{i}.lab.test/x") for i in range(50)])
    assert "UNTRIED" in eng.world() and lookups == []


def test_duplicate_cleanup_labels_are_tracked_separately(tmp_path: Path) -> None:
    @technique(risk="destructive")
    def two_temp(ctx: Ctx) -> str:
        """Registers two cleanups with the same label."""
        ctx.defer("tmpfile", lambda: None)
        ctx.defer("tmpfile", lambda: None)
        return "ok"

    log = tmp_path / "events.jsonl"
    eng = make(techniques=[two_temp], policy=Policy.lab(), log_path=log)
    eng.call("two_temp")
    labels = eng.effects.pending()
    assert len(set(labels)) == 2
    eng.mark_cleaned(labels[0])
    eng.ledger.close()
    resumed = Engagement.resume(log, Scope(nets=["10.0.0.0/24"]), techniques=[two_temp])
    assert resumed.effects.pending() == [labels[1]]
    resumed.close()


def test_per_target_budget_counts_hosts() -> None:
    eng = make(techniques=[web], budget=Budget(per_target=1))
    assert eng.call("http_request", {"url": "http://10.0.0.5/"}).ok
    assert eng.call("http_request", {"url": "http://10.0.0.5/a"}).blocked


def test_resume_keeps_history_for_reports_and_checks(tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    ex = FakeExecutor({"curl": "HTTP/1.1 200 OK\r\n\r\n"})
    first = make(ex, techniques=[web], log_path=log)
    token = first.canary()
    f = first.propose_finding("stored-xss", "http://10.0.0.5/c")
    ex.outputs["curl"] = f"HTTP/1.1 200 OK\r\n\r\n{token}"
    first.call("http_request", {"url": "http://10.0.0.5/c"})
    first.ledger.close()
    eng = Engagement.resume(log, Scope(nets=["10.0.0.0/24"]), techniques=[web], executor=FakeExecutor())
    assert eng.report()["stats"]["calls"] == 1
    assert eng.verify(f.id, CanaryCheck(token)).get("status") == "confirmed"
    eng.close()
