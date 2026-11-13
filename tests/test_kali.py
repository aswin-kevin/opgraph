"""Integration tests against a Linux lab box over SSH.

Run with: OPGRAPH_LAB_SSH=user@host uv run pytest -m kali

The target is a throwaway `python3 -m http.server` bound to Kali's 127.0.0.1 inside a temp dir.
It self-destructs after 5 minutes even if cleanup fails, and everything is removed afterwards.
"""

from __future__ import annotations

import os
import random
import subprocess
from collections.abc import Iterator

import pytest

from opgraph import Engagement, Policy, Scope, SSHExecutor
from opgraph.packs import core, net, web

LAB = os.environ.get("OPGRAPH_LAB_SSH", "")  # e.g. user@kali.local

pytestmark = pytest.mark.kali

SITE = {
    "index.html": "<html><head><title>Lab Portal</title></head><body>"
    "<form action='/login/' method='POST'><input name='username'><input name='password'></form>"
    "<a href='/uploads/'>files</a></body></html>",
    "admin/index.html": "<html><title>Admin</title></html>",
    "backup/index.html": "old backups",
    "uploads/index.html": "uploads",
    "login/index.html": "login",
}


@pytest.fixture(scope="module")
def ssh() -> Iterator[SSHExecutor]:
    if not LAB:
        pytest.skip("set OPGRAPH_LAB_SSH=user@host to run lab tests")
    probe = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", LAB, "true"], capture_output=True
    )
    if probe.returncode != 0:
        pytest.skip(f"cannot reach {LAB} over ssh")
    executor = SSHExecutor(LAB)
    yield executor
    executor.close()


@pytest.fixture(scope="module")
def target(ssh: SSHExecutor) -> Iterator[int]:
    """Serve SITE on Kali's 127.0.0.1:<port>; yield the port; remove everything afterwards."""
    site = ssh.run(["mktemp", "-d", "-t", "opgraph-site.XXXXXXXX"]).stdout.strip()
    assert site.startswith("/tmp/opgraph-site."), site
    for path, content in SITE.items():
        full = f"{site}/{path}"
        assert ssh.run(["mkdir", "-p", full.rsplit("/", 1)[0]]).ok
        assert ssh.run(["tee", full], stdin=content).ok
    port = random.randint(20000, 40000)
    start = (
        f"cd {site} || exit 1; nohup timeout 300 python3 -m http.server {port} --bind 127.0.0.1 "
        "</dev/null >/dev/null 2>&1 & echo $!"
    )
    pid = ssh.run(["bash", "-c", start]).stdout.strip()
    assert pid.isdigit(), pid
    wait = f"for i in $(seq 50); do curl -s -o /dev/null 127.0.0.1:{port} && exit 0; sleep 0.1; done; exit 1"
    ready = ssh.run(["bash", "-c", wait])
    assert ready.ok, "lab server did not start"
    try:
        yield port
    finally:
        ssh.run(["pkill", "-f", f"http.serve[r] {port} --bind 127.0.0.1"])
        ssh.run(["rm", "-rf", "--", site])


def test_ssh_basics(ssh: SSHExecutor) -> None:
    r = ssh.run(["uname", "-s"])
    assert r.ok and r.stdout.strip() == "Linux"
    r = ssh.run(["echo", "a b", "$(id)", "'quoted'"])
    assert r.stdout == "a b $(id) 'quoted'\n"  # argv survives the remote shell untouched
    assert ssh.resolve("localhost") == "127.0.0.1"


def test_remote_timeout_kills_process(ssh: SSHExecutor) -> None:
    r = ssh.run(["sleep", "31.7"], timeout=2)
    assert r.timed_out
    left = ssh.run(["pgrep", "-f", "slee[p] 31.7"])  # [p] avoids matching this command
    assert left.stdout.strip() == "", "remote process survived the timeout"


def test_engagement_against_lab(ssh: SSHExecutor, target: int) -> None:
    port = target
    base = f"http://127.0.0.1:{port}"
    scope = Scope(nets=["127.0.0.1/32"], ports=[port])
    eng = Engagement(scope, techniques=[web, net, core], executor=ssh, policy=Policy.safe())

    r = eng.call("port_scan", {"host": "127.0.0.1", "ports": str(port)})
    assert r.ok, r.to_tool_text()
    services = eng.facts.query("service", port=port)
    assert services and str(services[0].get("name")).startswith("http")

    r = eng.call("http_request", {"url": base + "/"})
    assert r.ok and "Lab Portal" in r.text, r.to_tool_text()
    assert {p.get("name") for p in eng.facts.query("param", location="body")} == {"username", "password"}

    r = eng.call("dir_discovery", {"base_url": base, "wordlist": "small"})
    assert r.ok, r.to_tool_text()
    found = {f.get("url") for f in eng.facts.query("endpoint")}
    assert {f"{base}/admin", f"{base}/backup", f"{base}/uploads"} <= found

    # out of scope: another port, and the metadata address, never reach a tool
    assert eng.call("http_request", {"url": "http://127.0.0.1:22/"}).blocked
    assert eng.call("http_request", {"url": "http://2852039166/"}).blocked
    assert eng.call("shell", {"command": "id"}).blocked  # raw shell needs approval

    workdir = eng.workdir()
    print("\n" + eng.world())
    lines = eng.close()
    assert any(line.startswith(f"cleaned  workdir {workdir}") for line in lines)
    assert not ssh.run(["test", "-e", workdir]).ok, "workdir left behind on Kali"
