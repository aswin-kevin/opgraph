import json
from pathlib import Path

from opgraph import parsers
from opgraph.facts import FactStore

FIXTURES = Path(__file__).parent / "fixtures"


def test_nmap_xml_fixture() -> None:
    facts = parsers.nmap_xml((FIXTURES / "nmapA.xml").read_text())
    services = {f.get("port"): f for f in facts if f.kind == "service"}
    assert [f.kind for f in facts].count("host") == 1
    assert len(services) == 5
    assert any(s.get("anon") is True and s.get("name") == "ftp" for s in services.values())
    assert any(s.get("title") for s in services.values())
    assert all(s.parent == f"host:{s.get('host')}" for s in services.values())


def test_nmap_xml_garbage() -> None:
    assert parsers.nmap_xml("not xml") == []
    assert parsers.nmap_xml("<nmaprun><host><status state='down'/></host></nmaprun>") == []


def test_gobuster_fixture() -> None:
    facts = parsers.gobuster((FIXTURES / "gobuster_stdout.txt").read_text(), "http://127.0.0.1:8080/")
    urls = {f.get("url") for f in facts}
    assert len(facts) == 15
    assert "http://127.0.0.1:8080/admin" in urls
    assert facts[0].get("location") == "/admin/"
    assert all(isinstance(f.get("status"), int) for f in facts)


def test_ffuf_json_lines_and_document() -> None:
    rows = [
        {"url": "http://h:8000/admin", "status": 301, "length": 0, "redirectlocation": "/admin/"},
        {"url": "http://h:8000/robots.txt", "status": 200, "length": 42, "redirectlocation": ""},
    ]
    lines = "\n".join(json.dumps(r) for r in rows) + "\nnot json\n"
    facts = parsers.ffuf_json(lines)
    assert [f.get("url") for f in facts] == ["http://h:8000/admin", "http://h:8000/robots.txt"]
    assert facts[0].get("location") == "/admin/" and facts[1].get("location") is None
    assert len(parsers.ffuf_json(json.dumps({"results": rows}))) == 2
    assert parsers.ffuf_json("") == []


RESPONSE = (
    "HTTP/1.1 100 Continue\r\n\r\n"
    "HTTP/1.1 200 OK\r\n"
    "Server: Werkzeug/2.0.1 Python/3.9\r\n"
    "X-Powered-By: PHP/5.6\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Set-Cookie: session=abc; HttpOnly\r\n"
    "\r\n"
    "<html><head><title>Acme Login</title></head><body>"
    "<form action='/login' method='POST'><input name='username'><input name='password' type='password'>"
    "<button name='submit'>go</button></form>"
    "<a href='/about?x=1'>about</a><a href='http://evil.example/'>x</a>"
    "<script src='/static/app.js'></script>"
    "</body></html>"
)


def test_http_response() -> None:
    url = "http://127.0.0.1:8000/?next=home"
    store = FactStore()
    store.add(parsers.http_response(RESPONSE, url))
    root = store.get("endpoint:http://127.0.0.1:8000/")
    assert root is not None
    assert root.get("status") == 200 and root.get("title") == "Acme Login"
    assert root.get("content_type") == "text/html"
    params = {(p.get("location"), p.get("name"), p.get("url")) for p in store.query("param")}
    assert ("body", "username", "http://127.0.0.1:8000/login") in params
    assert ("body", "password", "http://127.0.0.1:8000/login") in params
    assert ("cookie", "session", "http://127.0.0.1:8000/") in params
    assert ("query", "next", "http://127.0.0.1:8000/") in params
    assert store.get("endpoint:http://127.0.0.1:8000/login").get("methods") == "POST"  # type: ignore[union-attr]
    assert store.get("endpoint:http://127.0.0.1:8000/static/app.js") is not None
    assert not any("evil.example" in f.id for f in store)  # other origins are not followed
    assert {t.get("name") for t in store.query("tech")} == {"werkzeug", "php"}


def test_http_redirect_and_auth() -> None:
    raw = "HTTP/1.1 302 Found\nLocation: /dashboard\nWWW-Authenticate: Basic realm=x\n\n"
    facts = parsers.http_response(raw, "http://h/")
    ep = facts[0]
    assert ep.get("status") == 302 and ep.get("location") == "/dashboard" and ep.get("auth")
    assert any(f.id == "endpoint:http://h/dashboard" for f in facts)


def test_http_curl_fixture_and_garbage() -> None:
    facts = parsers.http_response((FIXTURES / "curl.txt").read_text(), "http://127.0.0.1:8080/")
    assert facts[0].get("title") == "Acme Admin Portal"
    assert parsers.http_response("curl: (7) Failed to connect", "http://h/") == []


def test_generic() -> None:
    text = "see http://10.0.0.1:8080/admin, and https://h/x?y=1. also \x1b[31mhttp://h/z\x1b[0m"
    facts = parsers.generic(text)
    assert [f.get("url") for f in facts] == ["http://10.0.0.1:8080/admin", "https://h/x", "http://h/z"]
    assert all(f.confidence == "low" for f in facts)
