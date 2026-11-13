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


def test_script_urls_and_js_endpoints() -> None:
    html = (
        "<script src='/static/app.js'></script><script src='https://cdn.other.example/x.js'></script>"
        "<script>fetch('/api/v1/users?limit=5'); const u = \"/admin/settings\";</script>"
    )
    assert parsers.script_urls(html, "http://h:8000/") == ["http://h:8000/static/app.js"]
    js = "axios.get(`/api/orders/${id}`); x='/logo.png'; y='//cdn.example/a'; z='http://h:8000/graphql'"
    urls = {f.get("url") for f in parsers.js_endpoints(html + js, "http://h:8000/")}
    assert urls == {
        "http://h:8000/static/app.js",
        "http://h:8000/api/v1/users",
        "http://h:8000/admin/settings",
        "http://h:8000/api/orders/",
        "http://h:8000/graphql",
    }
    assert all(f.confidence == "low" for f in parsers.js_endpoints(js, "http://h:8000/"))


SQLMAP = """
[INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3591=3591

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL-- -
---
[INFO] the back-end DBMS is SQLite
"""


def test_sqlmap_output() -> None:
    facts = parsers.sqlmap_output(SQLMAP, "http://h/item?id=1")
    found = next(f for f in facts if f.kind == "finding")
    assert found.id == "finding:sqli|http://h/item?id"
    assert found.get("status") == "confirmed" and found.get("dbms") == "SQLite"
    assert "UNION ALL SELECT" in found.get("evidence") and found.get("place") == "GET"
    assert any(f.kind == "param" and f.get("injectable") for f in facts)
    assert parsers.sqlmap_output("all tested parameters do not appear to be injectable", "http://h/") == []


def test_nuclei_jsonl() -> None:
    git = {"name": "Git Config", "severity": "medium", "tags": ["exposure"]}
    wappalyzer = {"name": "Wappalyzer", "severity": "info", "tags": ["tech"]}
    rows = [
        {"template-id": "git-config", "info": git, "matched-at": "http://h/.git/config",
         "extracted-results": ["repositoryformatversion"]},
        {"template-id": "tech-detect", "info": wappalyzer, "matcher-name": "nginx", "matched-at": "http://h/"},
    ]  # fmt: skip
    facts = parsers.nuclei_jsonl("\n".join(json.dumps(r) for r in rows) + "\ngarbage\n")
    found = next(f for f in facts if f.kind == "finding")
    assert found.id == "finding:git-config|http://h/.git/config"
    assert found.get("status") == "proposed" and found.get("severity") == "medium"
    assert any(f.kind == "tech" and f.get("name") == "nginx" for f in facts)


def test_httpx_jsonl() -> None:
    row = {"url": "https://h:8443", "status_code": 200, "title": "Portal", "webserver": "nginx",
           "tech": ["Nginx:1.25", "PHP"]}  # fmt: skip
    facts = parsers.httpx_jsonl(json.dumps(row))
    ep = facts[0]
    assert ep.id == "endpoint:https://h:8443/" and ep.get("title") == "Portal"
    assert {f.get("name") for f in facts if f.kind == "tech"} == {"nginx", "php"}
