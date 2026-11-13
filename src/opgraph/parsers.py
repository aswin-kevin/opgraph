"""Parsers turn raw tool output into facts. Each is a plain function: text in, facts out.

They never raise on bad input; malformed output yields fewer facts, not an exception.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import replace
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from .facts import Fact, endpoint, host, param, service, tech
from .observe import sanitize
from .targets import TargetError, base_url, normalize_url

# ---- nmap --------------------------------------------------------------------------------------------


def nmap_xml(text: str) -> list[Fact]:
    """`nmap -oX -` output -> host and open-service facts (with http-title / ftp-anon script results)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    facts: list[Fact] = []
    for h in root.iter("host"):
        status = h.find("status")
        addr = h.find("address")
        if status is None or status.get("state") != "up" or addr is None:
            continue
        ip = addr.get("addr", "")
        names = [n.get("name", "") for n in h.iter("hostname")]
        facts.append(host(ip, **({"hostname": names[0]} if names and names[0] else {})))
        for port in h.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            facts.append(_nmap_service(ip, port))
    return facts


def _nmap_service(ip: str, port: ET.Element) -> Fact:
    attrs: dict[str, object] = {}
    svc = port.find("service")
    if svc is not None:
        name = svc.get("name", "")
        if svc.get("tunnel") == "ssl" and name == "http":
            name = "https"
        attrs.update(name=name, product=svc.get("product", ""), version=svc.get("version", ""))
    for script in port.iter("script"):
        output = script.get("output", "")
        if script.get("id") == "http-title":
            attrs["title"] = output.strip()[:120]
        elif script.get("id") == "ftp-anon" and "allowed" in output.lower():
            attrs["anon"] = True
    return service(ip, int(port.get("portid", "0")), port.get("protocol", "tcp"), **attrs)


# ---- content discovery ------------------------------------------------------------------------------

_GOBUSTER = re.compile(r"^(/\S*)\s+\(Status:\s*(\d{3})\)(?:\s*\[Size:\s*(\d+)\])?(?:.*-->\s*([^\s\]]+))?")


def gobuster(text: str, base: str) -> list[Fact]:
    """`gobuster dir` stdout (ANSI and \\r safe) -> endpoint facts."""
    facts = []
    for line in sanitize(text).splitlines():
        m = _GOBUSTER.search(line.strip())
        if not m:
            continue
        attrs: dict[str, object] = {"status": int(m.group(2))}
        if m.group(3):
            attrs["length"] = int(m.group(3))
        if m.group(4):
            attrs["location"] = m.group(4)
        facts.extend(_safe_endpoint(base.rstrip("/") + m.group(1), **attrs))
    return facts


def ffuf_json(text: str) -> list[Fact]:
    """`ffuf -json` (one JSON object per line) or `-of json` (one document) -> endpoint facts."""
    records: list[dict] = []
    text = text.strip()
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            records = doc.get("results", [doc] if "url" in doc else [])
    except json.JSONDecodeError:
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                records.append(row)
    facts = []
    for r in records:
        url = r.get("url")
        if not isinstance(url, str):
            continue
        attrs = {"status": r.get("status"), "length": r.get("length"), "location": r.get("redirectlocation")}
        facts.extend(_safe_endpoint(url, **{k: v for k, v in attrs.items() if v not in (None, "")}))
    return facts


# ---- HTTP responses ---------------------------------------------------------------------------------

_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


def split_http(raw: str) -> tuple[int | None, list[tuple[str, str]], str]:
    """Split `curl -i` output into (status, headers, body). Skips interim 1xx responses."""
    text = raw.replace("\r\n", "\n")
    status: int | None = None
    headers: list[tuple[str, str]] = []
    while True:
        head, sep, rest = text.partition("\n\n")
        lines = head.split("\n")
        m = _STATUS.match(lines[0]) if lines else None
        if not m:
            return status, headers, text if status is not None else raw
        status = int(m.group(1))
        headers = [
            (k.strip().lower(), v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:]) if k.strip()
        ]
        text = rest if sep else ""
        if not (100 <= status < 200) or not _STATUS.match(text):
            return status, headers, text


def http_response(raw: str, url: str) -> list[Fact]:
    """`curl -i` output for `url` -> endpoint (status, title, type), tech, params from the query,
    forms and cookies, plus linked same-origin endpoints (low confidence)."""
    status, headers, body = split_http(raw)
    if status is None:
        return []
    header = dict(headers)
    attrs: dict[str, object] = {"status": status}
    if header.get("content-type"):
        attrs["content_type"] = header["content-type"].split(";")[0]
    if status in (401, 407) or "www-authenticate" in header:
        attrs["auth"] = header.get("www-authenticate", "required")[:60]
    if "location" in header:
        attrs["location"] = header["location"]
    page = _PageParser()
    if "html" in str(attrs.get("content_type", "html")):
        page.feed_safely(body)
        if page.title:
            attrs["title"] = page.title[:120]

    facts = list(_safe_endpoint(url, **attrs))
    if not facts:
        return []
    query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    facts += [param(url, "query", n) for n in _tokens(name for name, _ in query)]
    for name in _TECH_HEADERS:
        if header.get(name):
            product = _TECH_NAME.match(header[name])
            facts.append(tech(url, product.group(0) if product else name, header=name, raw=header[name]))
    cookies = [
        value.split("=", 1)[0].strip() for key, value in headers if key == "set-cookie" and "=" in value
    ]
    facts += [param(url, "cookie", n) for n in _tokens(cookies)]

    origin = base_url(url)
    for form in page.forms:
        action = urljoin(url, form["action"] or url)
        if base_url(action) != origin:
            continue
        location = "query" if form["method"] == "get" else "body"
        facts += _safe_endpoint(action, methods=form["method"].upper())
        facts += [param(action, location, n) for n in _tokens(form["inputs"])]
    links = {urljoin(url, href) for href in page.links}
    if "location" in header:
        links.add(urljoin(url, header["location"]))
    for link in sorted(links)[:100]:
        if link.startswith(("http://", "https://")) and base_url(link) == origin:
            facts += [replace(f, confidence="medium") for f in _safe_endpoint(link)]
    return facts


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._in_title = False

    def feed_safely(self, body: str) -> None:
        try:
            self.feed(body[:500_000])
            self.close()
        except Exception:  # broken markup: keep what was parsed
            pass

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in ("a", "link", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self.forms.append(
                {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            )
        elif tag in ("input", "select", "textarea", "button") and a.get("name") and self.forms:
            self.forms[-1]["inputs"].append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


# ---- anything else ----------------------------------------------------------------------------------

_URL = re.compile(r"https?://[^\s'\"<>()\[\]{}]+", re.IGNORECASE)


def generic(text: str, limit: int = 50) -> list[Fact]:
    """URLs found in arbitrary output (e.g. raw shell) -> low-confidence endpoint facts."""
    facts: list[Fact] = []
    for url in dict.fromkeys(_URL.findall(sanitize(text))):
        facts += [replace(f, confidence="low") for f in _safe_endpoint(url.rstrip(".,;:"))]
        if len(facts) >= limit:
            break
    return facts


# Parameter names are target-controlled; keep only plain identifiers (no spaces, quotes or newlines).
_TOKEN = re.compile(r"[A-Za-z0-9_.\-\[\]$]{1,64}")
_TECH_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,40}")


def _tokens(names: Iterable[str]) -> list[str]:
    return [n for n in dict.fromkeys(names) if _TOKEN.fullmatch(n)]


def _safe_endpoint(url: str, **attrs: object) -> list[Fact]:
    try:
        normalize_url(url)
        return [endpoint(url, **attrs)]
    except (TargetError, ValueError):
        return []
