"""Human-readable engagement report (Markdown).

    from opgraph.report import to_markdown
    Path("report.md").write_text(to_markdown(eng))

Target-controlled text is rendered inside code spans with backticks and pipes removed, so it
cannot inject links, HTML or table structure into whatever renders the report.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from .observe import clean_value
from .render import format_fact

if TYPE_CHECKING:
    from .engagement import Engagement

_STATUS_ORDER = {"confirmed": 0, "proposed": 1, "rejected": 2}


def to_markdown(eng: Engagement, max_items: int = 200) -> str:
    report = eng.report()
    stats = report["stats"]
    lines = [
        f"# Engagement report: {_code(report['name'])}",
        "",
        f"Generated {time.strftime('%Y-%m-%d %H:%M:%S %Z')}, duration {report['duration_s']} s.",
        "",
        "## Summary",
        "",
        "| calls | blocked | errors | facts | findings (confirmed) | cleanup residue |",
        "|---|---|---|---|---|---|",
        f"| {stats['calls']} | {stats['blocked']} | {stats['errors']} | {stats['facts']} "
        f"| {len(report['findings'])} ({_count_confirmed(report['findings'])}) | {len(report['residue'])} |",
        "",
        "## Scope",
        "",
        *[f"- {name}: {_code(value)}" for name, value in report["scope"].items() if value],
        "",
        *_findings(eng, report["findings"]),
        *_surface(eng, max_items),
        *_coverage(report["coverage"], max_items),
        *_cleanup(report),
    ]
    return "\n".join(lines).rstrip() + "\n"


def _findings(eng: Engagement, findings: list[dict]) -> list[str]:
    out = ["## Findings", ""]
    if not findings:
        return [*out, "No findings recorded.", ""]
    ordered = sorted(findings, key=lambda f: (_STATUS_ORDER.get(f["attrs"].get("status"), 9), f["key"]))
    for f in ordered:
        attrs = f["attrs"]
        status = attrs.get("status") if attrs.get("status") in _STATUS_ORDER else "unknown"
        key = f["key"]
        title = f"{_code(key[0])} at {_code(key[1])}" if len(key) == 2 else _code(" ".join(map(str, key)))
        out.append(f"### {status.upper()}: {title}")
        out.append("")
        for label, name in (("Evidence", "evidence"), ("Verified by", "verified_by"),
                            ("Rationale", "rationale"), ("Rejected because", "reason")):  # fmt: skip
            if attrs.get(name):
                out.append(f"- {label}: {_code(attrs[name], 300)}")
        chain = [eng.facts.get(fact_id) for fact_id in f["chain"]]
        if len(chain) > 1:
            out.append("- Evidence chain:")
            out += [f"  {i + 1}. {_code(format_fact(c), 200)}" for i, c in enumerate(chain) if c is not None]
        out.append("")
    return out


def _surface(eng: Engagement, max_items: int) -> list[str]:
    out = ["## Attack surface", ""]
    for kind, title in (("service", "Services"), ("endpoint", "Endpoints"), ("credential", "Credentials")):
        facts = sorted(eng.facts.query(kind), key=lambda f: f.id)
        if not facts:
            continue
        out += [f"**{title}** ({len(facts)})", ""]
        out += [f"- {_code(format_fact(f), 200)}" for f in facts[:max_items]]
        if len(facts) > max_items:
            out.append(f"- ... {len(facts) - max_items} more")
        out.append("")
    if len(out) == 2:
        out += ["Nothing discovered.", ""]
    return out


def _coverage(coverage: list[dict], max_items: int) -> list[str]:
    out = ["## Coverage", ""]
    if not coverage:
        return [*out, "No techniques were run.", ""]
    out += ["| technique | target | runs |", "|---|---|---|"]
    out += [
        f"| {_code(c['technique'])} | {_code(c['target'] or '-')} | {c['count']} |"
        for c in coverage[:max_items]
    ]
    return [*out, ""]


def _cleanup(report: dict) -> list[str]:
    out = ["## Cleanup", ""]
    if report["residue"]:
        out += ["**Manual cleanup required:**", ""]
        out += [f"- {_code(line, 300)}" for line in report["residue"]]
    if report["pending_cleanup"]:
        out += ["Not yet cleaned (engagement still open):", ""]
        out += [f"- {_code(label, 300)}" for label in report["pending_cleanup"]]
    if not report["residue"] and not report["pending_cleanup"]:
        out.append("Everything the engagement created has been cleaned up.")
    return [*out, ""]


def _count_confirmed(findings: list[dict]) -> int:
    return sum(1 for f in findings if f["attrs"].get("status") == "confirmed")


def _code(value: object, limit: int = 120) -> str:
    text = clean_value(value, limit).replace("`", "'").replace("|", "/")
    return f"`{text}`" if text else "` `"
