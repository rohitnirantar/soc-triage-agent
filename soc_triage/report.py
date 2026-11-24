"""Render triage results as JSON and Markdown."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .agent import TriageResult


def to_json(results: list[TriageResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


def to_markdown(results: list[TriageResult]) -> str:
    counts = Counter(r.priority for r in results)
    lines = [
        "# SOC Triage Report",
        "",
        f"Alerts triaged: **{len(results)}** | "
        + " | ".join(f"{p}: {counts.get(p, 0)}" for p in ("P1", "P2", "P3", "P4")),
        "",
        "| Priority | Score | Alert | Rule | Verdict |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.priority} | {r.score} | {r.alert_id} | {r.rule_name} | {r.verdict} |")
    for r in results:
        lines += ["", f"## {r.alert_id}: {r.rule_name} ({r.priority})", "", r.summary, ""]
        lines.append("**Score breakdown**")
        lines += [f"- {p['factor']}: {p['points']:+d}" for p in r.breakdown] or ["- (none)"]
        if r.techniques:
            lines += ["", "**MITRE ATT&CK**"]
            lines += [f"- {t['id']} {t['name']} ({t['tactic']})" for t in r.techniques]
        lines += ["", "**Recommended actions**"]
        lines += [f"- {a}" for a in r.actions]
        lines += ["", f"_Tools called: {', '.join(t['tool'] for t in r.trace)}_"]
    return "\n".join(lines) + "\n"


def write_reports(results: list[TriageResult], out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    j, m = out / "triage_results.json", out / "triage_report.md"
    j.write_text(to_json(results))
    m.write_text(to_markdown(results))
    return j, m
