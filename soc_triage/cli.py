"""Command line interface: `python -m soc_triage triage|eval`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import TriageAgent
from .evaluate import evaluate
from .planner import ClaudePlanner, RulePlanner
from .report import write_reports

ROOT = Path(__file__).resolve().parent.parent


def parse_alerts(data: object) -> list[dict]:
    """Validate already-parsed JSON (shared by the CLI and the Streamlit UI)."""
    if not isinstance(data, list):
        raise ValueError("input must be a JSON array of alerts")
    for a in data:
        if not isinstance(a, dict):
            raise ValueError(f"each alert must be a JSON object, got: {a!r}")
        for key in ("id", "timestamp", "rule_name"):
            if key not in a:
                raise ValueError(f"alert missing required field '{key}': {a}")
    return data


def load_alerts(path: str | Path) -> list[dict]:
    return parse_alerts(json.loads(Path(path).read_text()))


def build_agent(planner: str) -> TriageAgent:
    return TriageAgent(planner=ClaudePlanner() if planner == "claude" else RulePlanner())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soc_triage", description="Agentic SOC alert triage")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("triage", "eval"):
        s = sub.add_parser(name)
        s.add_argument("--input", default=str(ROOT / "data" / "sample_alerts.json"))
        s.add_argument("--planner", choices=["rule", "claude"], default="rule")
        if name == "triage":
            s.add_argument("--out", default=str(ROOT / "reports"))
        else:
            s.add_argument("--labels", default=str(ROOT / "data" / "labels.json"))
    args = p.parse_args(argv)

    try:
        alerts = load_alerts(args.input)
        results = build_agent(args.planner).triage_batch(alerts)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "triage":
        j, m = write_reports(results, args.out)
        for r in results:
            print(f"{r.priority}  {r.score:>3}  {r.alert_id}  {r.rule_name}")
        print(f"\nWrote {j} and {m}")
        return 0

    labels = json.loads(Path(args.labels).read_text())
    ev = evaluate(results, labels)
    for row in ev["rows"]:
        print(f"{'OK ' if row['ok'] else 'BAD'} {row['alert_id']} expected={row['expected']} got={row['got']}")
    print(f"\nexact accuracy: {ev['exact_accuracy']:.0%} | within one level: {ev['within_one_level']:.0%} | missed critical: {ev['missed_critical']}")
    return 0 if ev["missed_critical"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
