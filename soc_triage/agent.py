"""Triage agent: plan -> act (tools) -> observe -> score -> decide -> recommend."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .planner import RulePlanner, required_steps
from .tools import ToolBox

SEV_POINTS = {"low": 5, "medium": 15, "high": 25, "critical": 30}
CRIT_POINTS = {"low": 0, "medium": 5, "high": 10, "critical": 15}
HIGH_IMPACT_TACTICS = {"Credential Access", "Command and Control", "Impact", "Exfiltration"}
BENIGN_HINTS = r"change ticket|approved|scheduled|mistyped|routine"
RELATED_POINTS, RELATED_CAP = 8, 20

VERDICTS = {
    "P1": "true_positive",
    "P2": "likely_true_positive",
    "P3": "suspicious_needs_review",
    "P4": "benign_or_low_risk",
}


def priority_for(score: int) -> str:
    if score >= 70:
        return "P1"
    if score >= 45:
        return "P2"
    if score >= 25:
        return "P3"
    return "P4"


@dataclass
class TriageResult:
    alert_id: str
    rule_name: str
    priority: str
    verdict: str
    score: int
    breakdown: list[dict] = field(default_factory=list)
    techniques: list[dict] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    summary: str = ""
    trace: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class TriageAgent:
    def __init__(self, toolbox: ToolBox | None = None, planner=None):
        self.tools = toolbox or ToolBox()
        self.planner = planner or RulePlanner()

    def triage_batch(self, alerts: list[dict]) -> list[TriageResult]:
        self.tools.set_batch(alerts)
        results = [self.triage(a) for a in alerts]
        return sorted(results, key=lambda r: (r.priority, -r.score))

    def triage(self, alert: dict) -> TriageResult:
        trace: list[dict] = []
        done: set[tuple] = set()

        def record(tool: str, args: dict, result: dict) -> None:
            trace.append({"tool": tool, "args": args, "result": result})
            done.add((tool, tuple(sorted((k, str(v)) for k, v in args.items()))))

        narrative = self.planner.execute(alert, self.tools, record)

        # Guardrail: required tools always run, whatever the planner chose.
        for tool, args in required_steps(alert):
            key = (tool, tuple(sorted((k, str(v)) for k, v in args.items())))
            if key not in done:
                record(tool, args, self.tools.call(tool, **args))

        score, breakdown, techniques = self._score(alert, trace)
        priority = priority_for(score)
        result = TriageResult(
            alert_id=alert["id"],
            rule_name=alert["rule_name"],
            priority=priority,
            verdict=VERDICTS[priority],
            score=score,
            breakdown=breakdown,
            techniques=techniques,
            trace=trace,
        )
        result.actions = self._actions(priority, techniques, trace, alert)
        result.summary = narrative or self._summary(alert, result)
        return result

    # ---- scoring -----------------------------------------------------
    def _score(self, alert: dict, trace: list[dict]):
        parts: list[dict] = []

        def add(factor: str, points: int) -> None:
            if points:
                parts.append({"factor": factor, "points": points})

        def results(tool: str) -> list[dict]:
            return [t["result"] for t in trace if t["tool"] == tool and "error" not in t["result"]]

        add(f"vendor severity: {alert.get('vendor_severity', 'low')}", SEV_POINTS.get(alert.get("vendor_severity", "low"), 5))

        # reputation: worst of all IPs / domain, counted once
        reps = results("lookup_ip_reputation") + results("lookup_domain_reputation")
        bad = [r for r in reps if r["verdict"] == "malicious"]
        sus = [r for r in reps if r["verdict"] == "suspicious"]
        clean = [r for r in reps if r["verdict"] == "clean"]
        hard_evidence = False
        if bad:
            add("malicious indicator in threat intel", 30)
            hard_evidence = True
            if any("c2" in r.get("tags", []) for r in bad):
                add("known C2 infrastructure", 15)
        elif sus:
            add("suspicious indicator in threat intel", 12)
            hard_evidence = True
        elif clean:
            add("indicator is known-clean", -10)

        for h in results("lookup_host_context"):
            add(f"host criticality: {h['criticality']}", CRIT_POINTS.get(h["criticality"], 0))
        for u in results("lookup_user_context"):
            if u.get("privileged"):
                add("privileged account involved", 10)

        for c in results("analyze_command_line"):
            if c["score"]:
                add("command line: " + ", ".join(i["indicator"] for i in c["indicators"]), c["score"])
                hard_evidence = True

        techniques = []
        for m in results("map_mitre"):
            techniques = m["techniques"]
        if any(t["tactic"] in HIGH_IMPACT_TACTICS for t in techniques):
            add("high-impact ATT&CK tactic", 5)

        for r in results("find_related_alerts"):
            n = len(r["related"])
            add(f"{n} correlated alert(s) on same user/host/IP", min(RELATED_CAP, n * RELATED_POINTS))

        # Benign-context discount only applies when there is no hard evidence, so an
        # attacker cannot talk the agent down by writing "approved" into a log field.
        text = f"{alert.get('rule_name', '')} {alert.get('description', '')}"
        if not hard_evidence and re.search(BENIGN_HINTS, text, re.IGNORECASE):
            add("benign context (ticketed/scheduled/routine)", -20)

        score = max(0, min(100, sum(p["points"] for p in parts)))
        return score, parts, techniques

    # ---- output ------------------------------------------------------
    def _actions(self, priority: str, techniques: list[dict], trace: list[dict], alert: dict) -> list[str]:
        ids = {t["id"] for t in techniques}
        acts: list[str] = []
        if priority == "P1":
            acts.append("Open a P1 incident and page the on-call responder.")
        elif priority == "P2":
            acts.append("Escalate to a tier-2 analyst within 1 hour.")
        elif priority == "P3":
            acts.append("Queue for analyst review within 24 hours.")
        else:
            acts.append("Close as benign/low risk; no action required.")
            return acts
        if ids & {"T1110", "T1078"}:
            acts.append(f"Reset credentials and revoke active sessions for {alert.get('user') or 'the account'}.")
        if "T1003" in ids:
            acts.append("Isolate the host and rotate all credentials cached on it.")
        if ids & {"T1071", "T1105"} or any(
            r["result"].get("verdict") == "malicious" for r in trace if r["tool"] == "lookup_ip_reputation"
        ):
            ips = [r["result"]["ip"] for r in trace if r["tool"] == "lookup_ip_reputation" and r["result"].get("verdict") == "malicious"]
            if ips:
                acts.append("Block at firewall/proxy: " + ", ".join(sorted(set(ips))) + ".")
            if priority in ("P1", "P2"):
                acts.append(f"Isolate host {alert.get('host')} via EDR pending investigation.")
        if "T1059.001" in ids:
            acts.append("Collect the PowerShell script block logs and decode the payload.")
        if "T1566" in ids:
            acts.append("Search mail logs for other recipients and purge the message.")
        if "T1046" in ids:
            acts.append("Confirm the target is patched and rate-limit the source IP.")
        if "T1098" in ids:
            acts.append("Verify the change ticket and review group membership changes.")
        return acts

    def _summary(self, alert: dict, r: TriageResult) -> str:
        top = sorted((p for p in r.breakdown if p["points"] > 0), key=lambda p: -p["points"])[:3]
        why = "; ".join(p["factor"] for p in top) or "no significant risk factors"
        tech = ", ".join(f"{t['id']} {t['name']}" for t in r.techniques) or "no ATT&CK match"
        return (
            f"{alert['rule_name']} on {alert.get('host') or 'n/a'} (user: {alert.get('user') or 'n/a'}) "
            f"scored {r.score}/100 -> {r.priority} ({r.verdict}). Key factors: {why}. ATT&CK: {tech}."
        )
