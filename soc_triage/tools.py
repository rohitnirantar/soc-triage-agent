"""Tools the triage agent can call. Each tool is a pure, side-effect-free lookup.

Threat intel and asset context are loaded from local JSON so the project runs
offline. Swap `lookup_ip_reputation` for AbuseIPDB/VirusTotal in production.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# keyword rule -> (technique id, technique name, tactic)
MITRE_RULES: list[tuple[str, tuple[str, str, str]]] = [
    (r"brute|password spray|multiple failed", ("T1110", "Brute Force", "Credential Access")),
    (r"mimikatz|lsass|credential dump|sekurlsa", ("T1003", "OS Credential Dumping", "Credential Access")),
    (r"powershell", ("T1059.001", "PowerShell", "Execution")),
    (r"phish", ("T1566", "Phishing", "Initial Access")),
    (r"beacon|\bc2\b|command and control", ("T1071", "Application Layer Protocol", "Command and Control")),
    (r"certutil", ("T1105", "Ingress Tool Transfer", "Command and Control")),
    (r"port scan", ("T1046", "Network Service Discovery", "Discovery")),
    (r"privileged group|added to .* group", ("T1098", "Account Manipulation", "Persistence")),
    (r"vpn login", ("T1078", "Valid Accounts", "Initial Access")),
]

# regex -> (indicator name, weight)
CMD_INDICATORS: list[tuple[str, str, int]] = [
    (r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "encoded PowerShell command", 25),
    (r"-w(indowstyle)?\s+hidden", "hidden window", 10),
    (r"mimikatz|sekurlsa|privilege::debug", "credential dumping tool", 35),
    (r"certutil.*-urlcache", "certutil remote download", 25),
    (r"iex\b|invoke-expression|downloadstring|invoke-webrequest", "download cradle", 20),
]


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
)]


def _is_private(ip: str) -> bool:
    """True only for RFC1918/loopback/link-local. (ipaddress.is_private also covers
    documentation ranges like 203.0.113.0/24, which would hide external indicators.)"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS if addr.version == net.version)


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class ToolBox:
    def __init__(self, data_dir: Path | None = None):
        d = Path(data_dir) if data_dir else DATA_DIR
        self.intel = json.loads((d / "threat_intel.json").read_text())
        self.assets = json.loads((d / "assets.json").read_text())
        self.batch: list[dict] = []
        self.registry: dict[str, Callable[..., dict]] = {
            "lookup_ip_reputation": self.lookup_ip_reputation,
            "lookup_domain_reputation": self.lookup_domain_reputation,
            "lookup_user_context": self.lookup_user_context,
            "lookup_host_context": self.lookup_host_context,
            "map_mitre": self.map_mitre,
            "analyze_command_line": self.analyze_command_line,
            "find_related_alerts": self.find_related_alerts,
        }

    def set_batch(self, alerts: list[dict]) -> None:
        self.batch = alerts

    def call(self, name: str, **kwargs: Any) -> dict:
        if name not in self.registry:
            return {"error": f"unknown tool {name}"}
        try:
            return self.registry[name](**kwargs)
        except TypeError as e:
            return {"error": f"bad arguments for {name}: {e}"}

    # ---- tools -------------------------------------------------------
    def lookup_ip_reputation(self, ip: str) -> dict:
        if not ip:
            return {"ip": ip, "verdict": "unknown", "tags": [], "confidence": 0}
        if _is_private(ip):
            return {"ip": ip, "verdict": "internal", "tags": [], "confidence": 100}
        hit = self.intel["ips"].get(ip)
        if hit:
            return {"ip": ip, **hit}
        return {"ip": ip, "verdict": "unknown", "tags": [], "confidence": 0}

    def lookup_domain_reputation(self, domain: str) -> dict:
        hit = self.intel["domains"].get((domain or "").lower())
        if hit:
            return {"domain": domain, **hit}
        return {"domain": domain, "verdict": "unknown", "tags": [], "confidence": 0}

    def lookup_user_context(self, user: str) -> dict:
        hit = self.assets["users"].get(user)
        return {"user": user, "known": bool(hit), **(hit or {"privileged": False})}

    def lookup_host_context(self, host: str) -> dict:
        hit = self.assets["hosts"].get(host)
        return {"host": host, "known": bool(hit), **(hit or {"criticality": "low"})}

    def map_mitre(self, text: str) -> dict:
        found, seen = [], set()
        low = (text or "").lower()
        for pattern, (tid, name, tactic) in MITRE_RULES:
            if re.search(pattern, low) and tid not in seen:
                seen.add(tid)
                found.append({"id": tid, "name": name, "tactic": tactic})
        return {"techniques": found}

    def analyze_command_line(self, command_line: str) -> dict:
        hits = []
        for pattern, label, weight in CMD_INDICATORS:
            if re.search(pattern, command_line or "", re.IGNORECASE):
                hits.append({"indicator": label, "weight": weight})
        return {"indicators": hits, "score": min(45, sum(h["weight"] for h in hits))}

    def find_related_alerts(self, alert_id: str, window_hours: int = 24) -> dict:
        me = next((a for a in self.batch if a["id"] == alert_id), None)
        if not me:
            return {"related": []}
        start = _parse_ts(me["timestamp"])
        keys = [(k, me.get(k)) for k in ("user", "host", "src_ip", "dest_ip") if me.get(k)]
        related = []
        for a in self.batch:
            if a["id"] == alert_id or a.get("vendor_severity") == "low":
                continue
            if abs(_parse_ts(a["timestamp"]) - start) > timedelta(hours=window_hours):
                continue
            shared = [k for k, v in keys if v in (a.get("user"), a.get("host"), a.get("src_ip"), a.get("dest_ip"))]
            if shared:
                related.append({"id": a["id"], "rule_name": a["rule_name"], "shared": shared})
        return {"related": related}


# JSON-schema tool specs, for LLM tool-use planners.
TOOL_SPECS = [
    {"name": "lookup_ip_reputation", "description": "Threat-intel reputation for an IP address.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "lookup_domain_reputation", "description": "Threat-intel reputation for a domain.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "lookup_user_context", "description": "Role and privilege level of a user account.",
     "input_schema": {"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]}},
    {"name": "lookup_host_context", "description": "Criticality and role of a host.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]}},
    {"name": "map_mitre", "description": "Map alert text to MITRE ATT&CK techniques.",
     "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "analyze_command_line", "description": "Detect suspicious indicators in a command line.",
     "input_schema": {"type": "object", "properties": {"command_line": {"type": "string"}}, "required": ["command_line"]}},
    {"name": "find_related_alerts", "description": "Find other non-low alerts sharing user/host/IP within a time window.",
     "input_schema": {"type": "object", "properties": {"alert_id": {"type": "string"}, "window_hours": {"type": "integer"}}, "required": ["alert_id"]}},
]
