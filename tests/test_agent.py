import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_triage.agent import TriageAgent, priority_for
from soc_triage.cli import load_alerts, main
from soc_triage.evaluate import evaluate
from soc_triage.planner import ClaudePlanner
from soc_triage.report import to_markdown
from soc_triage.tools import ToolBox

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample_alerts.json"
EDGE = Path(__file__).resolve().parent / "sample_test_alerts.json"


@pytest.fixture
def agent():
    return TriageAgent()


# ---- tools ---------------------------------------------------------------
def test_internal_vs_documentation_ip():
    t = ToolBox()
    assert t.lookup_ip_reputation("10.1.1.1")["verdict"] == "internal"
    # documentation range must NOT be treated as internal (regression)
    assert t.lookup_ip_reputation("203.0.113.50")["verdict"] == "malicious"


def test_unknown_ip_and_empty():
    t = ToolBox()
    assert t.lookup_ip_reputation("8.8.4.4")["verdict"] == "unknown"
    assert t.lookup_ip_reputation(None)["verdict"] == "unknown"


def test_mitre_mapping():
    ids = {x["id"] for x in ToolBox().map_mitre("mimikatz sekurlsa on lsass")["techniques"]}
    assert "T1003" in ids


def test_command_line_indicators():
    r = ToolBox().analyze_command_line("powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
    labels = {i["indicator"] for i in r["indicators"]}
    assert {"encoded PowerShell command", "hidden window"} <= labels
    assert ToolBox().analyze_command_line("powershell -File backup.ps1")["score"] == 0


def test_unknown_tool_and_bad_args():
    t = ToolBox()
    assert "error" in t.call("nope")
    assert "error" in t.call("lookup_ip_reputation", wrong=1)


# ---- scoring -------------------------------------------------------------
def test_priority_thresholds():
    assert [priority_for(s) for s in (0, 24, 25, 44, 45, 69, 70, 100)] == ["P4", "P4", "P3", "P3", "P2", "P2", "P1", "P1"]


def test_sample_batch_sorted_and_complete(agent):
    alerts = load_alerts(SAMPLE)
    results = agent.triage_batch(alerts)
    assert len(results) == len(alerts)
    assert [r.priority for r in results] == sorted(r.priority for r in results)
    assert all(0 <= r.score <= 100 for r in results)
    assert all(r.actions and r.summary and r.trace for r in results)


def test_accuracy_on_labelled_sample(agent):
    results = agent.triage_batch(load_alerts(SAMPLE))
    ev = evaluate(results, json.loads((ROOT / "data" / "labels.json").read_text()))
    assert ev["total"] == 12
    assert ev["missed_critical"] == 0
    assert ev["exact_accuracy"] >= 0.9


def test_correlation_raises_score(agent):
    results = {r.alert_id: r for r in agent.triage_batch(load_alerts(SAMPLE))}
    assert any("correlated" in p["factor"] for p in results["ALT-1001"].breakdown)


# ---- edge cases / security -----------------------------------------------
def test_prompt_injection_in_description_cannot_lower_priority(agent):
    r = {x.alert_id: x for x in agent.triage_batch(load_alerts(EDGE))}["TST-1"]
    assert r.priority == "P1"
    assert not any("benign" in p["factor"] for p in r.breakdown)


def test_unknown_user_host_handled(agent):
    r = {x.alert_id: x for x in agent.triage_batch(load_alerts(EDGE))}["TST-2"]
    assert r.priority == "P4"


def test_download_cradle_detected(agent):
    r = {x.alert_id: x for x in agent.triage_batch(load_alerts(EDGE))}["TST-3"]
    assert r.priority in ("P1", "P2")
    assert any("download cradle" in p["factor"] for p in r.breakdown)


def test_minimal_alert_no_crash(agent):
    r = {x.alert_id: x for x in agent.triage_batch(load_alerts(EDGE))}["TST-4"]
    assert r.priority == "P4"


# ---- reporting / CLI -----------------------------------------------------
def test_markdown_report_contents(agent):
    md = to_markdown(agent.triage_batch(load_alerts(SAMPLE)))
    assert "# SOC Triage Report" in md and "ALT-1005" in md and "T1003" in md


def test_cli_triage_writes_files(tmp_path, capsys):
    assert main(["triage", "--input", str(EDGE), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "triage_results.json").exists()
    assert (tmp_path / "triage_report.md").exists()
    assert len(json.loads((tmp_path / "triage_results.json").read_text())) == 4


def test_cli_eval_exit_code_zero():
    assert main(["eval"]) == 0


def test_cli_rejects_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('[{"id": "x"}]')
    assert main(["triage", "--input", str(bad)]) == 2
    notjson = tmp_path / "n.json"
    notjson.write_text("not json")
    assert main(["triage", "--input", str(notjson)]) == 2
    assert main(["triage", "--input", str(tmp_path / "missing.json")]) == 2


# ---- Claude planner (mocked client; no network) ---------------------------
class FakeClient:
    """Claude asks for one tool, then answers. It skips every other tool."""

    def __init__(self):
        self.calls = 0
        self.messages = SimpleNamespace(create=self.create)

    def create(self, **kw):
        self.calls += 1
        if self.calls == 1:
            block = SimpleNamespace(type="tool_use", id="tu_1", name="lookup_ip_reputation", input={"ip": "45.155.205.233"})
            return SimpleNamespace(content=[block])
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="Beaconing to known C2; isolate host.")])


def test_claude_planner_with_guardrail_runs_required_tools():
    agent = TriageAgent(planner=ClaudePlanner(client=FakeClient()))
    alert = next(a for a in load_alerts(SAMPLE) if a["id"] == "ALT-1007")
    agent.tools.set_batch([alert])
    r = agent.triage(alert)
    assert r.summary == "Beaconing to known C2; isolate host."
    tools_run = {t["tool"] for t in r.trace}
    # Claude only called one tool; the guardrail must have filled in the rest
    assert {"lookup_host_context", "lookup_user_context", "map_mitre", "find_related_alerts"} <= tools_run
    assert r.priority == "P1"


# ---- Streamlit UI (skipped when streamlit is not installed) ----------------
def test_parse_alerts_rejects_non_object_items():
    from soc_triage.cli import parse_alerts

    with pytest.raises(ValueError):
        parse_alerts([1, 2])
    with pytest.raises(ValueError):
        parse_alerts({"id": "x"})


def test_streamlit_app_renders_without_errors():
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Alerts"] == "12" and metrics["P1"] == "5"
