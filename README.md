# SOC Triage Agent

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

A SOC alert-triage pipeline. It ingests SIEM alerts (Sentinel/Splunk-style JSON), investigates each one by calling tools, maps it to MITRE ATT&CK, scores risk, assigns a P1–P4 priority, and writes an analyst-ready report with recommended response actions.

Runs fully **offline** by default. Optionally lets **Claude** drive the investigation through tool use. Ships with a CLI and a small Streamlit UI.

## Architecture

```
alerts.json ─► Planner ─► Tools (act) ─► Findings (observe) ─► Scoring ─► Priority + Actions ─► Report
                 │            ▲
        rule | Claude         └── guardrail: required tools always run
```

| Component | Role |
|---|---|
| `tools.py` | 7 side-effect-free tools: IP/domain reputation, user/host context, MITRE mapping, command-line analysis, alert correlation |
| `planner.py` | `RulePlanner` (deterministic) or `ClaudePlanner` (Anthropic tool-use loop) |
| `agent.py` | Plan → act → observe → score → decide; explainable score breakdown |
| `report.py` | JSON + Markdown output |
| `evaluate.py` | Accuracy vs. analyst-labelled ground truth |
| `app.py` | Streamlit UI: ranked queue, per-alert score breakdown, tool trace, evaluation tab |

### Design decisions

- **The LLM never owns the verdict.** Priority comes from a transparent, deterministic score. Claude can write the analyst summary but cannot change the priority.
- **Required-tool guardrail.** The agent always runs the lookups the score depends on, whatever the planner chose. In practice this means the planner's tool selection does not affect the score: the default `RulePlanner` runs the same fixed tool list for every alert, and with `ClaudePlanner` the model's added value is the investigation narrative and the extra calls it makes, not the verdict.
- **Untrusted alert fields.** The "benign context" discount (e.g. text saying "approved change") applies only when there is no hard evidence (bad reputation, malicious command line), so an attacker cannot write their way to a lower priority on an alert that has such evidence. Covered by `test_prompt_injection_in_description_cannot_lower_priority`. The Claude planner's system prompt also tells the model to treat alert fields as data.
- **Explainability.** Every result includes the per-factor score breakdown and the full tool-call trace.

## Quick start

```bash
git clone https://github.com/rohitnirantar/soc-triage-agent.git && cd soc-triage-agent
pip install -e ".[dev]"
python -m soc_triage triage            # triage data/sample_alerts.json -> reports/
python -m soc_triage eval              # accuracy vs data/labels.json
python -m pytest -q
```

The core has no third-party dependencies; `pip install -e .` alone is enough to run the CLI.

Your own alerts: `python -m soc_triage triage --input my_alerts.json --out out/`

Required alert fields: `id`, `timestamp` (ISO 8601), `rule_name`. Optional: `vendor_severity`, `user`, `host`, `src_ip`, `dest_ip`, `domain`, `command_line`, `description`.

### Web UI

```bash
pip install -e ".[ui]"
streamlit run app.py
```

- Pick the labelled sample set, the prompt-injection/edge-case set, upload a file, or paste and edit alert JSON.
- Click an alert in the queue to see its score breakdown, ATT&CK techniques, recommended actions and the tool-call trace.
- Paste the prompt-injection alert and edit its description to watch the priority respond (or not) to attacker-controlled text.
- The Evaluation tab shows accuracy and a confusion matrix for the sample set.
- Download the Markdown or JSON report.

The UI is a view over the same `TriageAgent` the CLI uses; it contains no scoring logic.

### Using Claude as the planner

```bash
pip install -e ".[claude]"
export ANTHROPIC_API_KEY=...            # PowerShell: $env:ANTHROPIC_API_KEY="..."
python -m soc_triage triage --planner claude
```

In the UI, choose the Claude planner and paste a key; it is kept in session memory only.

## Sample output

```
P1  100  ALT-1002  Suspicious PowerShell execution
P1   91  ALT-1001  Multiple failed logons followed by success
P1   90  ALT-1005  Credential dumping tool detected
P1   88  ALT-1011  Certutil used to download file
P1   75  ALT-1007  Outbound connection to known C2
P2   58  ALT-1003  Phishing URL clicked
...
```

See `reports/triage_report.md` for the full report with ATT&CK mapping and recommended actions.

## Limitations

- Detection is keyword/regex matching against a tiny local threat-intel file (5 IPs, 2 domains) and asset file. This demonstrates the pipeline architecture, not a production detection engine. Production use needs real feeds (VirusTotal, AbuseIPDB) and a CMDB.
- The 12-alert labelled set is small and was written alongside the scoring weights, so 100% accuracy there demonstrates the pipeline works, not that the weights generalize. Next step: evaluate on a public dataset.
- The "benign context" discount can still be triggered by attacker-controlled text when an alert has no threat-intel or command-line hit (for example, a novel C2 address missing from intel). The injection test covers alerts that do have hard evidence.
- That injection test exercises the scoring logic with the rule planner, which never interprets alert text as instructions. It is not a test of LLM prompt-injection resistance.
- The Claude planner is unit-tested with a mocked client; it has not been exercised against the live API in CI.

## Roadmap

- Live threat-intel connectors (AbuseIPDB, VirusTotal)
- Sentinel/Splunk ingestion via API
- Ticket creation (Jira/ServiceNow) and SOAR hand-off
- Benchmark on a public alert dataset
- Run the Claude planner live and commit a sample trace

## License

MIT
