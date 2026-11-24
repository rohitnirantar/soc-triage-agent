"""Streamlit front end for the SOC triage agent.

Run with:  streamlit run app.py

This file is a thin view over the existing package: it calls TriageAgent and
evaluate() exactly as the CLI does and adds no scoring logic of its own.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from soc_triage.agent import TriageAgent, TriageResult
from soc_triage.cli import parse_alerts
from soc_triage.evaluate import ORDER, evaluate
from soc_triage.planner import ClaudePlanner
from soc_triage.report import to_json, to_markdown

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "data" / "sample_alerts.json"
EDGE = ROOT / "tests" / "sample_test_alerts.json"
LABELS = ROOT / "data" / "labels.json"

SRC_SAMPLE = "Sample alerts (12, labelled)"
SRC_EDGE = "Prompt-injection & edge cases (4)"
SRC_UPLOAD = "Upload JSON"
SRC_PASTE = "Paste / edit JSON"
PLANNER_RULE = "Rule-based (offline, deterministic)"
PLANNER_CLAUDE = "Claude (tool-use, needs API key)"

COLORS = {"P1": "#c62828", "P2": "#ef6c00", "P3": "#f9a825", "P4": "#2e7d32"}

st.set_page_config(page_title="SOC Triage Agent", page_icon="🛡️", layout="wide")


# ---- helpers ---------------------------------------------------------------
def plain(text: object) -> str:
    """Escape Markdown so untrusted alert fields render as literal text."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~$:])", r"\\\1", str(text))


def badge(priority: str) -> str:
    # priority is always one of P1-P4 (set by the agent), never user text.
    return (
        f"<span style='background:{COLORS[priority]};color:#fff;padding:2px 10px;"
        f"border-radius:6px;font-weight:700'>{priority}</span>"
    )


@st.cache_data(show_spinner=False)
def run_rule(alerts_json: str) -> list[dict]:
    alerts = json.loads(alerts_json)
    return [r.to_dict() for r in TriageAgent().triage_batch(alerts)]


def run_claude(alerts: list[dict], api_key: str, model: str) -> list[dict]:
    import anthropic  # optional dependency

    planner = ClaudePlanner(client=anthropic.Anthropic(api_key=api_key), model=model)
    return [r.to_dict() for r in TriageAgent(planner=planner).triage_batch(alerts)]


def as_results(rows: list[dict]) -> list[TriageResult]:
    return [TriageResult(**r) for r in rows]


# ---- sidebar: input --------------------------------------------------------
st.sidebar.title("🛡️ SOC Triage Agent")
source = st.sidebar.radio("Alerts", [SRC_SAMPLE, SRC_EDGE, SRC_UPLOAD, SRC_PASTE])

if source == SRC_SAMPLE:
    raw = SAMPLE.read_text()
elif source == SRC_EDGE:
    raw = EDGE.read_text()
elif source == SRC_UPLOAD:
    up = st.sidebar.file_uploader("Alerts JSON (array)", type="json")
    raw = up.getvalue().decode("utf-8", errors="replace") if up else None
else:
    first_edge = json.dumps(json.loads(EDGE.read_text())[:1], indent=2)
    raw = st.sidebar.text_area(
        "Edit alerts JSON", value=first_edge, height=260,
        help="Try changing the description of the alert, e.g. remove the injection text.",
    )

planner_choice = st.sidebar.radio("Planner", [PLANNER_RULE, PLANNER_CLAUDE])
api_key = model = ""
if planner_choice == PLANNER_CLAUDE:
    api_key = st.sidebar.text_input("Anthropic API key", type="password",
                                    help="Kept in this session's memory only; never written to disk.")
    model = st.sidebar.text_input("Model", value=os.environ.get("SOC_TRIAGE_MODEL", "claude-sonnet-5-5"))
    st.sidebar.caption("Makes one or more API calls per alert (billed to your key).")

# ---- parse + run -----------------------------------------------------------
st.title("SOC Alert Triage")
st.caption(
    "Tools gather evidence, a transparent score sets the priority. "
    "The LLM (if enabled) writes the summary but never changes the verdict."
)

if not raw:
    st.info("Upload an alerts JSON file in the sidebar.")
    st.stop()

try:
    alerts = parse_alerts(json.loads(raw))
except (ValueError, json.JSONDecodeError) as e:
    st.error(f"Invalid alerts input: {e}")
    st.stop()
if not alerts:
    st.warning("The alert list is empty.")
    st.stop()

alerts_json = json.dumps(alerts, sort_keys=True)
by_id = {a["id"]: a for a in alerts}

try:
    if planner_choice == PLANNER_RULE:
        rows = run_rule(alerts_json)
    else:
        run_clicked = st.sidebar.button("Run triage with Claude", type="primary",
                                        disabled=not api_key)
        if run_clicked:
            with st.spinner("Claude is investigating alerts..."):
                st.session_state["claude_run"] = {"alerts": alerts_json, "rows": run_claude(alerts, api_key, model)}
        saved = st.session_state.get("claude_run")
        if not saved or saved["alerts"] != alerts_json:
            st.info("Enter your API key and press **Run triage with Claude**.")
            st.stop()
        rows = saved["rows"]
except ImportError:
    st.error("The `anthropic` package is not installed. Run `pip install anthropic`.")
    st.stop()
except (ValueError, KeyError, TypeError) as e:
    st.error(f"Could not triage these alerts: {e}")
    st.stop()
except Exception as e:  # API/network failures from the Claude planner
    st.error(f"Claude planner failed: {type(e).__name__}. Check the API key, model name and network.")
    st.stop()

results = as_results(rows)
st.sidebar.divider()
st.sidebar.download_button("Download report (.md)", to_markdown(results), "triage_report.md")
st.sidebar.download_button("Download results (.json)", to_json(results), "triage_results.json")

# ---- summary + queue -------------------------------------------------------
counts = {p: sum(r.priority == p for r in results) for p in ORDER}
cols = st.columns(5)
cols[0].metric("Alerts", len(results))
for col, p in zip(cols[1:], ORDER):
    col.metric(p, counts[p])

tab_queue, *extra = st.tabs(["Triage queue"] + (["Evaluation"] if source == SRC_SAMPLE else []))

with tab_queue:
    df = pd.DataFrame(
        {
            "Priority": [r.priority for r in results],
            "Score": [r.score for r in results],
            "Alert": [r.alert_id for r in results],
            "Rule": [r.rule_name for r in results],
            "Verdict": [r.verdict for r in results],
            "Host": [by_id[r.alert_id].get("host") or "" for r in results],
            "User": [by_id[r.alert_id].get("user") or "" for r in results],
        }
    )
    styled = df.style.map(
        lambda v: f"background-color:{COLORS[v]};color:white;font-weight:700", subset=["Priority"]
    )
    event = st.dataframe(
        styled, hide_index=True, use_container_width=True, on_select="rerun",
        selection_mode="single-row", key="queue",
        column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d")},
    )
    st.caption("Click a row to investigate it.")
    picked = event.selection.rows[0] if event.selection.rows else 0
    r = results[picked]
    alert = by_id[r.alert_id]

    st.divider()
    st.markdown(f"### {plain(r.alert_id)} · {plain(r.rule_name)}")
    st.markdown(
        f"{badge(r.priority)} &nbsp; **score {r.score}/100** &nbsp; `{r.verdict}`",
        unsafe_allow_html=True,
    )
    st.markdown(plain(r.summary))

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Why this score**")
        if r.breakdown:
            bd = pd.DataFrame(r.breakdown)
            bd["effect"] = bd["points"].map(lambda p: "raises risk" if p > 0 else "lowers risk")
            chart = (
                alt.Chart(bd)
                .mark_bar()
                .encode(
                    x=alt.X("points:Q", title="points"),
                    y=alt.Y("factor:N", sort=None, title=None, axis=alt.Axis(labelLimit=420)),
                    color=alt.Color(
                        "effect:N",
                        scale=alt.Scale(domain=["raises risk", "lowers risk"], range=[COLORS["P1"], COLORS["P4"]]),
                        legend=alt.Legend(orient="bottom", title=None),
                    ),
                    tooltip=["factor", "points"],
                )
                .properties(height=max(120, 34 * len(bd)))
            )
            st.altair_chart(chart, use_container_width=True)
            st.caption(f"Sum {sum(p['points'] for p in r.breakdown)} → clamped to 0–100 → {r.score}. "
                       "Thresholds: P1 ≥ 70, P2 ≥ 45, P3 ≥ 25, else P4.")
        else:
            st.write("No risk factors contributed.")
    with right:
        st.markdown("**MITRE ATT&CK**")
        if r.techniques:
            st.dataframe(pd.DataFrame(r.techniques), hide_index=True, use_container_width=True)
        else:
            st.write("No technique matched.")
        st.markdown("**Recommended actions**")
        for a in r.actions:
            st.markdown(f"- {plain(a)}")

    with st.expander("Original alert (untrusted input)"):
        st.json(alert)
    with st.expander(f"Tool-call trace ({len(r.trace)} calls)"):
        for step in r.trace:
            st.markdown(f"`{step['tool']}`")
            st.json({"args": step["args"], "result": step["result"]}, expanded=False)

if extra:
    with extra[0]:
        labels = json.loads(LABELS.read_text())
        ev = evaluate(results, labels)
        a, b, c = st.columns(3)
        a.metric("Exact accuracy", f"{ev['exact_accuracy']:.0%}")
        b.metric("Within one level", f"{ev['within_one_level']:.0%}")
        c.metric("Missed critical (P1 → P3/P4)", ev["missed_critical"])
        st.warning(
            "Small, self-authored label set that was written alongside the scoring weights. "
            "High accuracy shows the pipeline works, not that the weights generalize."
        )
        left, right = st.columns(2)
        with left:
            st.markdown("**Confusion matrix** (rows: expected, columns: got)")
            cm = pd.DataFrame(0, index=ORDER, columns=ORDER)
            for key, n in ev["confusion"].items():
                want, got = key.split("->")
                cm.loc[want, got] = n
            st.dataframe(cm, use_container_width=True)
        with right:
            st.markdown("**Per-alert**")
            st.dataframe(pd.DataFrame(ev["rows"]), hide_index=True, use_container_width=True)
