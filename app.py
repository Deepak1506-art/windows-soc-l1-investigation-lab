from __future__ import annotations
import io, json, re
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
import streamlit as st

from soc_lab.ingest import load_events, normalize_events
from soc_lab.detections import run_detections
from soc_lab.reporting import build_case_report, report_markdown

st.set_page_config(page_title="Windows SOC Analyst L1 | Investigation Lab", page_icon="🛡️", layout="wide")
ROOT = Path(__file__).parent
DATA = ROOT / "data" / "sample_sysmon_events.csv"

st.title("🛡️ Windows SOC Analyst L1 — Investigation Lab")
st.caption("Sysmon event triage • process context • rule-based detections • timeline • case export")
st.warning("Training tool: alerts are investigation leads, not proof of compromise. Validate findings against endpoint context.")

with st.sidebar:
    st.header("Event source")
    uploaded = st.file_uploader("Upload Sysmon CSV or XML", type=["csv", "xml"])
    use_sample = st.checkbox("Use included synthetic sample", value=uploaded is None)
    st.caption("For real endpoint data, use scripts/Export-SysmonEvents.ps1 to export the local Sysmon Operational log.")

try:
    if uploaded is not None:
        raw = load_events(uploaded, uploaded.name)
        source_label = uploaded.name
    elif use_sample:
        raw = load_events(DATA, DATA.name)
        source_label = "Included synthetic sample"
    else:
        raw = pd.DataFrame()
        source_label = "No data selected"
except Exception as e:
    st.error(f"Could not load event file: {e}")
    st.stop()

if raw.empty:
    st.info("Upload a Sysmon CSV/XML file or enable the sample dataset.")
    st.stop()

events = normalize_events(raw)
detections = run_detections(events)
st.caption(f"Data source: **{source_label}** | {len(events)} normalized events")

high_count = int((detections["severity"] == "High").sum()) if not detections.empty else 0
cols = st.columns(5)
metrics = [
    ("Events loaded", len(events)),
    ("Detection hits", len(detections)),
    ("High severity", high_count),
    ("Unique process GUIDs", events["ProcessGuid"].replace("", pd.NA).nunique()),
    ("Event IDs", events["EventID"].replace("", pd.NA).nunique()),
]
for c, (label, value) in zip(cols, metrics):
    c.metric(label, value)

st.subheader("Detection overview")
if detections.empty:
    st.success("No detection rules matched the loaded events. This does not prove the system is safe.")
else:
    left, right = st.columns(2)
    with left:
        sev = detections["severity"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0)
        st.bar_chart(sev)
    with right:
        st.bar_chart(detections["rule_name"].value_counts().head(10))
    st.markdown("### Detection queue")
    severity_filter = st.multiselect("Severity filter", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
    filtered = detections[detections["severity"].isin(severity_filter)]
    show_cols = [c for c in ["severity", "rule_name", "technique_id", "timestamp", "Image", "CommandLine", "User", "ProcessGuid", "reason"] if c in filtered.columns]
    st.dataframe(filtered[show_cols], use_container_width=True, hide_index=True)

st.subheader("Process investigation")
guids = sorted(g for g in events["ProcessGuid"].dropna().astype(str).unique() if g.strip())
if guids:
    selected_guid = st.selectbox("Select Process GUID", guids)
    related = events[events["ProcessGuid"].astype(str) == selected_guid].copy()
    related = related.sort_values("timestamp", na_position="last")
    st.write(f"**{len(related)} event(s)** associated with this process GUID.")
    timeline_cols = [c for c in ["timestamp", "EventID", "event_name", "Image", "CommandLine", "ParentImage", "User", "DestinationIp", "DestinationPort"] if c in related.columns]
    st.dataframe(related[timeline_cols], use_container_width=True, hide_index=True)
    matching = detections[detections["ProcessGuid"].astype(str) == selected_guid] if not detections.empty else pd.DataFrame()
    if not matching.empty:
        st.markdown("#### Related detections")
        st.dataframe(matching[[c for c in ["severity", "rule_name", "technique_id", "reason"] if c in matching.columns]], use_container_width=True, hide_index=True)
else:
    selected_guid = ""
    st.info("No Process GUID values found. Some event types may not include process identifiers.")

st.subheader("Analyst checklist")
st.markdown("""
1. Confirm process image and command line.
2. Review parent process, user and logon context.
3. Correlate process creation (Event ID 1), network connection (Event ID 3) and termination (Event ID 5) when available.
4. Check whether the behavior is expected for the host and user.
5. Record evidence, limitations and disposition; escalate unresolved suspicious activity.
""")

st.subheader("Raw event records")
with st.expander("View / filter normalized event data"):
    event_ids = sorted(events["EventID"].dropna().astype(str).unique())
    chosen_ids = st.multiselect("Filter Event IDs", event_ids, default=event_ids)
    view = events[events["EventID"].astype(str).isin(chosen_ids)]
    st.dataframe(view, use_container_width=True, hide_index=True)

st.subheader("Create analyst case note")
with st.form("case_form"):
    case_id = st.text_input("Case ID", value="SOC-CASE-001")
    analyst = st.text_input("Analyst", value="L1 Analyst")
    summary = st.text_area("Summary", value=f"Investigate process activity for {selected_guid or 'selected event set'}.")
    disposition = st.selectbox("Disposition", ["Needs investigation", "Escalated", "Benign / expected", "Closed - insufficient evidence"])
    evidence = st.text_area("Evidence / timestamps / event IDs", placeholder="Add exact timestamps, Event IDs, image paths, command lines, source/destination details and why they matter.")
    submitted = st.form_submit_button("Generate case report")
if submitted:
    report = build_case_report(case_id, analyst, summary, disposition, evidence, selected_guid, related if guids else events, detections)
    st.success("Case report generated. Review it before using or sharing.")
    st.download_button("Download case report (JSON)", json.dumps(report, indent=2, default=str), file_name=f"{case_id}.json", mime="application/json")
    st.download_button("Download case report (Markdown)", report_markdown(report), file_name=f"{case_id}.md", mime="text/markdown")
