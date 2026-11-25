from __future__ import annotations
from datetime import datetime, timezone
import pandas as pd

def build_case_report(case_id, analyst, summary, disposition, evidence, guid, related_events, detections):
    event_records=[]
    if isinstance(related_events, pd.DataFrame):
        for _, row in related_events.iterrows():
            event_records.append({k: (None if pd.isna(v) else str(v)) for k,v in row.to_dict().items()})
    det_records=[]
    if isinstance(detections, pd.DataFrame):
        for _, row in detections.iterrows():
            if not guid or str(row.get("ProcessGuid","")) == str(guid):
                det_records.append({k: (None if pd.isna(v) else str(v)) for k,v in row.to_dict().items()})
    return {
        "case_id": case_id.strip() or "SOC-CASE-UNASSIGNED",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "analyst": analyst,
        "summary": summary,
        "disposition": disposition,
        "process_guid": guid,
        "evidence_notes": evidence,
        "events": event_records,
        "detections": det_records,
        "limitations": ["Rule-based detections are leads, not proof of compromise.", "Confirm findings using endpoint, user and network context.", "If the source is synthetic, this case is for training only."]
    }

def report_markdown(report):
    lines=[f"# {report['case_id']}", "", f"**Created (UTC):** {report['created_utc']}", f"**Analyst:** {report['analyst']}", f"**Disposition:** {report['disposition']}", f"**Process GUID:** {report['process_guid']}", "", "## Summary", report["summary"], "", "## Evidence notes", report["evidence_notes"] or "No analyst evidence notes supplied.", "", "## Detection hits"]
    if report["detections"]:
        for d in report["detections"]:
            lines += [f"- **{d.get('severity')}** — {d.get('rule_name')} ({d.get('technique_id')}): {d.get('reason')}"]
    else: lines.append("No detections attached to this process.")
    lines += ["", "## Event evidence", f"Included {len(report['events'])} event record(s).", "", "## Limitations"]
    lines += [f"- {x}" for x in report["limitations"]]
    return "\n".join(lines)
