# Windows SOC Analyst L1 — Investigation Lab (V2)

A local analyst-training dashboard for Windows Sysmon event triage, process correlation, rule-based detection, investigation timeline and case export.

## Features
- CSV and Sysmon XML ingestion (Event/System and EventData fields)
- Normalized event fields and Event ID names
- Rule-based detections with severity and MITRE ATT&CK technique references
- Detection queue and severity filtering
- Process GUID investigation timeline
- Analyst checklist
- Case report export to JSON and Markdown
- PowerShell script to export real Sysmon Operational events to CSV
- Synthetic sample dataset for safe demonstration

## Important limitations
This is a portfolio/training prototype, not a production SIEM or EDR. Detection rules are intentionally simple and can produce false positives or miss malicious activity. Alerts are leads, not proof of compromise. MITRE technique labels are indicative and should be validated against behavior. Sample events are synthetic.

## Run on Windows
Open PowerShell in the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Open the local URL shown in the terminal (usually `http://localhost:8501`).

## Import real Sysmon events (optional)
- Follow `scripts/Install-Sysmon-Guide.md`.
- Run PowerShell as Administrator if needed:
  `.\scripts\Export-SysmonEvents.ps1 -MaxEvents 2000`
- Upload the generated `data\sysmon_export.csv` in the app.

Do not upload raw live logs, command lines, usernames, hostnames or IP addresses to public GitHub without review and redaction.

## Detection rules
See `DETECTION_RULES.md`. Rules operate on event fields and are not a substitute for threat hunting or endpoint investigation.

## Suggested demo
1. Load included sample data.
2. Show the encoded PowerShell detection.
3. Select the associated Process GUID and inspect Event IDs 1, 3 and 5.
4. Explain the synthetic public documentation IP and the training nature of the dataset.
5. Generate a case report and explain why you chose the disposition.

## Resume description
Built a Windows SOC L1 investigation lab using Streamlit and Python to ingest Sysmon CSV/XML events, normalize process telemetry, apply rule-based detections mapped to MITRE ATT&CK, correlate events by Process GUID, visualize investigation timelines, and export analyst case reports. Added a PowerShell collection script for local Sysmon log export and documented false-positive/validation limitations.

## Project structure
- `app.py` — Streamlit UI
- `soc_lab/ingest.py` — CSV/XML ingestion and normalization
- `soc_lab/detections.py` — detection logic
- `soc_lab/reporting.py` — JSON/Markdown case reports
- `scripts/` — PowerShell event export and setup notes
- `data/` — synthetic sample
- `tests/` — basic rule test
