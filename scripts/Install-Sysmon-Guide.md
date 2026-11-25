# Real Sysmon collection (optional)
1. Install Sysmon from Microsoft's Sysinternals package using Microsoft's official instructions.
2. Verify the `Microsoft-Windows-Sysmon/Operational` event log exists in Event Viewer.
3. Run PowerShell as Administrator.
4. From this project folder, run:
   `.\scripts\Export-SysmonEvents.ps1 -MaxEvents 2000`
5. In the Streamlit app, upload `data\sysmon_export.csv`.

**Privacy:** Sysmon records may contain usernames, file paths, command lines, IP addresses and other sensitive details. Inspect and redact before uploading to GitHub or sharing screenshots. Do not upload live logs to a public repository.
