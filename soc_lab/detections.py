from __future__ import annotations
import re
import pandas as pd

RULES = [
    {"id":"SOC-001","name":"PowerShell with encoded or hidden execution","severity":"High","technique_id":"T1059.001","description":"PowerShell command line contains encoded-command or hidden-window indicators."},
    {"id":"SOC-002","name":"Suspicious script host","severity":"Medium","technique_id":"T1059","description":"A script host (wscript/cscript/mshta) executed."},
    {"id":"SOC-003","name":"Executable launched from user-writable location","severity":"Medium","technique_id":"T1204.002","description":"Process image path is under common user-writable directories."},
    {"id":"SOC-004","name":"Office application spawned a shell","severity":"High","technique_id":"T1566.001","description":"Office process is parent of a command shell or scripting process."},
    {"id":"SOC-005","name":"Network connection from script host","severity":"Medium","technique_id":"T1105","description":"Network event associated with a scripting host."},
    {"id":"SOC-006","name":"Potential LOLBin execution","severity":"Low","technique_id":"T1218","description":"A known dual-use Windows utility executed; validate arguments and context."},
]
def run_detections(events: pd.DataFrame) -> pd.DataFrame:
    hits=[]
    for _, r in events.iterrows():
        image=str(r.get("Image","")).lower()
        cmd=str(r.get("CommandLine","")).lower()
        parent=str(r.get("ParentImage","")).lower()
        eid=str(r.get("EventID",""))
        guid=str(r.get("ProcessGuid",""))
        ts=r.get("timestamp","")
        user=str(r.get("User",""))
        host=str(r.get("Computer",""))
        def add(rule, reason):
            hits.append({"rule_id":rule["id"],"rule_name":rule["name"],"severity":rule["severity"],"technique_id":rule["technique_id"],"timestamp":ts,"EventID":eid,"Image":r.get("Image",""),"CommandLine":r.get("CommandLine",""),"User":user,"Computer":host,"ProcessGuid":guid,"reason":reason})
        if eid=="1" and re.search(r"(-enc(?:odedcommand)?\b|windowstyle\s+hidden| -w\s+hidden)",cmd):
            add(RULES[0],"Command line contains encoded or hidden PowerShell execution indicators.")
        if eid=="1" and re.search(r"\\(wscript|cscript|mshta)\.exe$",image):
            add(RULES[1],"Script host executable created a process.")
        if eid=="1" and any(x in image for x in ["\\\\users\\\\","\\\\appdata\\\\","\\\\downloads\\\\","\\\\temp\\\\"]):
            add(RULES[2],"Executable image is located in a commonly user-writable path.")
        if eid=="1" and re.search(r"\\(winword|excel|powerpnt|outlook)\.exe$",parent) and re.search(r"\\(cmd|powershell|pwsh|wscript|cscript)\.exe$",image):
            add(RULES[3],"Office parent process launched a shell or script host.")
        if eid=="1" and any(x in image for x in ["\\\\users\\\\","\\\\appdata\\\\","\\\\downloads\\\\","\\\\temp\\\\"]):
            add(RULES[4],"Network connection event belongs to a scripting host.")
        if eid=="1" and re.search(r"\\(rundll32|regsvr32|mshta|certutil|bitsadmin)\.exe$",image):
            add(RULES[5],"Dual-use Windows utility executed; inspect command line and context.")
    return pd.DataFrame(hits, columns=["rule_id","rule_name","severity","technique_id","timestamp","EventID","Image","CommandLine","User","Computer","ProcessGuid","reason"])
