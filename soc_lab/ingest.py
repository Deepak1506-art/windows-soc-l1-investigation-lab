from __future__ import annotations
import io, xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd

EVENT_NAMES = {"1":"Process Create", "3":"Network Connect", "5":"Process Terminate", "7":"Image Load", "10":"Process Access", "11":"File Create", "12":"Registry Create/Delete", "13":"Registry Value Set", "22":"DNS Query"}

ALIASES = {
    "EventID": ["EventID", "Event Id", "Event ID", "event_id"],
    "ProcessGuid": ["ProcessGuid", "Process GUID", "ProcessGUID", "process_guid"],
    "Image": ["Image", "ProcessImage", "process_image"],
    "CommandLine": ["CommandLine", "Command Line", "command_line"],
    "ParentImage": ["ParentImage", "Parent Image", "parent_image"],
    "User": ["User", "Account", "user"],
    "UtcTime": ["UtcTime", "TimeCreated", "Timestamp", "timestamp", "Date"],
    "DestinationIp": ["DestinationIp", "Destination IP", "destination_ip"],
    "DestinationPort": ["DestinationPort", "Destination Port", "destination_port"],
    "SourceIp": ["SourceIp", "Source IP", "source_ip"],
    "RuleName": ["RuleName", "Rule Name", "rule_name"],
    "Computer": ["Computer", "Hostname", "host"],
}

def _xml_events(data: bytes) -> pd.DataFrame:
    root = ET.fromstring(data)
    rows = []
    # Accept either one Event or a wrapper containing many Event elements.
    for ev in root.iter():
        if ev.tag.split("}")[-1] != "Event":
            continue
        row = {}
        for child in ev:
            tag = child.tag.split("}")[-1]
            if tag == "System":
                for syschild in child:
                    name = syschild.tag.split("}")[-1]
                    if name == "EventID": row["EventID"] = syschild.text
                    elif name == "TimeCreated": row["UtcTime"] = syschild.attrib.get("SystemTime", "")
                    elif name == "Computer": row["Computer"] = syschild.text or ""
                row["EventID"] = row.get("EventID", "")
            elif tag == "EventData":
                for item in child:
                    row[item.attrib.get("Name", item.tag.split("}")[-1])] = item.text or ""
        if row:
            rows.append(row)
    if not rows:
        raise ValueError("No Sysmon Event elements were found in the XML.")
    return pd.DataFrame(rows)

def load_events(source, filename: str = "") -> pd.DataFrame:
    name = (filename or getattr(source, "name", "") or "").lower()
    if hasattr(source, "read"):
        data = source.read()
        try: source.seek(0)
        except Exception: pass
    else:
        data = Path(source).read_bytes()
    if name.endswith(".xml") or data.lstrip().startswith(b"<"):
        return _xml_events(data)
    return pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)

def normalize_events(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [str(c).strip() for c in out.columns]
    for target, names in ALIASES.items():
        if target not in out.columns:
            for name in names:
                if name in out.columns:
                    out[target] = out[name]
                    break
        if target not in out.columns:
            out[target] = ""
    out["EventID"] = out["EventID"].astype(str).str.extract(r"(\d+)").fillna("")
    out["ProcessGuid"] = out["ProcessGuid"].astype(str).fillna("")
    out["event_name"] = out["EventID"].map(EVENT_NAMES).fillna("Event")
    raw_time = out["UtcTime"].astype(str).replace({"": None})
    out["timestamp"] = pd.to_datetime(raw_time, errors="coerce", utc=True)
    # Some exports use TimeCreated or non-UTC timestamp formats.
    return out
