import pandas as pd
from soc_lab.detections import run_detections

def test_encoded_powershell_detection():
    df = pd.DataFrame([{"EventID":"1","Image":r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","CommandLine":"powershell -EncodedCommand abc","ParentImage":r"C:\Windows\System32\cmd.exe","ProcessGuid":"{abc}","User":"test","Computer":"lab","timestamp":""}])
    hits=run_detections(df)
    assert "SOC-001" in hits["rule_id"].tolist()
