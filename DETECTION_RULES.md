# Detection rules (training heuristics)

| Rule | Severity | ATT&CK reference | Logic | Analyst validation |
|---|---|---|---|---|
| SOC-001 Encoded/hidden PowerShell | High | T1059.001 | Event 1 command line contains encoded or hidden execution flags | Decode safely in an isolated lab; inspect parent, user and script context |
| SOC-002 Script host execution | Medium | T1059 | Event 1 image is wscript.exe, cscript.exe or mshta.exe | Verify script path, arguments, signer and parent |
| SOC-003 User-writable executable | Medium | T1204.002 (indicative) | Event 1 image is under Users/AppData/Downloads/Temp | Determine provenance, hash, signature and expected application |
| SOC-004 Office launches shell | High | T1566.001 (indicative) | Office parent launches shell/script host | Validate document/email context and process chain |
| SOC-005 Script host network | Medium | T1105 (indicative) | Event 3 image is a script host | Check destination reputation, DNS, proxy and expected behavior |
| SOC-006 LOLBin execution | Low | T1218 (indicative) | Event 1 image is rundll32/regsvr32/mshta/certutil/bitsadmin | Review exact arguments; these tools also have legitimate uses |

Rules are intentionally simple. Severity reflects triage priority, not confirmed impact. Technique mappings are approximate and must be checked against the observed behavior and current ATT&CK descriptions.
