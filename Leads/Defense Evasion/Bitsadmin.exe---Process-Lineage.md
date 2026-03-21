# Bitsadmin.exe - Process Lineage

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs |

#### Hypothesis
Adversaries may abuse bitsadmin.exe to download malicious files to Windows endpoints—effectively performing an Ingress Tool Transfer (MITRE ATT&CK T1105). This abuse often involves the /transfer or /addfile commands, and can be indicative of fileless or living-off-the-land (LOTL) techniques.

CommandLine = /Transfer|Addfile/i: This is the core detection logic. It filters for bitsadmin.exe executions where the command line contains either /Transfer or /Addfile (case-insensitive due to /i). These are common parameters used by attackers for moving files onto or within a system, or adding files to BITS jobs for later transfer.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* 

#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
event_platform="Win" #event_simpleName = ProcessRollup2 FileName = bitsadmin.exe
| CommandLine = /Transfer|Addfile/i
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine], limit=max)
```
---
