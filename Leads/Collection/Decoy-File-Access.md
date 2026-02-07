# Decoy File Access

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

#### Hypothesis
If a process accesses specially crafted decoy files (e.g., ZZZZZ*.doc, XORXOR*.doc) that legitimate users or applications should never open, this may indicate malicious data collection activity consistent with MITRE ATT&CK T1005 – Data from Local System.
Attackers performing reconnaissance, staging, or pre-exfiltration scanning often enumerate and access documents on disk, and touching these decoys is a strong signal of suspicious or automated discovery behavior.

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
defineTable(query={
#event_simpleName = /FileOpenInfo|RansomwareOpenFile/i
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ContextProcessId","cid"], as="Tree")
| TargetFileName = /ZZZZZ.+\.doc|XORXOR.+\.doc/i
| formatTime(format="%Y-%m-%d %H:%M:%S", as="FileAccessTimeStamp", timezone="Africa/Cairo")
}, include=[FileAccessTimeStamp, #event_simpleName, ComputerName, Tree, ContextProcessId, TargetFileName], name="FileAccessT")
| #event_simpleName = ProcessRollup2
| FileName != /(MsMpEng|MsSense)\.exe/i
| match(table="FileAccessT", field=[ComputerName, TargetProcessId], column=[ComputerName, ContextProcessId])
| groupBy([FileAccessTimeStamp, ComputerName, UserName, #event_simpleName, Tree, ParentBaseFileName, FileName, CommandLine, TargetFileName])
```
---
