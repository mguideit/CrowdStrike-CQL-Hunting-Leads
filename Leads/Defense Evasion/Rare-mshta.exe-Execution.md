# Rare mshta.exe Execution

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta |

#### Hypothesis
Adversaries may use mshta.exe to run malicious scripts or bypass whitelisting. Suspicious executions from unknown sources and unusual parent processes may indicate malicious activity.

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
event_platform=Win #event_simpleName=ProcessRollup2
| FileName=mshta.exe
| rename(field="ParentProcessId", as="PPID")
| CommandLine != /\\HP\\|cisco|egy-wds|F\:/i
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine],limit=max)
| sort(ComputerName, limit=20000)
```
---
