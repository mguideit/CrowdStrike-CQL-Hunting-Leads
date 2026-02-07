# Suspicious Rundll32.exe Execution via Scheduled Tasks

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 |

#### Hypothesis
Adversaries may abuse rundll32.exe to execute malicious DLLs through modified or newly registered scheduled tasks, leveraging LOLBIN techniques to evade detection and maintain persistence.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* 

#### Tags
`#Hunting` `#LOLBins`

---

## CrowdStrike (CQL)

```cql
event_platform=Win #event_simpleName=/ProcessRollup2|SyntheticProcessRollup2/i
| CommandLine != /sysmain\.dll/i
| rename(field="TargetProcessId", as="RpcClientProcessId")
| rename(field="SHA256HashData", as="ResponsibleProcessSHA256HashData")
| join(query={#event_simpleName = /ScheduledTaskRegistered|ScheduledTaskModified/i TaskExecCommand= /rundll32/i TaskExecArguments != /PcaSvc\.dll|WSClient\.dll\,WSpTLR licensing/i | rename(field="UserName", as="Creator")}, field=[RpcClientProcessId], include=[TaskName, Creator, TaskAuthor, TaskExecCommand, TaskExecArguments])
| groupBy([TaskName, TaskAuthor, TaskExecCommand, TaskExecArguments, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine], function=[count(ComputerName, distinct=true, as="UniqComputerCount"), collect([ComputerName, Creator, ResponsibleProcessSHA256HashData])], limit=max)
| UniqComputerCount < 6
| sort(UniqComputerCount, limit=20000)
```
---
