# Certutil Downloading

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer |

#### Hypothesis
Adversaries may abusecertutil.exe, a trusted Windows utility, to download malicious files, leveraging its legitimate functionality to evade detection and bypass security controls.

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
event_platform=Win #event_simpleName=/ProcessRollup2|SyntheticProcessRollup2/i FileName = certutil.exe
| CommandLine = /http/i
// Exclusions
| ParentBaseFileName != /HTTPDebuggerSvc/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ContextProcessId","cid"], as="Tree")
| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine])
```
---
