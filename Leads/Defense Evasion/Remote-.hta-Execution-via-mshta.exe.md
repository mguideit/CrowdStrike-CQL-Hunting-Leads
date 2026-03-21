# Remote .hta Execution via mshta.exe

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta |

#### Hypothesis
A remote .hta file executed via mshta.exe—especially with URL- or UNC-based paths (https://…/*.hta or \\host\share\file.hta)—is a hallmark of adversarial proxy execution. Threat actors abuse mshta.exe (a signed, trusted binary) to sidestep application control and execute VBScript or JScript fetched from a remote host.This technique is rarely seen in legitimate environments unless explicitly whitelisted (e.g. internal HTA apps), and should be treated as a high-confidence threat indicator.

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
event_platform=Win #event_simpleName=ProcessRollup2 FileName = mshta.exe
| CommandLine = /\/\//i
| CommandLine = /mshta(\.exe|\.exe\")?\s*(?<URL>(?:https?.+\.hta))/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine, URL], limit=max)
```
---