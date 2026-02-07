# Mshta Initiating Connections

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta |

#### Hypothesis
Adversaries may abuse mshta.exe to connect to external IPs for C2, payload delivery, or exploitation. Detecting such connections may reveal malicious activity.

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
| rename(field="TargetProcessId", as="ContextProcessId")
| rename(field="FileName", as="ContextBaseFileName")
| select([ComputerName, FileName, ContextProcessId, UserName, CommandLine, ParentBaseFileName, ParentProcessId])
| join(
query={#event_simpleName=NetworkConnectIP4 | ContextBaseFileName = mshta.exe | RemoteIP != /(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)/i | formatTime(format="%Y-%m-%d %H:%M:%S", as="TimeStamp", timezone="Africa/Cairo")},
field=[ComputerName,ContextProcessId],
include=[TimeStamp, ComputerName, RemoteIP, RemotePort, ContextProcessId, ContextBaseFileName]
)
| groupBy([TimeStamp, ComputerName, ContextBaseFileName, ContextProcessId, RemoteIP, RemotePort], function=[count(ComputerName, distinct=true, as=UniqComputerCount), collect([ParentBaseFileName, ParentProcessId, CommandLine, UserName], limit=20000)], limit=max)
```
---
