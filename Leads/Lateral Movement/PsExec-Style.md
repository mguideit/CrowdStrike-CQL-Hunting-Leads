# PsExec Style

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares |
| Lateral Movement | [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services |

#### Hypothesis
Adversaries may leverage PsExec or similar remote administration tools to execute binaries on remote systems for lateral movement. This activity often involves writing a PE file to disk on a target machine followed by the creation and execution of a Windows service that launches the uploaded binary. Suspicious activity may be identified by correlating newly written executable files with subsequent service creation events on the same host using the same binary path. Detection of this sequence may indicate unauthorized remote execution or lateral movement attempts.

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
#event_simpleName = /ProcessRollup/i ParentBaseFileName = "services.exe"
| rename(field="ImageFileName", as="TargetFileName")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Investigate")
| join(
query={
#event_simpleName = PeFileWritten
| TargetFileName != /DeploymentTool|pbpsdeploy|MOMAgentInstaller/i
| join(
query={
#event_simpleName = UserLogon
| RemoteIP != ""
| RemoteIP = *
| formatTime(format="%Y-%m-%d %H:%M:%S", as="TimeStamp", timezone="Africa/Cairo")
| case {LogonType = 3 | LogonType := "Network Logon"; *}
},
field=[ComputerName, ContextProcessId],
include=[UserPrincipal, LogonType, RemoteIP, ContextProcessId, RemoteAccount, TimeStamp, Investigate]
)
},
field=[ComputerName, TargetFileName],
include=[UserName, TargetFileName, UserName, LogonType, RemoteIP, ContextProcessId, RemoteAccount, ContextImageFileName, SHA256HashData, TimeStamp]
)
| TargetFileName != /TEMP\\\{[A-F0-9\-]{36}\}\\[^\\]+\.exe|Veeam|STRemoteCommand/i
| LocalIPEncoded := urlEncode("LocalIP")
| RemoteIPEncoded := urlEncode("RemoteIP")
| groupBy(
[TimeStamp, ComputerName, UserName, Investigate, ParentBaseFileName, TargetFileName, CommandLine, LogonType, LocalIP, RemoteIP, ContextImageFileName, ContextProcessId, SHA256HashData],
limit=max
)
| sort(ComputerName, limit=20000)
```
---
