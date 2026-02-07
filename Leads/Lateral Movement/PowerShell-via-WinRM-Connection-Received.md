# PowerShell via WinRM Connection Received

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management |
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell |

#### Hypothesis
Adversaries may abuse Windows Remote Management (WinRM) to execute remote commands and move laterally across the environment. Since WinRM leverages wsmprovhost.exe to spawn remote execution contexts, malicious activity may be identified by detecting abnormal parent-child process relationships

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
event_platform=Win #event_simpleName = ProcessRollup2
| ParentBaseFileName = "wsmprovhost.exe"
| formatTime(format="%Y-%m-%d %H:%M:%S", as="ExecTimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
// Exclusions
| FileName != /iisreset/i
}, include=[ComputerName, ExecTimeStamp, FileName, ParentProcessId, ParentBaseFileName, CommandLine, Tree], name="ProcessRollup2T")

| event_platform=Win #event_simpleName = UserLogon
| match(table="ProcessRollup2T", field=[ComputerName, ContextProcessId], column=[ComputerName, ParentProcessId], nrows=max)
| RemoteIP = *
| groupBy([ExecTimeStamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine, LogonType, LocalIP, RemoteIP, LogonDomain], limit=max)
```
---
