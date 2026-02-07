# PowerShell via WinRM Connection Received

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | PowerShell |

#### Hypothesis
This hunt detects malicious abuse of WinRM (wsmprovhost.exe) for lateral movement (T1021.006) or remote code execution (T1059.001). We look for anomalous cases where:

wsmprovhost.exe spawns from unexpected parents (e.g., powershell.exe instead of svchost.exe)

Command lines contain PowerShell artifacts (encoded commands/obfuscation)

Remote logons originate from suspicious IPs

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
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| ParentBaseFileName = "wsmprovhost.exe"
| formatTime(format="%Y-%m-%d %H:%M:%S", as="ExecTimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
// Exclusions
| FileName != /iisreset/i
| UserName != /itsvc_SecPatch/i
| not (ComputerName = "EFG-FACTDBSTG" and UserName = "oabdelkhaleq")
}, include=[ComputerName, ExecTimeStamp, FileName, ParentProcessId, ParentBaseFileName, CommandLine, Tree], name="ProcessRollup2T")

| event_platform=Win #event_simpleName = UserLogon
| match(table="ProcessRollup2T", field=[ComputerName, ContextProcessId], column=[ComputerName, ParentProcessId])
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| RemoteIP = *
| groupBy([ExecTimeStamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine, LogonType, LocalIP, RemoteIP, LogonDomain], limit=max)
```
---