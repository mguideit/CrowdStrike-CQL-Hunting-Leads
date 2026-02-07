# PsExec Style

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares |

#### Hypothesis
This query is hunting for potential PsExec-style execution by looking for: - PE files written to disk (PeFileWritten). - A corresponding service start (ServiceStarted) on the same machine (ComputerName) with the same binary file (BinaryFile). Use Case: This query can help identify suspicious activity where an attacker might be using PsExec or similar tools to execute binaries remotely or laterally move within a network. The results can be further investigated to determine if the activity is malicious or legitimate.

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
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38 // ValU
| CommandLine != /BTExecService/i
| rename(field="ImageFileName", as="TargetFileName")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Investigate")
| join(
query={
#event_simpleName = PeFileWritten
| TargetFileName != /DeploymentTool|\\EFG|pbpsdeploy|MOMAgentInstaller/i
| join(
query={
#event_simpleName = UserLogon
| RemoteIP != ""
| RemoteIP = *
| formatTime(format="%Y-%m-%d %H:%M:%S", as="TimeStamp", timezone="Africa/Cairo")
| case {LogonType = 3 | LogonType := "Network Logon"; *}
| ComputerName != /EFG-FSET-FILESR/i
},
field=[ComputerName, ContextProcessId],
include=[UserPrincipal, LogonType, RemoteIP, ContextProcessId, RemoteAccount, TimeStamp, Investigate]
)
},
field=[ComputerName, TargetFileName],
include=[UserName, TargetFileName, UserName, LogonType, RemoteIP, ContextProcessId, RemoteAccount, ContextImageFileName, SHA256HashData, TimeStamp]
)
| TargetFileName != /TEMP\\\{[A-F0-9\-]{36}\}\\[^\\]+\.exe|Veeam|STRemoteCommand/i
| not in(field="RemoteIP", values=["10.0.55.45", "10.4.3.27", "10.4.3.13", "10.55.18.100", "10.4.3.25", "10.55.33.200"])
| not (LocalIP = "10.55.21.51" and RemoteIP = "10.55.21.50")
| LocalIPEncoded := urlEncode("LocalIP")
| RemoteIPEncoded := urlEncode("RemoteIP")
| not(ComputerName = KWT-APPSRV03 and UserName = itkwtsvc_aeldeep)
| format("https://falcon.us-2.crowdstrike.com/investigate/search?end=&query=LocalIP%25%3D%25s%25%7CRemoteIP%25%3D%25s%25%7CgroupBy(%5B@timestamp,ComputerName,ContextBaseFileName,LocalIP,RemoteIP%5D)&repo=investigate&searchViewInteractions=NoXSA&start=1d&timezone=Africa/Cairo", field=["RemoteIPEncoded","LocalIPEncoded"], as="RemoteHost")
| groupBy(
[TimeStamp, ComputerName, UserName, Investigate, RemoteHost, ParentBaseFileName, TargetFileName, CommandLine, LogonType, LocalIP, RemoteIP, ContextImageFileName, ContextProcessId, SHA256HashData],
limit=max
)
| sort(ComputerName, limit=20000)
```
---