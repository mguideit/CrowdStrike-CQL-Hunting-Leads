# Remote PowerShell wsmprovhost Spawns Process

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |

#### Hypothesis
If wsmprovhost.exe spawns uncommon or unauthorized child processes, it may signify malicious activity, such as an attacker using WinRM for lateral movement or remote code execution.

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
event_platform=Win #event_simpleName = ProcessRollup2
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| UserName != /aaboushalaby|mmegahed/i
| ParentBaseFileName = "wsmprovhost.exe"
| FileName != /^(dcdiag|w32tm|msiexec|ccmrepair|FixLogArchive|csc|iisreset|WsusUtil|auditpol|bcdedit)\.exe/i
| CommandLine != /itsvc_ansible \/add|gac\.bat|C:\\Scripts/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([TimeStamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine, SHA256HashData])
```
---