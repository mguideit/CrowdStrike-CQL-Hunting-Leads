# Suspicious Process Tree

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |

#### Hypothesis
Adversaries may abuse Office apps or tools like mmc.exe to launch suspicious child processes (e.g., cmd.exe, powershell.exe), indicating possible macros, LOL techniques, or persistence. Rare parent-child process trees may reveal malicious activity.

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
#event_simpleName=ProcessRollup2 ParentBaseFileName = /mmc\.exe|excel\.exe|word\.exe/i
| FileName = /^(Cmd\.exe|Powershell\.exe|Schtasks\.exe|Mshta\.exe|Bitsadmin\.exe|Certoc\.exe|Msbuild\.exe|Bash\.exe|Regsvr32\.exe|Wmic\.exe|Msconfig\.exe|At\.exe|Netsh\.exe)/i
| CommandLine != /PEManager|MDTUpdate|HP LaserJet|egy-printsrv/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo") 
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([ComputerName, TimeStamp, UserName, Tree, ParentBaseFileName, FileName, CommandLine], function=[count(ComputerName, distinct=true, as="UniqComputerCount")], limit=max)
| UniqComputerCount < 10
| sort([ComputerName, TimeStamp], limit=20000)
```
---
