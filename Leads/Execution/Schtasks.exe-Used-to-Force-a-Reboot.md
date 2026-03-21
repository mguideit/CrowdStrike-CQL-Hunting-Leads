# Schtasks.exe Used to Force a Reboot

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task |

#### Hypothesis
Adversary may abuse the Windows Scheduled Tasks utility (schtasks.exe) to orchestrate a forced system reboot. By creating or modifying tasks with specific flags—particularly those intended to bypass user confirmation or force application closures—attackers can disrupt security monitoring, clear volatile memory (anti-forensics), or trigger the final execution stage of a ransomware payload. This technique is often employed to ensure malicious persistence mechanisms are fully initialized or to lock users out of their systems during an encryption routine.

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
event_platform=Win #event_simpleName=ProcessRollup2 
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargettProcessId","cid"], as="Tree")
| FileName="schtasks.exe" 
| CommandLine=/shutdown/i 
| CommandLine=/\/create/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, ParentProcessId, FileName, SHA256HashData, TargetProcessId, CommandLine])
```
---