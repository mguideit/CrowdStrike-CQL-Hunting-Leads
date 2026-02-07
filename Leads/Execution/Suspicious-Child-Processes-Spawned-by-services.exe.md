# Suspicious Child Processes Spawned by services.exe

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution |

#### Hypothesis
Adversary may create or modify Windows services leveraging legitimate system utilities such as cmd.exe, PowerShell, or PsExec to achieve persistent code execution, escalate privileges, or execute commands under the context of the LocalSystem account, thereby masking malicious activity within standard service operations.

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
event_platform = "Win" #event_simpleName = ProcessRollup2
| (ParentBaseFileName = services.exe or GrandParentBaseFileName = services.exe)
| FileName = /^(cmd|powershell|pwsh|psexec|regsvr32|mshta|wscript|cscript|wmic|certutil|bitsadmin|schtasks|taskkill|explorer|lsass)\.exe/i
// Exclusions
| CommandLine != /NVIDIA|PSScheduledJob|AMS_DAILY_JOB|Palo Alto|MachineAgent/i
| ParentBaseFileName != /CSFalconService|Veeam|VMS_Service|PRTG|HPAudioAnalytics|CcmExec|EFG|RtkAudUService64|igfxCUIService|SurSvc|LenovoVisionService|SupportAssistAgent|OfficeClickToRun|SolarWinds|sqlservr|vmtoolsd|PowerMgrInst|UserProfileManager|infoblox_rc_service|esrv_svc|ZSATrayManager|EVIndexAdminService|CrushFTPService|HealthService|IntelSoftwareAssetManagerService|MSPCManagerService|SYS\.exe|StorageServer\.exe|sfc\.exe|smsexec\.exe/i
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ParentProcessId","cid"], as="Tree")
| groupBy([ParentBaseFileName], function=[count(ComputerName, distinct=true, as="UniqComputerCount"), collect([ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine, Tree], limit=200000)], limit=max)
| UniqComputerCount < 5
| table([ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine, Tree])
```
---
