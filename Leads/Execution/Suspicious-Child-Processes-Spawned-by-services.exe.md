# Suspicious Child Processes Spawned by services.exe

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution |

#### Hypothesis
This query aims to detect anomalies in service configurations and operations that deviate from the norm, focusing particularly on tools like cmd, PowerShell and PsExec which are often leveraged in sophisticated cyber attacks for executing scripts, managing services, and modifying system configurations.

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
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| (ParentBaseFileName = services.exe or GrandParentBaseFileName = services.exe)
| FileName = /^(cmd|powershell|pwsh|psexec|regsvr32|mshta|wscript|cscript|wmic|certutil|bitsadmin|schtasks|taskkill|explorer|lsass)\.exe/i
// Exclusions
| ComputerName != /EGY-APXINTEG01/i
| CommandLine != /NVIDIA|PSScheduledJob|AMS_DAILY_JOB|Palo Alto|C:\\\\Scripts|efg|Advent|APX|MachineAgent/i
| ParentBaseFileName != /CSFalconService|Veeam|VMS_Service|PRTG|HPAudioAnalytics|CcmExec|EFG|RtkAudUService64|igfxCUIService|SurSvc|LenovoVisionService|SupportAssistAgent|OfficeClickToRun|SolarWinds|sqlservr|vmtoolsd|PowerMgrInst|UserProfileManager|infoblox_rc_service|esrv_svc|ZSATrayManager|EVIndexAdminService|CrushFTPService|HealthService|IntelSoftwareAssetManagerService|MSPCManagerService|SYS\.exe|StorageServer\.exe|sfc\.exe|smsexec\.exe/i
| not (ComputerName = /STG-SP2013-APP|EGY-SP2013-APP/i and CommandLine = /powershell.exe\" -Version 3.0 -s -NoLogo -NoProfile/i)
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ParentProcessId","cid"], as="Tree")
// | groupBy([@timestamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine])
| groupBy([ParentBaseFileName], function=[count(ComputerName, distinct=true, as="UniqComputerCount"), collect([ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine, Tree], limit=200000)], limit=max)
| UniqComputerCount < 5
| table([ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine, Tree])
```
---