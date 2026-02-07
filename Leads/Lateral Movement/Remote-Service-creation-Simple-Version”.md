# Remote Service creation "Simple Version”

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services |

#### Hypothesis
Adversaries may create or manipulate Windows services remotely to establish persistence or execute malicious payloads. By identifying service creation events originating from unexpected remote IP addresses and excluding known legitimate services, we can uncover potential unauthorized activities.

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
event_platform=Win #event_simpleName=CreateService
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| RemoteIP = * RemoteIP != ""
| rename(field="RemoteIP", as="RemoteIP (Creator)")
| not in(field="RemoteIP (Creator)", values=["10.4.3.21", "10.4.3.27", "10.4.3.17", "10.4.3.13", "10.4.3.25", "10.55.18.100"])
| ServiceImagePath != /Veeam|KAV Remote Installations|ProPatches\\Scheduler|omtsreco\.exe/i
| ServiceDisplayName != /SanctuaryExec|Ivanti|MOMAgentInstaller|ccmsetup|BeyondTrust/i
| ComputerName != /EFG-APX-APP|EFG-FSET-FILESR/i
| case {
ServiceStart=0 | ServiceStartType := "SERVICE_BOOT_START";
ServiceStart=1 | ServiceStartType := "SERVICE_SYSTEM_START";
ServiceStart=2 | ServiceStartType := "SERVICE_AUTO_START";
ServiceStart=3 | ServiceStartType := "SERVICE_DEMAND_START";
ServiceStart=4 | ServiceStartType := "SERVICE_DISABLED";
* }
| formatTime("%Y/%m/%d %H:%M:%S", timezone="Africa/Cairo", as="TimeStamp")
| groupBy([TimeStamp, ComputerName, LocalIP, "RemoteIP (Creator)", ServiceDisplayName, ServiceImagePath, ServiceObjectName, ServiceStart, ServiceStartType])
```
---