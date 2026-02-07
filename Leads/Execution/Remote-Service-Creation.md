# Remote Service Creation

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution |

#### Hypothesis
Adversaries are establishing persistence or executing commands on Windows endpoints by remotely creating services, potentially originating from compromised or unauthorized internal systems.

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
event_platform=Win #event_simpleName = NetworkConnectIP4 // Get the remote machine which created the service
| rename(field="LocalIP", as="RemoteCreatorIP") // Field renamed to be used as a common in the JOIN
| rename(field="ComputerName", as="RemoteCreatorComputer")
| rename(field="ContextBaseFileName", as="RemoteContextBaseFileName")
| formatTime(format="%Y-%m-%d %H:%M", as="RemoteTimeStamp")
| RemoteContextBaseFileName = * RemoteContextBaseFileName != ""

| join(query={event_platform=Win #event_simpleName=CreateService // Filter on service creation events
| RemoteIP = * RemoteIP != ""  // Make sure this field is not empty (this indicate a remote service creation)
| not in(field="RemoteIP", values=["10.4.3.21", "10.4.3.27", "10.4.3.25"]) // Exclude benign remote IPs
| ServiceImagePath != /Veeam|KAV Remote Installations|ProPatches\\Scheduler/i // Exclude benign Services
| ServiceDisplayName != /SanctuaryExec|Ivanti|MOMAgentInstaller|ccmsetup|BeyondTrust/i
| rename(field="RemoteIP", as="RemoteCreatorIP")
| case { // Map the service start type
    ServiceStart=0 | ServiceStartType := "SERVICE_BOOT_START";
    ServiceStart=1 | ServiceStartType := "SERVICE_SYSTEM_START";
    ServiceStart=2 | ServiceStartType := "SERVICE_AUTO_START";
    ServiceStart=3 | ServiceStartType := "SERVICE_DEMAND_START";
    ServiceStart=4 | ServiceStartType := "SERVICE_DISABLED";
* }
| formatTime(format="%Y-%m-%d %H:%M", as="TimeStamp")}, field=[RemoteCreatorIP], include=[ComputerName, TimeStamp, LocalIP, ServiceDisplayName, ServiceImagePath, ServiceObjectName, ServiceStart, ServiceStartType])
| test(LocalIP == RemoteIP) // Make sure that the RemoteIP field in NetworkConnectIP4 event = the LocalIP field in CreateService event
| test(TimeStamp == RemoteTimeStamp) // Make sure the service creation time and the remote connection match
| groupBy([TimeStamp, RemoteTimeStamp, ComputerName, LocalIP, RemoteCreatorComputer, RemoteCreatorIP, RemoteContextBaseFileName, RPort, ServiceDisplayName, ServiceImagePath, ServiceObjectName, ServiceStart, ServiceStartType])
```
---
