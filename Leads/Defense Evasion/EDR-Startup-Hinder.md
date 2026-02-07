# EDR Startup Hinder

#### MITRE ATT&CK Technique(s)
| Technique ID | Title |
| --- | --- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools |

#### Hypothesis
An adversary may attempt to impair endpoint security controls before initialization by creating or modifying an auto-start Windows service that is registered to a high-priority or uncommon Service Load Order Group. This service executes early in the boot sequence and abuses the Windows Bindlink API to redirect critical System32 DLLs to invalid or unsigned versions, causing EDR/AV user-mode services (PPL) to fail during startup.

If this technique is used, we expect to observe:
* Creation or modification of auto-start services tied to Service Load Order Groups.
* Use of non-standard or high-priority groups (e.g., TDI).
* Abnormal DLL redirection affecting core System32 libraries.
* Early boot failures or crashes of security agent processes.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [CrowdStrike Blog: Stopping the Hinder Boot-Time Evasion](https://www.crowdstrike.com/blog/stopping-the-hinder-boot-time-evasion/)
* [Microsoft: Service Load Order Groups Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/specifying-service-load-order)

#### Tags
`#Hunting` `#DefenseEvasion` `#EDR-Evasion` `#BootSighting` `#ServiceAbuse` `#Falcon` `#LogScale`

---

## CrowdStrike (CQL)

```cql
/* Name: EDR Startup Hinder via Service Group Abuse
   Description: Identifies creation of auto-start services in high-priority Load Order Groups 
                correlated with the creating process.
*/

defineTable(query={
#event_simpleName = CreateService
| ServiceStart = 2
| ServiceGroup != "" ServiceGroup = *
| RpcClientProcessId != "" RpcClientProcessId = *
| UserName != /\$|SYSTEM/i
| formatTime(format="%Y-%m-%d %H:%M:%S", as="TimeStamp", timezone="Africa/Cairo")
// Baselining
| ServiceImagePath != /\.sys$|^"C:\\Program Files\\HP/i
}, include=[ComputerName, UserName, RpcClientProcessId, ServiceGroup, ServiceDisplayName, ServiceStart, ServiceImagePath, TimeStamp], name="CreateServiceT")

| #event_simpleName = ProcessRollup2
| match(table="CreateServiceT", field=[ComputerName, TargetProcessId], column=[ComputerName, RpcClientProcessId])
| groupBy([TimeStamp, ComputerName, UserName, ServiceGroup, ServiceDisplayName, ServiceStart, ServiceImagePath, ParentBaseFileName, FileName, CommandLine])
