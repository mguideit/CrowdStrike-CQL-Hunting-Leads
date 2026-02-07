# Windows Service Created with Suspicious Service Path

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service |
| Privilege Escalation | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service |

#### Hypothesis
This analytic detects creation of Windows Services with binaries in uncommon folders, which may indicate lateral movement, remote code execution, or persistence.

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
#event_simpleName = /ProcessRollup/i
| rename(field="TargetProcessId", as="RpcClientProcessId")
| rename(field="FileName", as="RespFileName")
| rename(field="CommandLine", as="RespCommandLine")
| rename(field="ParentBaseFileName", as="RespParentBaseFileName")
| rename(field="SHA256HashData", as="RespSHA256HashData")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","RpcClientProcessId","cid"], as="Tree")
| join(
query={
#event_simpleName=CreateService
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| ServiceImagePath = *
| ServiceImagePath != /\\Windows|\\Program File|\\Programdata\\|\%systemroot\%|System32|Development_Applications|SysWOW64|mysql|Packages\\Plugins|azagent|bin\\httpd|ROGRA\~|Marketbeat|FixServices|DistributionManager|RuleEngineCOFServices|DSS\\|SoftwareAG|EFG|Brokerage|\\HKF|D:\\|E:\\|WinPcap|(sys)$|BirtReporter|kavremover/i
| ServiceDisplayName != /EFG|ALSysIO|KL Deployment|TDKLIMIT|SysmonDrv|nginx/i
| ComputerName != /EGY-OPSWAT01/i
},
field=[ComputerName, RpcClientProcessId],
include=[ServiceDisplayName, ServiceImagePath, ServiceStart, RpcClientProcessId]
)
| RespFileName != /java/i
| RespParentBaseFileName != /java/i
| RespCommandLine != /\\oracle\\/i
| groupBy([ComputerName, UserName, Tree, RespParentBaseFileName, RespFileName, RespCommandLine, ServiceDisplayName, ServiceImagePath, ServiceStart, RpcClientProcessId, RespSHA256HashData], function=count(field=ComputerName, as=ComputerCount))
```
---