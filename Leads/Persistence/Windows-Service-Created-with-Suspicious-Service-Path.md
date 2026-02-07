# Windows Service Created with Suspicious Service Path

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service |
| Privilege Escalation | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service |

#### Hypothesis
Adversaries may create or modify Windows services to achieve persistence, enable remote code execution, or facilitate lateral movement. Services that reference binaries stored in uncommon or non-standard folders (outside typical system paths like C:\Windows\System32) can indicate suspicious activity. Detection focuses on identifying newly created services whose executable paths deviate from standard conventions, which may suggest deployment of malicious binaries or unauthorized service manipulation.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [Splunk](https://research.splunk.com/endpoint/429141be-8311-11eb-adb6-acde48001122/)

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
| ServiceImagePath = *
| ServiceImagePath != /\\Windows|\\Program File|\\Programdata\\|\%systemroot\%|System32|SysWOW64|mysql|Packages\\Plugins|azagent|bin\\httpd|ROGRA\~|FixServices|DistributionManager|RuleEngineCOFServices|DSS\\|SoftwareAG|\\HKF|D:\\|E:\\|WinPcap|(sys)$|BirtReporter|kavremover/i
| ServiceDisplayName != /ALSysIO|KL Deployment|TDKLIMIT|SysmonDrv|nginx/i
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
