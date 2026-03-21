# Lateral Movement via WinRM/Winrs [Destination]

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management |

#### Hypothesis

Adversary may leverage the Windows Remote Shell (WinRM) service to execute commands on a target host after gaining a foothold in the network. While the previous hunt focused on the source of the connection (winrs.exe), this hypothesis focuses on the target (destination) host. When a remote command is received, the system spawns winrshost.exe to manage the session. If this process subsequently spawns unexpected children—such as shell interpreters, discovery tools, or credential dumpers—it strongly indicates that an attacker is using WinRM for lateral movement or remote code execution.


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
#event_simpleName = ProcessRollup2
| ParentBaseFileName = winrshost.exe
| FileName != conhost.exe
| rename(field="ParentProcessId", as="ContextProcessId")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| join(query={#event_simpleName = UserLogon | RemoteIP != "" RemoteIP = * }, field=[ContextProcessId], include=[UserName, RemoteIP])
| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine, LocalIP, RemoteIP])
```
---