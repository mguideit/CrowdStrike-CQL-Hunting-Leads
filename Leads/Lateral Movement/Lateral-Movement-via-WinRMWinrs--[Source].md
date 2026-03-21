# Lateral Movement via WinRM/Winrs -[Source]

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management |

#### Hypothesis
Adversary may leverage the Windows Remote Shell (winrs.exe) to execute arbitrary commands or move laterally to remote systems within the network. By utilizing the WinRM (Windows Remote Management) protocol, attackers can spawn processes on target endpoints while operating from a trusted, Microsoft-signed binary. This technique is highly effective for stealthy remote code execution, as it often bypasses traditional host-based restrictions and utilizes common administrative ports to blend in with legitimate remote management traffic.

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
event_platform=Win #event_simpleName = ProcessRollup2
| FileName = winrs.exe| CommandLine = /-r|\/r/i
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, LocalIP, Tree, ContextBaseFileName, FileName, CommandLine], limit=max)| sort([ComputerName, TimeStamp], limit=20000)
```
---