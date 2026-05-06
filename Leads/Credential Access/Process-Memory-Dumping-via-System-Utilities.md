# Process Memory Dumping via System Utilities

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Credential Access | [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping |

#### Hypothesis
Adversaries may leverage legitimate system utilities such as Windows Task Manager, Process Explorer, or System Informer to generate memory dumps of running processes. This technique allows attackers to extract sensitive information (e.g., credentials, tokens, in-memory secrets) without relying on custom tooling, helping them blend in with legitimate administrative activity.


#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
*

#### Tags
`#Hunting` `#Falcon` `#CQL`

---

## CrowdStrike (CQL)

```cql
#event_simpleName = DmpFileWritten
| ContextBaseFileName = /Taskmgr|procexp|systeminformer/i
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","ContextProcessId","cid"], as="Tree") 
| groupBy([@timestamp, ComputerName, Tree, ContextBaseFileName, TargetFileName])
```
