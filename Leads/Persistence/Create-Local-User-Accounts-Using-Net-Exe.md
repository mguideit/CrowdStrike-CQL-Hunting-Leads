# Create Local User Accounts Using Net Exe

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account |

#### Hypothesis
Adversaries may attempt to create local administrator accounts to maintain persistence or escalate privileges. This behavior can be detected by identifying net.exe or net1.exe processes that include the "/add" parameter, which indicates the creation of a new local user. While legitimate administrative activity may use these commands, unexpected or suspicious instances—especially when executed by non-standard users or from unusual parent processes—may indicate malicious activity. Investigation should include the initiating user, parent process, and on-disk artifacts, as well as any concurrent suspicious processes to determine if the account creation is part of a broader attack.

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
#event_simpleName = ProcessRollup2 FileName = /^(net\.exe|net1\.exe)$/i
| CommandLine = /\/add/i
| UserName != /\$/i
| time := formatTime("%Y/%m/%d %H:%M:%S", field=@timestamp, timezone="Egypt") | sort(timestamp, order=asc)
| groupBy([ComputerName, time, UserName, ParentBaseFileName, ParentProcessId, FileName, CommandLine])
```
---
