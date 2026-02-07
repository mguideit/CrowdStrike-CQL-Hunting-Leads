#  Suspicious Credential File Search

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials In Files |

#### Hypothesis
An adversary who has obtained interactive access to a Windows host may attempt to locate stored or hard-coded credentials by recursively enumerating files and directories using commands such as ls -R, Get-ChildItem -Recurse, or by using findstr /si pass.
If such commands appear in CommandHistory or CommandLine, especially when executed by non-administrative users or in unusual paths, it may indicate that an attacker is searching the filesystem for plaintext passwords or sensitive configuration files to escalate privileges or move laterally.

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
event_platform = "Win" #event_simpleName = /CommandHistory|ProcessRollup2/
| (CommandHistory = /(ls|Get-ChildItem)\s.*-(R|Recurse)\s.+pass/i or CommandLine = /findstr\s+\/si pass/i)
| CommandHistory := splitString(field=CommandHistory,by="¶")
| CommandHistory := concatArray("CommandHistory", separator="\n")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, CommandLine, CommandHistory])
```
---
