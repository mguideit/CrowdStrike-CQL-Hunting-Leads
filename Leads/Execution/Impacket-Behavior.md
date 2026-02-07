#  Impacket Behavior

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

#### Hypothesis
This query detects potential Impacket activity, specifically focusing on command output redirection to administrative shares (e.g., 1> or 2>).  By analyzing command history and command-line arguments, it identifies patterns indicative of lateral movement or unauthorized activity involving administrative shares.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* 

#### Tags
`#Detection` `#Impacket`

---

## CrowdStrike (CQL)

```cql
event_platform=Win (#event_simpleName = ProcessRollup2 or #event_simpleName=CommandHistory)
| ParentBaseFileName != /HRA|run\.exe|php\.exe|java\.exe|perl\.exe/i
| (CommandLine = /.+1\>.+2\>/i or CommandHistory = /.+1\>.+2\>/i)
| CommandLine != /xcopy \/iesryhd|E\:|1\> config\\|\/c java -jar|u000/i
| CommandHistory != /u000/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| groupBy([TimeStamp, ComputerName, UserName, GranParentBaseFileName, ParentBaseFileName, FileName, CommandLine, CommandHistory], limit=max)
| sort(ComputerName, limit=20000)
```
---
