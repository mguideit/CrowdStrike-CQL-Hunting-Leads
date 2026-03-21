# Hidden Mshta Windows

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta |

#### Hypothesis
An adversary may be attempting to evade detection by using Mshta.exe and leveraging resizeTo with single-digit values to make the window extremely small, or moveTo with negative coordinates to move it off-screen. These actions could indicate an attempt to hide the execution of Mshta and its activities from security monitoring tools.

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
event_platform=Win #event_simpleName=ProcessRollup2
| FileName = "mshta.exe"
| CommandLine = /moveto|resizeto/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ContextProcessId","cid"], as="Tree")
| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine], limit=max)
| sort(ComputerName, limit=20000)
```
---