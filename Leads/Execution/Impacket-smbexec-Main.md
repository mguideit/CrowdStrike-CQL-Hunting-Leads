#  Impacket-smbexec-Main

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares |

#### Hypothesis
Hunting for impacket-smbexec:
- Script (bat) file written
- Same script deleted
- Both actions done from services.exe

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
| rename(field="TargetProcessId", as="WritingProcessId")
| rename(field="ParentBaseFileName", as="WritingProcessName")
| WritingProcessName = "services.exe"
| join(query={ #event_simpleName = FileDeleteInfo | rename(field="ContextProcessId", as="WritingProcessId") | FileDeleteTime := @timestamp
| join(
query={#event_simpleName = ScriptFileWrittenInfo | #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38 | ScriptContent = />/i | ScriptFileWriteTime := @timestamp},
field=[FileName],
include=[ScriptFileWriteTime, #event_simpleName, ScriptContent, TargetFileName, FileFormatString]
)
},

field=[WritingProcessId],
include = [ScriptFileWriteTime, FileDeleteTime, #event_simpleName, ScriptContent, TargetFileName, FileFormatString, FileName]
)
| CommandLine != /\\Palo/i
| diff := ScriptFileWriteTime - FileDeleteTime
| test(diff < duration("1m"))
| groupBy([@timestamp, ComputerName, UserName, WritingProcessName, TargetFileName, ScriptContent, FileName, CommandLine])
```
---