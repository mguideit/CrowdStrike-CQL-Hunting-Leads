#  Impacket-wmiexec-Main

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation |

#### Hypothesis
This query is to detect suspicious remote WMI execution on the destination host

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
#event_simpleName=WmiCreateProcess RemoteIP=*  event_platform=Win| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38| ComputerName != /U-YMKHALIL-NB|Valu/i| CommandLine != /nessus|fstmp|fsprocsvc/i| base64Decode("CommandLine", charset="UTF-16LE", as="DecodedString")| DecodedString != /nessus/i| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")| groupBy([TimeStamp, ComputerName, Tree, ParentBaseFileName, ImageFileName, TargetProcessId, CommandLine, RemoteIP], limit=max)| sort(ComputerName, limit=20000)
```
---