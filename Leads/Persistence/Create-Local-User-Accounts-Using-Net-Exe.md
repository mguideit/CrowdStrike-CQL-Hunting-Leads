# Create Local User Accounts Using Net Exe

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account |

#### Hypothesis
The following analytic detects the creation of local administrator accounts using the net.exe command. This query to search for processes with the name net.exe or net1.exe that include the "/add" parameter in their process name. The creation of unauthorized local user accounts might indicate that an attacker has successfully created a new user account and is trying to gain persistent access to a system or escalate their privileges for data theft, or other malicious activities. You must consider the context of the activity and other indicators of compromise before taking any action. For next steps, review the details of the identified process, including the user, parent process, and parent process name. Examine any relevant on-disk artifacts and look for concurrent processes to determine the source of the attack.

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
| #repo.cid = 77bb5e6ffad446f491aad89de6fa8d38
| CommandLine = /\/add/i
| UserName != /\$/i
| time := formatTime("%Y/%m/%d %H:%M:%S", field=@timestamp, timezone="Egypt") | sort(timestamp, order=asc)
| groupBy([ComputerName, time, UserName, ParentBaseFileName, ParentProcessId, FileName, CommandLine])
```
---