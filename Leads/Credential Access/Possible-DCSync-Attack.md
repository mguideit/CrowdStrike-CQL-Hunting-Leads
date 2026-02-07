# Possible DCSync Attack

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Credential Access | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | DCSync |

#### Hypothesis
If a non-domain-controller host or non-standard user account (i.e., one without legitimate DS replication privileges) initiates MS-DRSR (e.g., DRSGetNCChanges) RPC requests to a Domain Controller to retrieve credential data, then it is likely indicative of a malicious DCSync attack.

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
#event_simpleName=DCSyncAttempted
// Exclude authorized usernames
| UserName != /\$|benign/i
// Exclude DCs and authorized IPs
| !in(field="RemoteIP", values=["10.0.0.5", "10.0.0.50"])
| formatTime(format="%m/%d/%Y %H:%M:%S %a", timezone="Africa/Cairo", as="TimeStamp")
| test(LocalIP != RemoteIP)
| table([TimeStamp, ComputerName, LocalIP, SubjectDomainNameEtw, RemoteIP, UserName])
```
---
