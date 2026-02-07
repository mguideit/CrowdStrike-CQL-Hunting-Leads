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
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| ComputerName != /WEBSITE/i
| UserName != /\$|spointadmins|itsvc_rpad/i
| not in(field="RemoteIP", values=["10.0.54.82", "192.168.150.129", "10.255.102.50", "10.0.55.48"])
| not (RemoteIP = "10.255.102.40" and UserName = "itsvc_rpad")
| formatTime(format="%m/%d/%Y %H:%M:%S %a", timezone="Africa/Cairo", as="TimeStamp")
| test(LocalIP != RemoteIP)
| table([TimeStamp, ComputerName, LocalIP, SubjectDomainNameEtw, RemoteIP, UserName])
```
---