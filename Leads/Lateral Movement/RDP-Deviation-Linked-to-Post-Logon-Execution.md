# RDP Deviation Linked to Post Logon Execution

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol |

#### Hypothesis
An adversary who obtained valid credentials via phishing, credential dumping, or brute force is performing lateral movement through RDP into endpoints they have not previously accessed, and upon gaining interactive access, is executing commands or tools under the context of the compromised session to achieve post-exploitation objectives such as discovery, persistence, or data exfiltration.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References


#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
// Hunting New RDP Logons Not Seen in Last Month and Correlating with Process Activity
// Step 1: Look for RDP Logons Last Month Ending Yesterday
| defineTable(query={
  #event_simpleName = UserLogon
  | LogonType = 10
  | RemoteIP = *
}, include=[*], name="LoginLast30Days",  start=30d, end=1d)

// Step 2: Look for RDP Logons Since Yesterday
| defineTable(query={
  #event_simpleName = UserLogon
  | LogonType = 10
  | RemoteIP = *
  | !match(file="LoginLast30Days", field=[UserName])
  | formatTime(format="%Y-%m-%d %H:%M:%S", timezone="Africa/Cairo", as="LogonTimestamp")
}, include=[*], name="LoginLastDay", start=1d, end=now)

// Step 3: Correlate with Process Activity Using AuthenticationId
| #event_simpleName = ProcessRollup2
| match(table="LoginLastDay", field=[AuthenticationId], nrows=max)
| ParentBaseFileName = explorer.exe
// Exclusions
| FileName != /(OneDrive|OneDrive|RtkAudUService64|SecurityHealthSystray|ms-teams|runonce|RTNotify|msedge)\.exe/i
| groupBy([#repo.cid, event_platform, LogonTimestamp, ComputerName, UserPrincipal, UserName, LogonType, LogonDomain, LogonServer, RemoteIP, LocalIP, ParentBaseFileName, FileName, CommandLine], limit=max)
| sort(ComputerName, limit=max)


```
