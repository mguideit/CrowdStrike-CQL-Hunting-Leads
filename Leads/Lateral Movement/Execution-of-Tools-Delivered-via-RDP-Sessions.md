# Execution of Tools Delivered via RDP Sessions

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Lateral Movement | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol |
| Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer |

#### Hypothesis
An adversary may stage tools or payloads on a compromised host by transferring them through Remote Desktop Protocol sessions and subsequently execute the transferred tools locally to perform post-compromise activities or retrieve execution output from the victim system.

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
// STEP 1: Identify RDP Sessions
// Stores these sessions in a temporary table 'UserLogonT' keyed by AuthenticationId.
defineTable(query={
  #event_simpleName = UserLogon
  | LogonType = 10
  | case { UserIsAdmin = 1 | UserIsAdmin := "True"; *}
  | case { LogonType = 10 | LogonType := "RDP"; *}
}, include=[ComputerName, UserName, LogonDomain, UserIsAdmin, RemoteIP, LogonType, AuthenticationId], name="UserLogonT")

// STEP 2: Detect File Transfers via RDP
// Monitors for archive or PE files written by 'explorer.exe' (typical of RDP drag-and-drop/copy-paste).
// Joins this data with 'UserLogonT' using AuthenticationId to ensure the file was written during an RDP session.
| defineTable(query={
  in(field=#event_simpleName, values=[PeFileWritten])
  | ContextBaseFileName = "explorer.exe"
  | rename(field="TargetFileName", as="FileWrittenOverRDP")
  // Exclusions
  | FileWrittenOverRDP != /BENIGN/i
  | match(table="UserLogonT", field=[ComputerName, AuthenticationId], column=[ComputerName, AuthenticationId], nrows=max)
}, include=[#event_simpleName, ComputerName, UserName, LogonDomain, UserIsAdmin, RemoteIP, LogonType, ContextBaseFileName, FileWrittenOverRDP, FileName, SHA256HashData, AuthenticationId], name="WrittenT")

// STEP 3: Track Execution of Transferred Files
// Searches for Process Creation events (ProcessRollup2) where the SHA256 matches the file from Step 2.
| #event_simpleName = ProcessRollup2
| match(table="WrittenT", field=[ComputerName, AuthenticationId, SHA256HashData], column=[ComputerName, AuthenticationId, SHA256HashData], nrows=max)
| rename(field="CommandLine", as="RDPTransferredFileExecutionCommandLine")
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree") 
| groupBy([ComputerName, UserName, Tree, LogonDomain, UserIsAdmin, RemoteIP, LogonType, FileWrittenOverRDP, RDPTransferredFileExecutionCommandLine, SHA256HashData])
| drop([_count])


```
