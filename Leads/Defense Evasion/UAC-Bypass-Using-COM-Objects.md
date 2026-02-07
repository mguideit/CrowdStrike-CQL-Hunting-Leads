# UAC Bypass Using COM Objects

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control |

#### Hypothesis
An adversary may invoke the ICMLuaUtil auto‑elevated COM interface to bypass User Account Control (UAC), allowing processes to execute with elevated privileges without user interaction. This behavior can be abused to execute malicious code stealthily during post‑exploitation.

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
// ICMLuaUtil is a legitimate Windows auto elevated COM interface used to support UAC-related operations.
// Threat actors can abuse this interface to bypass UAC controls and execute code with elevated privileges without triggering a UAC prompt.
defineTable(query={
#event_simpleName = ProcessRollup2
//Focus specifically on dllhost.exe which acts as the 'Surrogate' for COM objects
| FileName = "dllhost.exe"
//Use Regex to look for CLSIDs associated with ICMLuaUtil and other auto-elevating interfaces
| CommandLine = /3E5FC7F9-9A51-4367-9063-A120244FBEC7|6EDD6D74-C007-4E75-B76A-E5740995E24C|D2E7041B-2927-42FB-8E9F-7CE93B6DC937/i
//Create a deep link to the Falcon Process Tree for faster investigation
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="DLLHostTree")
| rename(field="CommandLine", as="DLLHostCommandLine")
| formatTime(format="%Y-%m-%d %H:%M:%S", as="TimeStamp", timezone="Africa/Cairo")
}, include=[ComputerName, RpcClientProcessId, DLLHostCommandLine, TimeStamp, DLLHostTree], name="DLLHostT")

// Map the result with other processes to find the "Caller" process
| #event_simpleName = ProcessRollup2
//Match the 'RpcClientProcessId' from dllhost back to the 'TargetProcessId' of the process that called it
//This identifies the script or binary that triggered the UAC bypass
| match(table="DLLHostT", field=[ComputerName, TargetProcessId], column=[ComputerName, RpcClientProcessId])
| rename(field="CommandLine", as="CallerProcess")
| rename(field="ParentBaseFileName", as="ParentOfCallerProcess")
//Create a second link for the Caller process tree to see what happened BEFORE the bypass
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="CallerProcessTree")
| groupBy([ComputerName, UserName, DLLHostTree, CallerProcessTree, DLLHostCommandLine, CallerProcess, ParentOfCallerProcess])
```
---