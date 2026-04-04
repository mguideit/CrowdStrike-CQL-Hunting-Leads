# IFEO Injection

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | Image File Execution Options Injection |
| Privilege Escalation | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | Image File Execution Options Injection |

#### Hypothesis
An adversary is achieving stealthy persistence and privilege escalation by hijacking the Windows process loading mechanism. By registering a malicious binary as a Debugger or MonitorProcess for a common utility (like notepad.exe or taskmgr.exe), the attacker ensures their code executes automatically either when the target starts or silently exits, bypassing traditional "Run Key" or "Startup Folder" monitoring.

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
// Scope to Falcon's ASEP registry write events only
// (Auto-Start Extensibility Point — persistence-relevant writes)
#event_simpleName = AsepValueUpdate

// Match both IFEO (Method 1) and SilentProcessExit (Method 2) paths
| RegObjectName = /Image File Execution Options|SilentProcessExit/i

// The four values that make IFEO persistence work:
// Debugger       → Method 1 — implant path, fires on process LAUNCH
// GlobalFlag     → Method 2 — activates exit monitoring (must = 0x200)
// MonitorProcess → Method 2 — implant path, fires on process EXIT
// ReportingMode  → Method 2 — enables monitoring (must = 1)
| RegValueName = /Debugger|GlobalFlag|MonitorProcess|ReportingMode/i

// Drop incomplete telemetry records
| TargetFileName != ""

// Build a one-click Process Explorer link per result row
// — jumps directly to the full process tree for the writing process
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","ContextProcessId","cid"], as="Tree")

// One row per unique write — includes what was written, what wrote it, and its hash
| groupBy([@timestamp, ComputerName, Tree, RegObjectName, RegValueName, RegStringValue, TargetFileName, TargetSHA256HashData])
```
---