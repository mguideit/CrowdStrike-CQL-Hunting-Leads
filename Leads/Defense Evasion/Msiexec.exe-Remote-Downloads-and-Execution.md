# Msiexec.exe Remote Downloads and Execution

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Msiexec |

#### Hypothesis
Adversary may abuse the Windows Installer service (msiexec.exe) to download and execute malicious MSI packages or DLLs directly from remote web servers. By passing HTTP/HTTPS URLs via the /i (install) or /x (uninstall) switches, attackers can bypass perimeter defenses and host-based firewalls that trust Microsoft-signed binaries to make outbound connections. This "Living off the Land" (LotL) technique allows for the stealthy delivery of second-stage payloads, lateral movement, or system exploitation while blending in with legitimate software update patterns.

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
event_platform = Win #event_simpleName = ProcessRollup2 FileName = msiexec.exe
| CommandLine = /http/i
| CommandLine = /[-/][ix]\s*(?<URL>(?:\"https?:[^\"]*?\")|(?:https?:[^ ]*?(\s|$)))/i
| URL != /cribl.io/i
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([GrandParentBaseFileName, ParentBaseFileName, URL, FileName, CommandLine], function=[count(ComputerName, distinct=true, as="UniqComputerCount"), collect([ComputerName, UserName, Tree])], limit=max)
| UniqComputerCount < 5
| table([ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, URL, FileName, CommandLine])
```
---