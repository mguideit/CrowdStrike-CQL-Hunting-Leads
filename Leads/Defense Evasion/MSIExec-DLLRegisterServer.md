# MSIExec DLLRegisterServer

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Msiexec |

#### Hypothesis
Adversary may leverage the Windows Installer process (msiexec.exe) with the /y (or /z) switch to reflectively load and register a DLL via its DllRegisterServer entry point. This technique is often used to bypass application whitelisting or security monitoring that focuses on standard execution methods, as it allows the registration of malicious modules under a legitimate, Microsoft-signed binary to achieve initial code execution or maintain long-term persistence.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* https://research.splunk.com/endpoint/fdb59aef-d88f-4909-8369-ec2afbd2c398/
* https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md

#### Tags
`#Hunting` `#LOLBins`

---

## CrowdStrike (CQL)

```cql
#event_simpleName = ProcessRollup2 FileName = msiexec.exe
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| ParentBaseFileName != /Nexthink|msiexec\.exe/i
| CommandLine = /-y |-z |\/y | \/z/i
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","ContextProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine])
```
---