# Notepad++ Updater Hijacking

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| **Execution** | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols |

#### Hypothesis
**Lead 1: Suspicious Notepad++ Updater Lineage**
Threat actors are leveraging the Notepad++ update mechanism (GUP.exe) to bypass security controls by spawning malicious installers or secondary stages (like update.exe) that deviate from the standard behavior of launching only the legitimate Notepad++ installer or explorer.exe. By monitoring for non-standard child processes of this trusted signed binary, we can identify instances where the update infrastructure has been hijacked to execute unauthorized code.

**Lead 2: Suspicious Notepad++ Updater DNS Request**
Adversary may hijack the communication flow of GUP.exe to redirect it toward malicious infrastructure. By modifying the updater's configuration or exploiting the distribution chain, an adversary may force the process to make DNS requests to non-whitelisted domains, enabling the download of secondary payloads from unauthorized C2 servers.


#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [Rapid7: TR-Chrysalis Technical Analysis](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)


#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

### Lead 1: Suspicious Notepad++ Updater Lineage
```cql
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = /GUP\.exe/i
| FileName != /^npp.+Installer.+exe$|explorer\.exe/i
| groupBy([ParentBaseFileName, FileName, CommandLine, SHA256HashData])
```

### Lead 2: Suspicious Notepad++ Updater DNS Request
```cql
// Be wary if GUP.exe makes DNS requests to domains other than the whitelisted below
#event_simpleName = DnsRequest
| ContextBaseFileName = /GUP\.exe/i
| !in(field="DomainName", values=["notepad-plus-plus.org", "github.com", "release-assets.githubusercontent.com", "ocsp.globalsign.com", "ocsp2.globalsign.com"])
| groupBy([ComputerName, ContextBaseFileName, DomainName, RemoteIP])
```
