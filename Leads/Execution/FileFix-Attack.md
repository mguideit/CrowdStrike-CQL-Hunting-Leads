# FileFix Attack

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell |
| Initial Access | [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing |

#### Hypothesis
Adversaries are attempting to execute commands or living-off-the-land binaries (LOLBINs) through web browser-initiated processes, indicative of the "FileFix" social engineering technique, where they trick the user to click CTRL+L then pasted the malicious command and press Enter, thereby bypassing typical execution controls and establishing a foothold or performing further malicious actions.


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
#event_simpleName = ProcessRollup2
| in(field="FileName", values=["powershell.exe","certutil.exe","bitsadmin.exe","mshta.exe","wmic.exe","regsvr32.exe","cmd.exe","cscript.exe","wscript.exe","sc.exe","net.exe","ftp.exe","tftp.exe","curl.exe","wget.exe","ssh.exe","telnet.exe","sftp.exe"])
| CommandLine != /Adobe|extension|Explorer\\FileExts\\\.htm|sn-v2/i
| in(field="ParentBaseFileName", values=["chrome.exe", "brave.exe", "msedge.exe", "firefox.exe"])
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine])
```
---
