# Possible FileFix Attack

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Phishing |
| Initial Access | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Phishing |

#### Hypothesis
Adversaries are attempting to execute commands or living-off-the-land binaries (LOLBINs) through web browser-initiated processes, indicative of the "FileFix" social engineering technique, where they trick the user to click CTRL+L then pasted the malicious command and press Enter, thereby bypassing typical execution controls and establishing a foothold or performing further malicious actions.


===========
Query Logic
===========

This query posits that a suspicious pattern of execution—where a trusted web browser directly launches system utilities or scripting interpreters—is occurring. This behavior is unusual for legitimate user activity and aligns with the FileFix attack's mechanism of tricking users into pasting commands into File Explorer's address bar, which then causes the browser (as the parent process due to the file dialog context) to spawn the malicious command.

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
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| in(field="FileName", values=["powershell.exe","certutil.exe","bitsadmin.exe","mshta.exe","wmic.exe","regsvr32.exe","cmd.exe","cscript.exe","wscript.exe","sc.exe","net.exe","ftp.exe","tftp.exe","curl.exe","wget.exe","ssh.exe","telnet.exe","sftp.exe"])
| CommandLine != /Nexthink|Adobe|extension|Explorer\\FileExts\\\.htm|sn-v2/i
| in(field="ParentBaseFileName", values=["chrome.exe", "brave.exe", "msedge.exe", "firefox.exe"])
// Exclusions
| not(ComputerName = WALID and CommandLine = /VNC/i)
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine])
```
---