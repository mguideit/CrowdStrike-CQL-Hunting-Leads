# MITRE ATT&CK® Coverage Matrix

This matrix provides a centralized view of all hunting leads. It is automatically updated via our Python automation suite.

## 📊 Coverage Summary
| Tactic | Count | | Tactic | Count |
| :--- | :---: | --- | :--- | :---: |
| 🎟️ Initial Access | **`2`** | 📡 Discovery | `0` |
| 🚀 Execution | **`9`** | 🏃 Lateral Movement | **`5`** |
| ⚓ Persistence | **`8`** | 📦 Collection | **`1`** |
| 📈 Privilege Escalation | **`2`** | 🚩 Command and Control | **`4`** |
| 🛡️ Defense Evasion | **`11`** | 📤 Exfiltration | `0` |
| 🔑 Credential Access | **`2`** | 💥 Impact | `0` |

---

## 🎟️ Initial Access
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1189](https://attack.mitre.org/techniques/T1189/) | Drive-by Compromise | [ClickFix Attack](Leads/Initial%20Access/ClickFix-Attack.md) |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | [FileFix Attack](Leads/Execution/FileFix-Attack.md) |

## 🚀 Execution
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | [Impacket-smbexec-Main](Leads/Execution/Impacket-smbexec-Main.md) |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | [Impacket-wmiexec-Main](Leads/Execution/Impacket-wmiexec-Main.md) |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | [Impacket Behavior](Leads/Execution/Impacket-Behavior.md) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | [Obfuscated PowerShell Activity with High Entropy](Leads/Defense%20Evasion/Obfuscated-PowerShell-Activity-with-High-Entropy.md) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | [FileFix Attack](Leads/Execution/FileFix-Attack.md) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | [PowerShell via WinRM Connection Received](Leads/Lateral%20Movement/PowerShell-via-WinRM-Connection-Received.md) |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | [NTLM Hash Leak - CVE-2025-24054](Leads/Execution/NTLM-Hash-Leak---CVE-2025-24054.md) |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | [Remote Service Creation](Leads/Execution/Remote-Service-Creation.md) |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | [Suspicious Child Processes Spawned by services.exe](Leads/Execution/Suspicious-Child-Processes-Spawned-by-services.exe.md) |

## ⚓ Persistence
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | Additional Local or Domain Groups | [AD Administrative Group Membership Changes](Leads/Persistence/AD-Administrative-Group-Membership-Changes.md) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | [Hidden User via Dollar Sign](Leads/Defense%20Evasion/Hidden-User-via-Dollar-Sign.md) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | [Create Local User Accounts Using Net Exe](Leads/Persistence/Create-Local-User-Accounts-Using-Net-Exe.md) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | [User Account Created and Added to a Group](Leads/Persistence/User-Account-Created-and-Added-to-a-Group.md) |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | [Possible ToolShell SharePoint Exploit - ASPX File Created](Leads/Persistence/Possible-ToolShell-SharePoint-Exploit---ASPX-File-Created.md) |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | [Possible ToolShell SharePoint Exploit - Process Lineage](Leads/Persistence/Possible-ToolShell-SharePoint-Exploit---Process-Lineage.md) |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | [Possible ToolShell SharePoint Exploit](Leads/Persistence/Possible-ToolShell-SharePoint-Exploit.md) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | [Windows Service Created with Suspicious Service Path](Leads/Persistence/Windows-Service-Created-with-Suspicious-Service-Path.md) |

## 📈 Privilege Escalation
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | [Windows Service Created with Suspicious Service Path](Leads/Persistence/Windows-Service-Created-with-Suspicious-Service-Path.md) |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | [UAC Bypass Using COM Objects](Leads/Defense%20Evasion/UAC-Bypass-Using-COM-Objects.md) |

## 🛡️ Defense Evasion
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | [Obfuscated PowerShell Activity with High Entropy](Leads/Defense%20Evasion/Obfuscated-PowerShell-Activity-with-High-Entropy.md) |
| [T1202](https://attack.mitre.org/techniques/T1202/) | Indirect Command Execution | [ClickFix Attack](Leads/Initial%20Access/ClickFix-Attack.md) |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | [Suspicious Process Tree](Leads/Defense%20Evasion/Suspicious-Process-Tree.md) |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | [Suspicious Notepad++ Updater Lineage](Leads/Defense%20Evasion/Suspicious-Notepad++-Updater-Lineage.md) |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | [Remote PowerShell wsmprovhost Spawns Process](Leads/Defense%20Evasion/Remote-PowerShell-wsmprovhost-Spawns-Process.md) |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | [Rare mshta.exe Execution](Leads/Defense%20Evasion/Rare-mshta.exe-Execution.md) |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | [Mshta Initiating Connections](Leads/Defense%20Evasion/Mshta-Initiating-Connections.md) |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | [Regsvr32 scrobj.dll Scriptlet Remote Execution](Leads/Defense%20Evasion/Regsvr32-scrobjdll-Scriptlet.md) |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | [Suspicious Rundll32.exe Execution via Scheduled Tasks](Leads/Defense%20Evasion/Suspicious-Rundll32.exe-Execution-via-Scheduled-Tasks.md) |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | [UAC Bypass Using COM Objects](Leads/Defense%20Evasion/UAC-Bypass-Using-COM-Objects.md) |
| [T1564.002](https://attack.mitre.org/techniques/T1564/002/) | Hidden Users | [Hidden User via SpecialAccounts](Leads/Defense%20Evasion/Hidden-User-via-SpecialAccounts.md) |

## 🔑 Credential Access
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | DCSync | [Possible DCSync Attack](Leads/Credential%20Access/Possible-DCSync-Attack.md) |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials In Files | [Suspicious Credential File Search](Leads/Credential%20Access/Suspicious-Credential-File-Search.md) |

## 📡 Discovery
*No entries yet.*

## 🏃 Lateral Movement
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | [PsExec Style](Leads/Lateral%20Movement/PsExec-Style.md) |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | [Remote Service creation "Simple Version”](Leads/Lateral%20Movement/Remote-Service-creation-Simple-Version”.md) |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | [Execution of Tools Delivered via RDP Sessions](Leads/Lateral%20Movement/Execution-of-Tools-Delivered-via-RDP-Sessions.md) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | [PsExec Style](Leads/Lateral%20Movement/PsExec-Style.md) |
| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management | [PowerShell via WinRM Connection Received](Leads/Lateral%20Movement/PowerShell-via-WinRM-Connection-Received.md) |

## 📦 Collection
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | [Decoy File Access](Leads/Collection/Decoy-File-Access.md) |

## 🚩 Command and Control
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | [Suspicious Notepad++ Updater DNS Request](Leads/Command%20and%20Control/Suspicious-Notepad++-Updater-DNS-Request.md) |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | [LOLBins DNS](Leads/Command%20and%20Control/LOLBins-DNS.md) |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | [ClickFix Attack](Leads/Initial%20Access/ClickFix-Attack.md) |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | [Execution of Tools Delivered via RDP Sessions](Leads/Lateral%20Movement/Execution-of-Tools-Delivered-via-RDP-Sessions.md) |

## 📤 Exfiltration
*No entries yet.*

## 💥 Impact
*No entries yet.*

---
**Author:** [Muhammad Hassoub](https://www.linkedin.com/in/m-hassoub/)
