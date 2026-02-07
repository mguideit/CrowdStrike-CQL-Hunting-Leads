# MITRE ATT&CK® Coverage Matrix

This matrix provides a centralized view of all hunting leads available in this repository. Use the links in the **Lead Name** column to jump directly to the technical documentation and CQL logic.

---

## 📊 Coverage Summary
| Tactic | Count | | Tactic | Count |
| :--- | :---: | --- | :--- | :---: |
| 🔍 Reconnaissance | `0` | | 🔑 Credential Access | `0` |
| 🏗️ Resource Dev | `0` | | 📡 Discovery | `0` |
| 🎟️ Initial Access | `0` | | 🏃 Lateral Movement | `0` |
| 🚀 **Execution** | **`1`** | | 📦 Collection | `0` |
| ⚓ Persistence | `0` | | 🚩 **Command & Control** | **`1`** |
| 📈 Privilege Esc | `0` | | 📤 Exfiltration | `0` |
| 🛡️ **Defense Evasion** | **`1`** | | 💥 Impact | `0` |

---

## 🔍 Reconnaissance
*No entries yet.*

---

## 🏗️ Resource Development
*No entries yet.*

---

## 🎟️ Initial Access
*No entries yet.*

---

## 🚀 Execution
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | [Notepad++ Hijacking](Leads/Execution/Notepad++%20Hijacking.md) |

---

## ⚓ Persistence
*No entries yet.*

---

## 📈 Privilege Escalation
*No entries yet.*

---

## 🛡️ Defense Evasion
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | [EDR Startup Hinder](Leads/Defense%20Evasion/EDR-Startup-Hinder.md) |

---

## 🔑 Credential Access
*No entries yet.*

---

## 📡 Discovery
*No entries yet.*

---

## 🏃 Lateral Movement
*No entries yet.*

---

## 📦 Collection
*No entries yet.*

---

## 📡 Command and Control
| Technique ID | Title | Query / Lead |
| :--- | :--- | :--- |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | [Notepad++ Hijacking](Leads/Execution/Notepad++%20Hijacking.md) |

---

## 📤 Exfiltration
*No entries yet.*

---

## 💥 Impact
*No entries yet.*


---

## 🛠️ How to use this Matrix
1. **Identify the Tactic**: Locate the phase of the attack you are interested in (e.g., Execution).
2. **Review the Technique**: Check if the specific MITRE Technique ID matches your current threat intel.
3. **Navigate**: Click the **Lead Name** to open the full hunting report, which includes the hypothesis and the CrowdStrike CQL logic.

---

**Author:** [Muhammad Hassoub](https://www.linkedin.com/in/m-hassoub/)
