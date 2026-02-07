# 🦅 CrowdStrike-CQL-Hunting-Leads

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: CrowdStrike Falcon](https://img.shields.io/badge/Platform-CrowdStrike_Falcon-red)](https://www.crowdstrike.com/)

## 🎯 Project Overview
Curated **CrowdStrike Query Language (CQL)** leads for proactive threat hunting, mapped to the **MITRE ATT&CK®** framework. This repository is built for security analysts and threat hunters using **CrowdStrike Falcon** and LogScale.

---

## 📊 Coverage Matrix
For a full list of available hunting leads and their associated TTPs, please refer to our:
* 👉 [**MITRE ATT&CK Matrix**](ATTACK_MATRIX.md)

---

## 📂 Repository Structure
The repository is organized to allow for quick navigation either via the filesystem or via tactic mapping.

* **`Leads/`**: The core directory where subfolders are mapped directly to **MITRE ATT&CK Tactics** (e.g., Execution, Defense Evasion). Each lead file contains a structured hypothesis and functional CQL logic.
* **`ATTACK_MATRIX.md`**: A centralized tracking table that maps every lead to its specific Technique ID and Tactic. Use this file as a high-level overview or as a shortcut menu to jump directly to specific hunting reports.

---

## 🛠️ Usage
1. **Locate a Lead**: Browse the `/Leads` directory by tactic, or use the [**ATTACK_MATRIX.md**](ATTACK_MATRIX.md) to find a specific MITRE technique.
2. **Copy Logic**: Copy the provided CQL logic from the lead's Markdown file.
3. **Execute**: Run the query within the **CrowdStrike Falcon** Advanced Search or LogScale console.
4. **Investigate**: Review the **Hypothesis** and **References** sections for context during your triage process.

---

**Author:** [Muhammad Hassoub](https://www.linkedin.com/in/m-hassoub/)
