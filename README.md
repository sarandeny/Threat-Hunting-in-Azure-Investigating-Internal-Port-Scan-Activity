# 🔍 Threat Hunt: Sudden Network Slowdowns — Internal Port Scan Investigation

> **Platform:** Microsoft Defender for Endpoint (MDE) + Azure CyberRange  
> **Analyst:** Saran  
> **Hunt Date:** March 27, 2026  
> **Severity:** Medium  
> **Status:** ✅ Contained — Device Isolated, Rebuild Recommended

---

## 📋 Table of Contents

- [Overview](#overview)
- [Scenario Background](#scenario-background)
- [Hunt Methodology](#hunt-methodology)
- [Key Findings](#key-findings)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response Actions Taken](#response-actions-taken)
- [Lessons Learned](#lessons-learned)
- [KQL Query Reference](#kql-query-reference)
- [Project Structure](#project-structure)
- [Tools & Technologies](#tools--technologies)

---

## Overview

This repository documents a **threat hunting exercise** conducted in a live Azure CyberRange environment using **Microsoft Defender for Endpoint (MDE)** and **Kusto Query Language (KQL)**. The hunt was initiated after the server team reported significant network performance degradation on older devices within the `10.0.0.0/16` network.

After ruling out external DDoS attacks, the investigation focused internally — ultimately uncovering an **active port scan** being conducted from `saranpc2` (`10.3.0.42`) via a PowerShell script (`portscan.ps1`) executed under the `labuser` account.

**Bottom Line Up Front (BLUF):** A port scanning script was launched from an internal host, causing network slowdowns through mass failed connection attempts. The device was isolated, a malware scan returned clean, and a full rebuild was recommended as a precautionary measure.

---

## Scenario Background

The server team reported **significant network performance degradation** on older devices connected to the `10.0.0.0/16` network. Initial triage ruled out external DDoS activity. The security team turned its focus internally, noting:

- All internal traffic was **permitted by default** — no east-west segmentation
- **PowerShell was unrestricted** across the environment
- The degradation pointed to either **large file transfers** or **internal port scanning**

**Hypothesis:**
> *"An internal host may be conducting port scanning or generating excessive network traffic through unrestricted PowerShell or other tooling, causing performance degradation on legacy devices."*

---

## Hunt Methodology

This investigation follows the structured **Threat Hunting Lifecycle**:

```
1. Preparation  →  2. Data Collection  →  3. Data Analysis
       ↑                                         ↓
7. Improvement  ←  6. Documentation  ←  4. Investigation
                                         ↓
                                    5. Response
```

For the full step-by-step walkthrough, see [`reports/hunt-report.md`](reports/hunt-report.md).

---

## Key Findings

| Finding | Detail |
|---|---|
| **Affected Device** | `saranpc2` — IP `10.3.0.42` |
| **Root Cause** | PowerShell port scan script (`portscan.ps1`) |
| **Executing Account** | `labuser` |
| **Script Launch Time** | `2026-03-27T10:47:50.0391688Z` |
| **Detection Method** | Sequential failed connections revealing scanning pattern |
| **Malware Detected?** | ❌ No — scan returned clean |
| **Device Status** | 🔒 Isolated — Rebuild recommended |

---

## MITRE ATT&CK Mapping

| TTP ID | Technique | Tactic | Observed |
|---|---|---|---|
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Discovery | Port scan via `portscan.ps1` |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | Script executed via `powershell.exe -ExecutionPolicy Bypass` |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Persistence / Defense Evasion | Script launched under `labuser` account |

See [`mitre/ttp-mapping.md`](mitre/ttp-mapping.md) for detailed analysis.

---

## Response Actions Taken

1. **Device Isolated** — `saranpc2` removed from network via MDE to stop ongoing scanning activity.
2. **Malicious Process Terminated** — `portscan.ps1` PowerShell process stopped.
3. **Malware Scan Completed** — Full system scan returned no detections.
4. **Logs Preserved** — `DeviceNetworkEvents` and `DeviceProcessEvents` retained for analysis.
5. **Rebuild Recommended** — Ticket raised to reimage/rebuild `saranpc2` as a precautionary measure.

---

## Lessons Learned

- 🔴 **Unrestricted PowerShell** in an environment is a significant risk — execution policy bypass was trivially used.
- 🔴 **Flat internal network** (all traffic allowed by default) enabled scanning to reach all hosts unimpeded.
- 🟡 **Sequential port patterns** in `DeviceNetworkEvents` are a reliable indicator of scanning — easy to alert on.
- 🟢 **Pivoting across tables** (`NetworkEvents` → `ProcessEvents`) is a powerful technique to trace root cause quickly.
- 🟢 **Device isolation via MDE** allowed rapid containment without physical access.

---

## KQL Query Reference

All KQL queries used in this hunt are documented in [`queries/kql-queries.md`](queries/kql-queries.md), including:

- Identifying hosts with excessive failed connections
- Isolating a specific IP's connection failures in chronological order
- Pivoting to process events to find the responsible script
- Detection engineering rules for future port scan alerts

---

## Project Structure

```
📁 soc-network-slowdown/
├── 📄 README.md                        ← You are here
├── 📁 reports/
│   └── 📄 hunt-report.md               ← Full investigation report
├── 📁 queries/
│   └── 📄 kql-queries.md               ← All KQL queries with explanations
├── 📁 mitre/
│   └── 📄 ttp-mapping.md               ← MITRE ATT&CK framework mapping
├── 📁 playbooks/
│   └── 📄 internal-portscan-response.md ← IR playbook for this scenario
└── 📁 assets/
    └── 📄 timeline.md                  ← Attack timeline reconstruction
```

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| **Microsoft Defender for Endpoint (MDE)** | Endpoint telemetry and containment |
| **Kusto Query Language (KQL)** | Log analysis and threat hunting queries |
| **Microsoft Sentinel / MDE Portal** | SIEM/XDR query interface |
| **MITRE ATT&CK Navigator** | TTP mapping and adversary behavior analysis |
| **Azure CyberRange** | Lab environment for hands-on practice |
| **PowerShell** | Attack simulation tool (portscan.ps1) |

---

## About This Project

This project was completed as part of a **CyberRange threat hunting exercise** simulating a real-world SOC analyst investigation. It demonstrates:

- Internal threat hypothesis development
- Multi-table KQL pivoting (Network → Process → File events)
- MITRE ATT&CK framework application
- Device isolation and incident containment
- Professional SOC documentation and reporting

> 💡 *If you're a recruiter or fellow analyst reviewing this — all queries were executed against live MDE telemetry in a sandboxed Azure environment. Findings are real.*

---

*Last updated: March 27, 2026 | Author: Saran*
