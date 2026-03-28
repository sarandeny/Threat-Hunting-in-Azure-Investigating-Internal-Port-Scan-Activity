# 🗺️ MITRE ATT&CK Framework Mapping

> **Hunt:** Sudden Network Slowdowns — Internal Port Scan Investigation  
> **Date:** March 27, 2026  
> **Reference:** [MITRE ATT&CK v14](https://attack.mitre.org/)

---

## Overview

This document maps observed adversary behaviours from this threat hunt to the [MITRE ATT&CK Enterprise Framework](https://attack.mitre.org/). Three TTPs were confirmed across the **Execution**, **Discovery**, and **Defense Evasion** tactics.

---

## ATT&CK Navigator Summary

```
EXECUTION               DISCOVERY               DEFENSE EVASION / PERSISTENCE
┌──────────────────┐   ┌──────────────────┐    ┌──────────────────┐
│  T1059.001       │   │  T1046           │    │  T1078           │
│  Command &       │   │  Network Service │    │  Valid Accounts  │
│  Scripting:      │   │  Discovery       │    │  (labuser)       │
│  PowerShell      │   │  (portscan.ps1)  │    │                  │
│  (Observed)      │   │  (Observed)      │    │  (Observed)      │
└──────────────────┘   └──────────────────┘    └──────────────────┘
```

---

## Detailed TTP Analysis

### T1046 — Network Service Discovery

| Field | Detail |
|---|---|
| **Tactic** | Discovery |
| **ID** | [T1046](https://attack.mitre.org/techniques/T1046/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those running on cloud infrastructure, in order to identify attack vectors. Network Service Discovery was the **primary technique** observed in this hunt — `portscan.ps1` systematically scanned ports across hosts in the `10.0.0.0/16` subnet.

**Evidence:**
- High volume of `ConnectionFailed` events from `saranpc2` (`10.3.0.42`)
- Sequential port ordering in `DeviceNetworkEvents` — textbook scanner signature
- `portscan.ps1` confirmed on disk at `C:\programdata\portscan.ps1`
- Script designed specifically to iterate through IP ranges and ports

**Why Attackers Do This:**
Port scanning tells an attacker:
- Which hosts are alive in the network
- Which services are running (RDP on 3389? SMB on 445? SSH on 22?)
- Which services might be exploitable

In a flat network with no east-west controls, a single compromised host can map the entire environment in minutes.

**Detection:**
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnections = count() by LocalIP, DeviceName, bin(Timestamp, 1m)
| where FailedConnections > 100
```

**Mitigation:**
- Implement network segmentation — hosts should not be able to freely scan peers
- Deploy an IDS/IPS to detect and block port scanning in real time
- Alert on high-volume connection failures from internal IPs

---

### T1059.001 — Command and Scripting Interpreter: PowerShell

| Field | Detail |
|---|---|
| **Tactic** | Execution |
| **ID** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. In this hunt, PowerShell was used to both **download** and **execute** the port scan script with deliberate bypass of security controls.

**Evidence:**
- `powershell.exe` observed in `DeviceProcessEvents` at `2026-03-27T10:47:50Z`
- Command line: `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1`
- Delivery: `Invoke-WebRequest` used to pull script from a public GitHub URL
- Initiating process: `cmd.exe` — a common pattern for staging PowerShell attacks

**Key Red Flags in the Command Line:**

| Flag | What It Means | Why It's Suspicious |
|---|---|---|
| `-ExecutionPolicy Bypass` | Ignore the machine's execution policy | Deliberate circumvention of a security control |
| `-File C:\programdata\...` | Run a specific script file | Combined with Bypass, indicates staged attack |
| `Invoke-WebRequest` | Download content from a URL | Pulling attack tooling from internet |
| `cmd /c powershell.exe` | Launching PowerShell from cmd | Common evasion pattern to obscure PowerShell origin |

**Detection:**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
    or ProcessCommandLine has_any("Invoke-WebRequest", "DownloadString", "iex")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

**Mitigation:**
- Enable **PowerShell Script Block Logging** (GPO: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell`)
- Enable **PowerShell Module Logging** for full command capture
- Configure **Constrained Language Mode** to restrict PowerShell capabilities
- Alert on any use of `-ExecutionPolicy Bypass` or `-EncodedCommand`

---

### T1078 — Valid Accounts

| Field | Detail |
|---|---|
| **Tactic** | Defense Evasion / Persistence / Initial Access |
| **ID** | [T1078](https://attack.mitre.org/techniques/T1078/) |
| **Status in Hunt** | ✅ Observed |
| **Confidence** | Medium-High |

**Description:**
Adversaries may obtain and abuse credentials of existing accounts to bypass access controls. In this hunt, the `labuser` account — a legitimate standard user account — was used to execute the port scan script. Whether the account was compromised or the user deliberately ran the script, the use of a valid account meant:

- No authentication alerts were triggered
- The process appeared as normal user activity at first glance
- Standard security controls (e.g., logon monitoring) would not flag this

**Evidence:**
- `AccountName == "labuser"` in the `portscan.ps1` process event
- `labuser` is a legitimate account in the environment
- No failed logons or credential anomalies detected for `labuser`

**Investigation Approach:**
When `labuser` was identified as the executing account, the following checks were performed:

```kql
// Was labuser's account recently used from unusual IPs?
DeviceLogonEvents
| where AccountName == "labuser"
| where DeviceName == "saranpc2"
| where ActionType == "LogonSuccess"
| summarize count() by RemoteIP, LogonType
| order by count_ desc
```

```kql
// Did labuser run any other suspicious processes?
DeviceProcessEvents
| where AccountName == "labuser"
| where DeviceName == "saranpc2"
| where ProcessCommandLine has_any("Bypass", "Invoke-WebRequest", "DownloadString", "encoded")
```

**Result:** No further anomalies detected for `labuser`. The execution appears isolated to this single event.

**Mitigation:**
- Enforce **least privilege** — standard users should not be able to run arbitrary scripts
- **Restrict PowerShell access** for non-admin accounts via AppLocker or WDAC
- **Monitor all script execution** by non-admin accounts as a matter of policy
- Enable MFA for all user accounts to reduce risk of credential compromise

---

## Full Kill Chain Mapping

```
PREPARATION          EXECUTION             DISCOVERY            (PREVENTED)
┌─────────────────┐  ┌─────────────────┐   ┌─────────────────┐  ┌─────────────────┐
│ • Download      │  │ • cmd.exe →     │   │ • portscan.ps1  │  │  Lateral        │
│   portscan.ps1  │  │   powershell    │   │   scans all     │  │  Movement       │
│   via           │  │   -Exec Bypass  │   │   hosts in      │  │  (T1021)        │
│   Invoke-WebReq │  │ • T1059.001     │   │   10.0.0.0/16   │  │                 │
│ • T1078 (valid  │  │                 │   │ • T1046         │  │  Exploitation   │
│   account used) │  │                 │   │                 │  │  of open ports  │
└─────────────────┘  └─────────────────┘   └─────────────────┘  └─────────────────┘
                                                    │                     ↑
                                                    │           NEVER REACHED
                                            Device isolated
                                            by SOC team
```

---

## Detection Coverage Assessment

| TTP | Detection Available in Hunt? | Detection Rule Recommended |
|---|---|---|
| T1046 — Network Service Discovery | ✅ Yes — via `DeviceNetworkEvents` aggregation | Port scan volume alert |
| T1059.001 — PowerShell | ✅ Yes — via `DeviceProcessEvents` CommandLine | ExecutionPolicy Bypass alert |
| T1078 — Valid Accounts | ⚠️ Partial — detected post-fact via process owner | Least privilege + script execution alert |

**Key Gap:** None of these were detected in real time — the hunt was **reactive**, triggered by user complaints about network slowdowns. All three TTPs should have automated detection rules that alert before a user notices degradation.

---

## References

- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

*Mapping authored by: Saran | CyberRange Lab | March 27, 2026*
