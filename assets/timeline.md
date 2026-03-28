# ⏱️ Attack Timeline Reconstruction

**Device:** `saranpc2` — IP `10.3.0.42`  
**Hunt Date:** March 27, 2026  
**Analyst:** Saran

---

## Timeline of Events

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T-UNKNOWN]
    📌 EVENT: Environment Security Gap — Flat Network
    ─────────────────────────────────────────────────────────────────
    The 10.0.0.0/16 network has no east-west segmentation.
    All internal hosts can communicate freely with each other.
    PowerShell is unrestricted across all endpoints.
    No execution policy enforced. No script block logging enabled.
    
    Status: Pre-existing configuration gap

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27T10:47:50.0391688Z]
    📌 EVENT: portscan.ps1 Executed on saranpc2
    ─────────────────────────────────────────────────────────────────
    The labuser account executes the following command:
    
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/
    joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/
    entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1'
    
    cmd /c powershell.exe -ExecutionPolicy Bypass -File 
    C:\programdata\portscan.ps1
    
    What happened:
    1. Script downloaded from public GitHub URL to C:\programdata\
    2. Immediately executed with -ExecutionPolicy Bypass
    3. portscan.ps1 begins systematically scanning the 10.0.0.0/16 subnet
    
    Source: DeviceProcessEvents (ProcessCommandLine)
    Confirmed via: DeviceFileEvents (FileCreated — portscan.ps1)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27T10:47:50Z → ONGOING]
    📌 EVENT: Mass Port Scan Begins
    ─────────────────────────────────────────────────────────────────
    portscan.ps1 begins generating high-volume outbound connection
    attempts across the local network.
    
    Characteristics observed:
    ┌──────────────────────────────────────────────────────────────┐
    │ Source IP:    10.3.0.42 (saranpc2)                          │
    │ Targets:      All hosts in 10.0.0.0/16                      │
    │ Pattern:      Sequential port order (1, 2, 3... etc.)       │
    │ Protocol:     TCP                                            │
    │ Volume:       Hundreds of ConnectionFailed events/minute    │
    └──────────────────────────────────────────────────────────────┘
    
    Source: DeviceNetworkEvents (ActionType == "ConnectionFailed")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ONGOING]
    📌 EVENT: Network Degradation Noticed by Server Team
    ─────────────────────────────────────────────────────────────────
    The mass of failed TCP connection attempts begins causing
    noticeable network performance degradation on older devices
    in the 10.0.0.0/16 subnet.
    
    The server team reports the issue to the security team.
    Initial suspicion: External DDoS attack.
    
    External DDoS ruled out — investigation pivots internally.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — HUNT INITIATED]
    📌 EVENT: Security Team Begins Threat Hunt
    ─────────────────────────────────────────────────────────────────
    Hypothesis formed:
    "An internal host may be conducting port scanning or generating 
    excessive network traffic through unrestricted PowerShell."
    
    Key data sources identified:
    - DeviceNetworkEvents
    - DeviceFileEvents  
    - DeviceProcessEvents

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 1]
    📌 ANALYSIS: Hosts with Excessive Failed Connections
    ─────────────────────────────────────────────────────────────────
    DeviceNetworkEvents
    | where ActionType == "ConnectionFailed"
    | summarize ConnectionCount = count() by DeviceName, LocalIP
    | order by ConnectionCount
    
    ✅ Result: saranpc2 (10.3.0.42) flagged as top outlier

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 2]
    📌 ANALYSIS: Chronological Connection Failures from 10.3.0.42
    ─────────────────────────────────────────────────────────────────
    DeviceNetworkEvents
    | where ActionType == "ConnectionFailed"
    | where LocalIP == "10.3.0.42"
    | order by Timestamp desc
    
    ✅ Result: Sequential port ordering confirmed — PORT SCAN identified

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 3]
    📌 PIVOT: DeviceProcessEvents around scan start time
    ─────────────────────────────────────────────────────────────────
    DeviceProcessEvents
    | where DeviceName == "saranpc2"
    | where Timestamp ~ 10:47:50Z (±10 minutes)
    
    ✅ Result: portscan.ps1 discovered — launched at 10:47:50.039Z
    ✅ Executing account: labuser
    ✅ Command: powershell.exe -ExecutionPolicy Bypass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — INVESTIGATION]
    📌 EVENT: Script Reviewed on Device
    ─────────────────────────────────────────────────────────────────
    Analyst logs into saranpc2 and inspects portscan.ps1 directly.
    Script confirmed to perform systematic port scanning of the
    local network — iterating through IPs and ports sequentially.
    
    labuser identified as the account that ran the script.
    Review of labuser logon history — no unusual IPs or patterns.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — CONTAINMENT]
    📌 ACTION: Device Isolated via MDE
    ─────────────────────────────────────────────────────────────────
    saranpc2 isolated from the network via MDE.
    Port scanning activity stops immediately.
    portscan.ps1 process terminated.
    
    MDE communication channel preserved for ongoing investigation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — MALWARE SCAN]
    📌 ACTION: Full Malware Scan Completed
    ─────────────────────────────────────────────────────────────────
    Full system malware scan run on saranpc2 via MDE.
    
    Result: ❌ No malicious payloads detected.
    
    Decision: Despite clean scan, rebuild recommended as precaution
    given the -ExecutionPolicy Bypass usage and internet download.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — VERDICT]
    📌 CONCLUSION: Reconnaissance Confirmed, No Malware, Device Contained
    ─────────────────────────────────────────────────────────────────
    ✅ Internal port scan confirmed from saranpc2 (10.3.0.42)
    ✅ Root cause: portscan.ps1 executed via PowerShell Bypass
    ✅ Executing account: labuser
    ✅ No malware detected
    ✅ No lateral movement or exploitation observed
    ✅ Device isolated — scanning stopped
    🔲 Rebuild ticket raised — pending reimage

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## What Could Have Happened Next (Threat Modelling)

If the scan had completed and the data been acted on by a threat actor, the likely next steps would have been:

```
Port Scan Completes (T1046)
         ↓
Attacker maps all open services on 10.0.0.0/16
(RDP on 3389? SMB on 445? Unpatched services?)
         ↓
Lateral Movement via RDP or SMB (T1021)
         ↓
Privilege Escalation on second host (T1068)
         ↓
Persistence: New admin account, registry run key (T1136, T1547)
         ↓
Impact: Ransomware deployment, data exfiltration (T1486, T1041)
```

**Why the flat network made this especially dangerous:**  
With no east-west segmentation, a completed port scan would have given a threat actor a full map of every reachable service in the environment — from the same device, without any network-level friction.

---

## Key Timestamps Reference

| Timestamp | Event |
|---|---|
| Pre-existing | Flat network, unrestricted PowerShell — no controls |
| `2026-03-27T10:47:50.039Z` | `portscan.ps1` launched by `labuser` on `saranpc2` |
| Shortly after | Mass `ConnectionFailed` events begin across `10.0.0.0/16` |
| During | Server team reports network degradation |
| `2026-03-27` | External DDoS ruled out — internal hunt initiated |
| `2026-03-27` | `saranpc2` identified as source via `DeviceNetworkEvents` |
| `2026-03-27` | Sequential ports confirm port scan |
| `2026-03-27` | Pivot to `DeviceProcessEvents` — `portscan.ps1` found |
| `2026-03-27` | Device isolated via MDE — scanning stopped |
| `2026-03-27` | Malware scan: clean |
| `2026-03-27` | Rebuild ticket raised |

---

*Timeline reconstructed by: Saran | CyberRange Lab | March 27, 2026*
