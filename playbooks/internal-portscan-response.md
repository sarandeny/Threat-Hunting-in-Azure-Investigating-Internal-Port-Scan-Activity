# 📋 Incident Response Playbook
## Scenario: Internal Port Scanning / Suspicious Network Reconnaissance

**Playbook ID:** IR-PB-002  
**Version:** 1.0  
**Last Updated:** March 27, 2026  
**Classification:** TLP:WHITE  

---

## Purpose

This playbook provides a structured, repeatable process for investigating and responding to suspected internal port scanning or network reconnaissance activity. It is designed for **Tier 1 and Tier 2 SOC analysts** working in environments with Microsoft Defender for Endpoint (MDE) telemetry.

---

## Trigger Conditions

Initiate this playbook when **any of the following** are true:

- [ ] Unexplained network performance degradation reported by server or infrastructure team
- [ ] An alert fires for a device with high-volume `ConnectionFailed` events from a single internal IP
- [ ] A detection rule fires for `powershell.exe -ExecutionPolicy Bypass` on an endpoint
- [ ] A script file (`.ps1`, `.bat`, `.vbs`) is created in `C:\programdata\` or `C:\temp\` by a non-admin process
- [ ] A device is observed downloading and immediately executing a script from the internet

---

## Severity Classification

| Severity | Criteria |
|---|---|
| 🔴 **Critical** | Active scanning + evidence of lateral movement or exploitation |
| 🟠 **High** | Active scanning confirmed from internal host + no lateral movement yet |
| 🟡 **Medium** | Historical scanning detected, device no longer active, no spread observed |
| 🟢 **Low** | Single anomalous connection burst — not confirmed as scanning |

**This hunt:** 🟠 High — Active internal port scan confirmed, contained before lateral movement.

---

## Phase 1: Detection & Initial Triage

**Estimated time: 15–30 minutes**

### Step 1.1 — Identify the Source Host

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where Timestamp > ago(1h)
| summarize ConnectionCount = count() by DeviceName, LocalIP, bin(Timestamp, 5m)
| order by ConnectionCount desc
```

- [ ] Which device has the highest failed connection count?
- [ ] Is the count significantly higher than other devices? (Outlier = suspect)
- [ ] Note the `LocalIP` of the suspect device

### Step 1.2 — Confirm Port Scanning Pattern

```kql
let IPInQuestion = "<SUSPECT_IP>";

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol
| order by Timestamp asc
```

- [ ] Are `RemotePort` values incrementing sequentially? → **Port scan confirmed**
- [ ] Are `RemoteIP` values incrementing? → **Subnet sweep**
- [ ] What time did the scanning begin? (Note for pivot step)

### Step 1.3 — Assign Initial Severity

Use the table above. If scanning is confirmed and active → 🟠 High minimum.

**Escalate to Tier 2 if:** Scanning has been running for >30 minutes without detection, or if any `ConnectionSuccess` events appear alongside the failures (potential exploit in progress).

---

## Phase 2: Root Cause Investigation

**Estimated time: 20–45 minutes**

### Step 2.1 — Pivot to Process Events

```kql
DeviceProcessEvents
| where DeviceName == "<SUSPECT_DEVICE>"
| where Timestamp between (datetime(<SCAN_START_TIME> - 10m) .. datetime(<SCAN_START_TIME> + 10m))
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

- [ ] Is there a `powershell.exe` or `cmd.exe` process around the scan start time?
- [ ] Does `ProcessCommandLine` contain `-ExecutionPolicy Bypass`?
- [ ] Does `ProcessCommandLine` contain `Invoke-WebRequest` or similar download commands?
- [ ] What `AccountName` ran this process?

### Step 2.2 — Check for Dropped Script Files

```kql
DeviceFileEvents
| where DeviceName == "<SUSPECT_DEVICE>"
| where ActionType == "FileCreated"
| where FileName endswith ".ps1" or FileName endswith ".bat" or FileName endswith ".vbs"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

- [ ] Was a script file dropped to disk? Where?
- [ ] What created it? (`InitiatingProcessCommandLine`)
- [ ] Was it downloaded from the internet? (Look for URLs in command line)

### Step 2.3 — Review the Executing Account

```kql
DeviceLogonEvents
| where DeviceName == "<SUSPECT_DEVICE>"
| where AccountName == "<EXECUTING_ACCOUNT>"
| where ActionType == "LogonSuccess"
| summarize count() by RemoteIP, LogonType
```

- [ ] Are logon IPs for this account normal?
- [ ] Has the account been used from unusual locations?
- [ ] Are there failed logon attempts before the success? (Possible compromise)

---

## Phase 3: Containment

**Estimated time: 5–15 minutes**

### Step 3.1 — Isolate the Device

**Via MDE Portal:**
1. Navigate to the device page for `<SUSPECT_DEVICE>`
2. Click **"Device actions"** → **"Isolate device"**
3. Confirm — this cuts all network access while preserving MDE telemetry

**What isolation does:**
- Stops ongoing scanning immediately
- Prevents any lateral movement to other hosts
- Preserves forensic data (process memory, disk, logs) for further investigation
- MDE communication channel remains open (you can still query the device)

### Step 3.2 — Terminate the Malicious Process

**Via MDE Live Response (if available):**
```
# In MDE Live Response console:
processes
# Find the PID of powershell.exe running the scanner
kill <PID>
```

Or raise a request for the endpoint team to terminate via standard process.

### Step 3.3 — Preserve Evidence

Before any remediation, ensure the following logs are captured:

- [ ] Export `DeviceNetworkEvents` for the suspect device (last 24 hours)
- [ ] Export `DeviceProcessEvents` for the suspect device (last 24 hours)
- [ ] Export `DeviceFileEvents` for the suspect device (last 24 hours)
- [ ] Screenshot or export the process command line in full
- [ ] Note the script file path and content if accessible

---

## Phase 4: Eradication & Recovery

**Estimated time: 1–4 hours**

### Step 4.1 — Malware Scan

Run a full system malware scan via MDE:
- MDE Portal → Device page → **"Run antivirus scan"** → Full scan
- Wait for completion — document the result

**If scan is clean:** Proceed with rebuild as precaution (see Step 4.2)  
**If malware is detected:** Escalate to 🔴 Critical — follow full IR process, notify CISO

### Step 4.2 — Rebuild Recommendation

Even with a clean scan, a rebuild is recommended when:
- The execution vector is unclear
- `-ExecutionPolicy Bypass` was used (indicates deliberate security bypass)
- The account executing the script may have been compromised
- The script was downloaded from the internet and executed

**Raise a ticket for:** Reimaging/rebuilding `<SUSPECT_DEVICE>` before returning to service.

### Step 4.3 — Account Review

- [ ] Reset `<EXECUTING_ACCOUNT>` password as a precaution
- [ ] Review account permissions — does this account need to run scripts?
- [ ] Consider restricting the account's PowerShell access via AppLocker or WDAC

---

## Phase 5: Hardening & Improvement

### Immediate Hardening Actions

| Action | Tool | Priority |
|---|---|---|
| Enable PowerShell Script Block Logging | GPO | 🔴 High |
| Alert on `-ExecutionPolicy Bypass` | Sentinel/MDE Custom Detection | 🔴 High |
| Alert on high-volume `ConnectionFailed` | Sentinel/MDE Custom Detection | 🔴 High |
| Restrict PowerShell for non-admin users | AppLocker / WDAC | 🟠 Medium |
| Implement network segmentation | NSG / Firewall rules | 🟠 Medium |
| Review least privilege for all accounts | AD / Azure AD | 🟡 Low |

### GPO Settings for PowerShell Hardening

```
Computer Configuration →
  Administrative Templates →
    Windows Components →
      Windows PowerShell:
        - Turn on Script Block Logging: ENABLED
        - Turn on Module Logging: ENABLED
        - Turn on PowerShell Transcription: ENABLED
```

### Execution Policy via GPO

```
Computer Configuration →
  Windows Settings →
    Security Settings →
      Software Restriction Policies (or AppLocker):
        - Block: powershell.exe launched from cmd.exe by non-admin users
        - Block: Scripts in C:\programdata\, C:\temp\, C:\users\public\
```

---

## Appendix: Decision Flow

```
High volume ConnectionFailed detected
            ↓
    Is it from a single internal IP?
    YES ──────────────────────────────→ Suspect identified
    NO  → Check for DDoS / external cause
            ↓
    Sequential port pattern in RemotePort?
    YES ──────────────────────────────→ Port scan CONFIRMED
    NO  → May be noisy app / misconfiguration
            ↓
    Pivot to DeviceProcessEvents
    Find PowerShell / script execution?
    YES ──────────────────────────────→ Root cause found
    NO  → Investigate network driver / OS-level cause
            ↓
    Isolate device → Malware scan → Rebuild
```

---

## Documentation Template

```
Incident ID: IR-2026-___
Date: _______________
Analyst: _______________

DEVICE
------
Device Name: _______________
Local IP: _______________
Scan Start Time: _______________

ROOT CAUSE
----------
Script Name: _______________
Script Location: _______________
Executing Account: _______________
Command Line: _______________
Download Source: _______________

VERDICT
-------
[ ] Port scan confirmed
[ ] Lateral movement detected
[ ] Malware detected
[ ] Clean scan

ACTIONS TAKEN
-------------
[ ] Device isolated via MDE
[ ] Process terminated
[ ] Malware scan completed (result: _______)
[ ] Logs preserved
[ ] Password reset for account
[ ] Rebuild ticket raised

RECOMMENDATIONS
---------------
1. _______________
2. _______________
3. _______________
```

---

*Playbook authored by: Saran | CyberRange Lab | March 27, 2026*  
*Review cycle: Quarterly or after each major incident*
