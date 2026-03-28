# 📊 KQL Query Reference — Internal Port Scan Threat Hunt

> All queries were executed in **Microsoft Defender for Endpoint (MDE)**  
> Platform: MDE Advanced Hunting / Microsoft Sentinel  
> Hunt Date: March 27, 2026

---

## Table of Contents

1. [Identify Hosts with Excessive Failed Connections](#1-identify-hosts-with-excessive-failed-connections)
2. [Chronological Connection Failures from Suspect IP](#2-chronological-connection-failures-from-suspect-ip)
3. [Pivot to Process Events — Find the Responsible Script](#3-pivot-to-process-events--find-the-responsible-script)
4. [Check for Suspicious File Downloads](#4-check-for-suspicious-file-downloads)
5. [Confirm Script Execution Details](#5-confirm-script-execution-details)
6. [Bonus: Detection Engineering Queries](#6-bonus-detection-engineering-queries)

---

## 1. Identify Hosts with Excessive Failed Connections

**Purpose:** Surface any device generating an abnormal number of failed outbound connections — the primary signal for port scanning or network flooding.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

**Field Reference:**

| Field | Description |
|---|---|
| `ActionType` | Type of network event — `ConnectionFailed`, `ConnectionSuccess`, etc. |
| `LocalIP` | Source IP of the connection attempt |
| `ConnectionCount` | Total failed connections per device (aggregated) |

**What to look for:**
- Any device with a significantly **higher count than peers** — that's your suspect
- Devices with hundreds or thousands of failed connections in a short window
- Cross-reference `LocalIP` with your known asset inventory to identify the host

**Result (this hunt):**
`saranpc2` (`10.3.0.42`) had the highest failed connection count, making it the immediate suspect.

---

**Extended version — add a time window:**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where Timestamp > ago(1h)
| summarize ConnectionCount = count() by DeviceName, LocalIP, bin(Timestamp, 5m)
| order by ConnectionCount desc
```

> 💡 **SOC Tip:** Adding `bin(Timestamp, 5m)` lets you see *when* the spike occurred, not just the total. This helps you pinpoint the start of an attack and correlate with other events.

---

## 2. Chronological Connection Failures from Suspect IP

**Purpose:** Pull all failed connections from the suspect IP in time order to confirm port scanning via sequential port patterns.

```kql
let IPInQuestion = "10.3.0.42";

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

**What to look for:**
- **Sequential `RemotePort` values** — ports incrementing in order (e.g., 1, 2, 3... or 21, 22, 23...) = port scanner
- **Sequential `RemoteIP` values** — incrementing IPs = subnet sweep
- **High frequency** — hundreds of events per minute = automated tool, not human

**Why sequential ports matter:**
> Legitimate application traffic hits specific, known ports (80, 443, 3389, etc.) with no particular ordering. When you see ports incrementing numerically across short time windows, it's virtually always a scanner. This is how you distinguish a port scan from noisy legitimate traffic at a glance.

**Result (this hunt):**
The chronological view confirmed sequential port ordering across destination hosts — confirming automated port scanning behaviour from `10.3.0.42`.

---

**Extended version — include destination context:**

```kql
let IPInQuestion = "10.3.0.42";

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, DeviceName
| order by Timestamp asc
```

---

## 3. Pivot to Process Events — Find the Responsible Script

**Purpose:** Identify what process or script was responsible for generating the scanning traffic, by querying `DeviceProcessEvents` around the time the scanning began.

```kql
DeviceProcessEvents
| where DeviceName == "saranpc2"
| where Timestamp between (datetime(2026-03-27T10:40:00Z) .. datetime(2026-03-27T11:00:00Z))
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

**Key concepts:**

- `between (datetime(...) .. datetime(...))` — filters to a specific time window
- `ProcessCommandLine` — the **most important field** — shows exactly what was run, including arguments and flags
- `InitiatingProcessFileName` — what launched this process (e.g., `cmd.exe`, `explorer.exe`)
- `AccountName` — which user account executed this process

**What to look for:**
- `powershell.exe` with suspicious flags like `-ExecutionPolicy Bypass`, `-EncodedCommand`, `-NoProfile`
- Unusual script file paths (e.g., `C:\programdata\`, `C:\temp\`, `%APPDATA%`)
- `cmd.exe` or `wscript.exe` launching PowerShell (common attacker pattern)
- `Invoke-WebRequest`, `curl`, `wget` in the command line (downloading from internet)

**Result (this hunt):**
`portscan.ps1` was found launching at `2026-03-27T10:47:50.0391688Z` via:
```
powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```
Initiated by `cmd.exe` under the `labuser` account.

---

**Generic pivot template — use this in any hunt:**

```kql
// Pivot from a network event timestamp to find responsible processes
let SuspectDevice = "DEVICE_NAME_HERE";
let IncidentTime = datetime(YYYY-MM-DDTHH:MM:SSZ);

DeviceProcessEvents
| where DeviceName == SuspectDevice
| where Timestamp between ((IncidentTime - 10m) .. (IncidentTime + 10m))
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

---

## 4. Check for Suspicious File Downloads

**Purpose:** Confirm the script was downloaded to disk and identify when it appeared.

```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where FileName == "portscan.ps1"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**What to look for:**
- `ActionType == "FileCreated"` — the file was newly written to disk
- `FolderPath` — unusual locations like `C:\programdata\`, `C:\windows\temp\` are red flags
- `InitiatingProcessCommandLine` — the command that created the file (look for `Invoke-WebRequest`, `curl`, `certutil`)

**Result (this hunt):**
`portscan.ps1` was created in `C:\programdata\` — a writable directory commonly used by attackers to drop files, as it doesn't require elevated privileges.

---

**Broader version — find any newly created scripts:**

```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where ActionType == "FileCreated"
| where FileName endswith ".ps1" or FileName endswith ".bat" or FileName endswith ".vbs"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

> 💡 **SOC Tip:** Any `.ps1`, `.bat`, `.vbs`, or `.js` file created in `programdata`, `temp`, or `appdata` by `powershell.exe` or `cmd.exe` is a high-value finding worth investigating immediately.

---

## 5. Confirm Script Execution Details

**Purpose:** Get the full picture of the script execution — command, user, and parent process — to confirm the chain of events.

```kql
DeviceProcessEvents
| where DeviceName == "saranpc2"
| where ProcessCommandLine has "portscan"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Result (this hunt):**

| Field | Value |
|---|---|
| Timestamp | `2026-03-27T10:47:50.0391688Z` |
| FileName | `powershell.exe` |
| ProcessCommandLine | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1` |
| AccountName | `labuser` |
| InitiatingProcessFileName | `cmd.exe` |

**Why `-ExecutionPolicy Bypass` matters:**
PowerShell's execution policy is a first-line defence against running unsigned scripts. Using `-ExecutionPolicy Bypass` deliberately circumvents this control — it's a common attacker technique and should always be treated as suspicious in production environments.

---

## 6. Bonus: Detection Engineering Queries

These queries can be deployed as **scheduled detection rules** in Microsoft Sentinel or MDE Custom Detections.

### 6.1 — Port Scan Detector (High-Volume Failed Connections)

```kql
// Alert: Single IP generating excessive failed connections (port scan indicator)
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where isnotempty(LocalIP)
| summarize FailedConnections = count() by LocalIP, DeviceName, bin(Timestamp, 1m)
| where FailedConnections > 100
| project Timestamp, DeviceName, LocalIP, FailedConnections
| order by FailedConnections desc
```

> **Alert threshold:** >100 failed connections per IP per minute  
> **Severity:** High  
> **Recommended action:** Investigate device, check `DeviceProcessEvents` for scanner tooling

---

### 6.2 — PowerShell Execution Policy Bypass Detector

```kql
// Alert: PowerShell launched with -ExecutionPolicy Bypass
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
    or ProcessCommandLine has "-ep bypass"
    or ProcessCommandLine has "-exec bypass"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

> **Severity:** High  
> **Recommended action:** Investigate immediately — this is a deliberate security control bypass

---

### 6.3 — Script Downloaded from Internet and Executed

```kql
// Alert: PowerShell downloading and running scripts from the internet
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("Invoke-WebRequest", "iwr", "wget", "curl", "DownloadFile", "DownloadString")
| where ProcessCommandLine has_any(".ps1", ".bat", ".exe", ".vbs")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

> **Severity:** Critical  
> **Recommended action:** Isolate device, pull `DeviceFileEvents` for dropped files, run malware scan

---

### 6.4 — Script Files Created in Suspicious Locations

```kql
// Alert: Script files created in writable system directories
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".ps1" or FileName endswith ".bat" or FileName endswith ".vbs"
| where FolderPath has_any(
    @"C:\programdata",
    @"C:\windows\temp",
    @"C:\users\public",
    @"C:\temp"
)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

> **Severity:** Medium-High  
> **Recommended action:** Inspect the dropped file, check execution history in `DeviceProcessEvents`

---

### 6.5 — Sequential Port Scan Pattern (Advanced)

```kql
// Detect sequential port scanning: look for ordered port increments
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where isnotempty(RemotePort)
| summarize 
    Ports = make_list(RemotePort),
    Count = count()
    by LocalIP, DeviceName, bin(Timestamp, 5m)
| where Count > 50
// Sequential ports = ports with a small average difference between consecutive values
| extend PortList = array_sort_asc(Ports)
| project Timestamp, DeviceName, LocalIP, Count, PortList
| order by Count desc
```

> **Severity:** High  
> **Note:** This query requires post-processing to confirm sequential ordering — use as a starting point and review `PortList` manually.

---

## Quick Reference: Key KQL Concepts Used in This Hunt

| Concept | Example |
|---|---|
| `let` variable for IP | `let IPInQuestion = "10.3.0.42";` |
| Time window filter | `where Timestamp between (datetime(...) .. datetime(...))` |
| Time bucketing | `bin(Timestamp, 1m)` — group events into 1-minute buckets |
| Cross-table pivoting | Query `DeviceNetworkEvents` → note timestamp → query `DeviceProcessEvents` |
| `has` vs `==` | `has` is substring match; `==` is exact match |
| `has_any()` | Match against multiple values: `has_any("Bypass", "bypass")` |
| `project` | Select only the columns you need — keeps output readable |
| `order by Timestamp asc` | Chronological order — essential for timeline reconstruction |

---

*Queries authored by: Saran | CyberRange Lab | March 27, 2026*
