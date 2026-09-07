# AI SENTINEL — AI-Powered Host Security Analysis

## What This Does
AI Sentinel performs a comprehensive security analysis of a Windows machine using Claude AI as the analysis engine. It collects host data via PowerShell and sends it to Claude for threat analysis across 5 phases:

1. **Event Log Analysis** — Critical Windows Event IDs (logon failures, new services, log clearing, scheduled task creation, etc.)
2. **Process Behavioral Analysis** — LOLBin detection, unsigned processes, fileless malware indicators
3. **Network & Persistence Analysis** — External connections, suspicious ports, registry run keys, scheduled tasks, services
4. **AI Malware Behavioral Scan** — Pattern-based malware detection with MITRE ATT&CK TTP mapping
5. **Threat Summary** — Executive report with prioritized remediation steps

## Files
- `collect.ps1` — PowerShell data collection script (run on the target machine)
- `sentinel_dashboard.html` — AI analysis dashboard (run in any browser)

## Usage

### Step 1: Collect Host Data
Open PowerShell **as Administrator** on the machine you want to analyze:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
cd "path\to\ai_sentinel"
.\collect.ps1
```

This generates `sentinel_data.json` in the same directory.
Collection takes ~1-2 minutes depending on event volume.

Optional parameters:
```powershell
.\collect.ps1 -EventHours 48 -OutputFile "my_scan.json"
```

### Step 2: Analyze in Dashboard
1. Open `sentinel_dashboard.html` in a browser (Chrome recommended)
2. Enter your Claude API key (`sk-ant-api03-...`)
3. Optionally describe your environment (helps AI understand what's normal)
4. Load the `sentinel_data.json` file
5. Click **INITIALIZE THREAT ANALYSIS**

Analysis takes 2-3 minutes (5 API calls).

## What It Collects
- Windows Event Logs (Security, System, Application, PowerShell, Defender)
- Running processes (signatures, paths, LOLBin detection)
- TCP/UDP network connections
- DNS cache (beacon detection)
- Registry Run keys
- Scheduled tasks
- Windows services
- Startup folder items
- Recent executables in high-risk filesystem paths
- Local users and admins
- System information (OS, Defender status, firewall)

## Data Privacy
- All data goes to Anthropic's Claude API for analysis
- Nothing is stored permanently; API calls are stateless
- No data is sent anywhere else
- The script is read-only; it never modifies anything on the target machine

## Requirements
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Administrator privileges
- Claude API key (https://console.anthropic.com)
- Modern browser (Chrome, Edge, Firefox)

## API Key
Get a Claude API key at https://console.anthropic.com
The key is entered in the dashboard — it never leaves your browser except for API calls.

## Limitations
- Not a replacement for a real EDR/SIEM
- Analysis quality depends on what data was collected
- Some data collection requires admin rights; partial data is collected if run as standard user
- DNS cache beacon detection requires manual review of flagged domains
- File hash lookup against threat intel feeds (VirusTotal) not included by default

## Rendering security

Imported telemetry and AI output are untrusted. The dashboard now creates DOM nodes and assigns values with `textContent`, including raw JSON panels. Severity classes come from a fixed list. No telemetry-derived HTML or attributes are interpreted. API keys are still supplied locally by the analyst; do not distribute a dashboard with embedded keys.

Regression check: `npm install && npm test`. The test loads the actual dashboard in jsdom and supplies HTML/event-handler payloads in telemetry, findings, severity and raw JSON, then verifies they remain text.
