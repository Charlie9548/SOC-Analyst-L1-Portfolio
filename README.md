# SIEM Log Monitoring & Threat Detection using Wazuh

## Project Overview
This project demonstrates a beginner-friendly Security Operations Center (SOC) lab using Wazuh SIEM and a Windows 10 endpoint. The objective is to monitor Windows Security events and investigate failed login attempts.

## Objectives
- Monitor Windows endpoint security events using Wazuh.
- Verify Windows Security Event ID 4625.
- Search and investigate failed login alerts in Wazuh Threat Hunting.
- Understand basic alert triage and evidence-based analysis.

## Lab Environment

| Component | Details |
|---|---|
| SIEM | Wazuh |
| Manager | Ubuntu Linux |
| Endpoint | Windows 10 Pro |
| Agent Name | mylaplab |
| Log Source | Windows Security Log |
| Event ID | 4625 |

## Tools Used
- Wazuh SIEM
- Windows PowerShell
- Windows Security Event Logs
- Wazuh Threat Hunting

## Implementation

### 1. Verify Wazuh Agent
Checked the Windows agent service using PowerShell:

```powershell
Get-Service WazuhSvc
```

The service was observed in the Running state.

### 2. Verify Failed Login Events
Queried the Windows Security log for Event ID 4625:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5
```

The output showed events with the message "An account failed to log on."

### 3. Search Alerts in Wazuh
Used the following query in Threat Hunting → Events:

```text
data.win.system.eventID: "4625"
```

## Findings
- Six matching events were displayed in Wazuh Threat Hunting.
- Agent: `mylaplab` (Windows 10 Pro).
- Rule description: `Logon Failure - Unknown user or bad password`.
- Rule level: 5 (low severity).

**Important:** These observations do not, by themselves, confirm a brute-force attack. Further investigation of the target account, source IP, logon type, failure details, and surrounding events is required.

## Skills Demonstrated
- Windows Security log analysis
- SIEM event monitoring
- Wazuh alert investigation
- PowerShell event-log queries
- Basic SOC alert triage

## Project Report
See the [Wazuh SIEM Project Report][View Project Report (PDF)](./Wazuh_SIEM_Project_Report_v3.pdf) for the methodology, evidence, findings, and next investigation steps.

## Future Improvements
- Investigate the username, source IP, and failure reason in individual alerts.
- Analyse repeated failed-login
