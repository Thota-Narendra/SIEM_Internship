# 📡 Scenario 5: Command & Control (C2) Beaconing Detection

## 🎯 Detection Objective
Detect periodic HTTP/HTTPS-based communication to rare external domains which may indicate beaconing behavior from malware.

## 🛠 Tools Used
- **SIEM Stack**: Elasticsearch, Kibana
- **Log Shippers**: Winlogbeat, Sysmon
- **Detection Engine**: ElastAlert
- **Simulation Tool**: curl or scheduled task with http-ping

## 👻 Attacker Mindmap
![image](https://github.com/user-attachments/assets/faead105-4160-4d7e-8a17-a2934267d410)

## 🧪 Task Execution Steps

### ⚙️ Simulating C2 Beaconing Behavior
1. On the Windows machine, run periodic outbound connections using tools like:
```powershell
while ($true) { Invoke-WebRequest -Uri "http://testphp.vulnweb.com" -UseBasicParsing; Start-Sleep -Seconds 60 }
```
or create a scheduled task:
```cmd
schtasks /create /tn "C2Beacon" /tr "curl http://testphp.vulnweb.com" /sc minute /mo 1
```

2. Allow it to run for at least 5-10 minutes.

## 🔍 What Gets Logged
- `event.code: 3` (Sysmon - Network Connection)
- `process.name: curl.exe` or `powershell.exe`
- `destination.ip`: External IPs
- Regular intervals of the same process or domain/IP

## 🧠 Detection Logic (KQL for Kibana)
```kql
event.code: 3 AND (
  process.name: "curl.exe" OR 
  process.name: "powershell.exe"
) AND destination.ip: * AND NOT destination.ip: ("internal_IP_ranges")
```

## 📬 Sample Log
![alt text](<sample log.png>)

## 🚨 Analyst Action on Alert
- Verify the destination domain/IP reputation.
- Check if the behavior is consistent with known good software.
- Correlate with scheduled tasks or abnormal processes.
- Consider isolating the system or blocking the domain.

## ⚠️ Possible False Positives
- Automated updates from legitimate tools (e.g., antivirus, software updaters).
- Scripts using regular API calls (DevOps, backups).

## ✅ Detection Status
**Successfully Triggered**
- Alert sent on repetitive external communication.
- Events matched on Sysmon ID 3.

---
