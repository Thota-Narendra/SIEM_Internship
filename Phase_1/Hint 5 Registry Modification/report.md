# 🚨 Registry Modification Detection

## 📌 Objective
Simulate a registry modification on a Windows VM and detect related events using Sysmon, Winlogbeat, Elasticsearch, and Kibana.

---

## 🧪 What Was Done

1. **Simulated Registry Modification**:
   - Used PowerShell to add a new registry key under:
     ```
     HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
     ```
   - Command used:
     ```powershell
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Ghost" -Value "C:\temp\malware.exe"
     ```

2. **Sysmon Configuration**:
   - Ensured Sysmon was set to log registry modifications (**Event ID 13**).

3. **Winlogbeat Setup**:
   - Configured to forward Sysmon logs to **Elasticsearch**.

4. **Kibana Monitoring**:
   - Used Kibana to monitor for **Sysmon Event ID 13**, filtering specifically for suspicious `Run` key activity.

---

## 👁️ What Was Observed in the Logs

✅ **Sysmon and Winlogbeat logs** captured:

- **Event ID 13** – Registry key modification event.
- **Registry Path**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Ghost`
- **New Value**: `C:\temp\malware.exe`

---

## 🧠 How SIEM Flagged the Event

✔️ Detection workflow:

- **Sysmon** captured the registry key change.
- **Winlogbeat** forwarded the log to **Elasticsearch**.
- Analysts used **Kibana** to identify and analyze the registry modification.

---

## 📊 Data Source Mapping

| Log Source | Event Type             | Event ID | Description                           |
|------------|------------------------|----------|---------------------------------------|
| Sysmon     | Registry Modification  | 13       | Modification of registry keys         |
| Winlogbeat | Log Forwarding         | -        | Forwarded all events to Elasticsearch |

---

## 📩 Sample Alert


![Screenshot 2025-05-24 095408](https://github.com/user-attachments/assets/85515597-4ee0-43df-8b76-7e9d72102db3)

---

## 🛡️ Analyst Action on Alert

- ✅ Verified the registry change in **Kibana Discover**.
- ✅ Correlated registry path and new value with known persistence mechanisms.
- ✅ Investigated the associated process and user context for signs of malicious behavior.

---

## ⚠️ Possible False Positives

| 🧩 Scenario               | 📌 Description                                                                 |
|--------------------------|---------------------------------------------------------------------------------|
| **Legitimate Software**  | Some trusted applications may modify the `Run` key during installation or updates. |
| **IT Automation Scripts**| Enterprise IT scripts or GPOs may alter registry settings as part of normal operations. |
| **User Customization**   | Users configuring startup apps might unintentionally trigger detections.       |
| **Software Updaters**    | Auto-updaters (e.g., browser or antivirus tools) may create similar entries.   |
| **Registry Cleanup Tools** | Registry management software may temporarily create or modify keys.           |

---

## 🛠️ Recommendations

- 🔍 **Whitelist Known Good Modifications**:
  - Hash or path-based filtering for common, trusted binaries.
  
- 📚 **Context-Aware Detection**:
  - Combine registry events with process telemetry, parent-child relationships, or user identity.

- 📈 **Behavioral Correlation**:
  - Match registry changes with new process executions or unusual login activity.

- 🔁 **Rule Tuning & Review**:
  - Continuously update detection rules based on observed false positives and environment-specific patterns.

- 🤖 **UEBA Integration**:
  - Implement User and Entity Behavior Analytics to flag anomalies beyond static rule-based alerts.

---

## 🧪 Detection Status

✅ **Successfully Triggered**

- Sysmon logged the registry change.
- Event was successfully detected and visualized in Kibana.


