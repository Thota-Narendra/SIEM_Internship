# 🚨 Persistence Simulation via Startup Folder

## 📌 Objective
Simulate a persistence mechanism by placing a file in the Windows Startup folder and detect related events using Sysmon, Winlogbeat, Elasticsearch, Kibana, and ElastAlert.

## 🧪 What Was Done

### Simulated Persistence Mechanism
- **Action**: Copied a file (`evil.exe`) to the Windows Startup folder to ensure it runs at system startup
- **Command used**:
  ```cmd
  copy evil.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"
  ```

### Sysmon Configuration
- Ensured Sysmon was configured to log:
  - File creation events (Event ID 11)
  - Process creation events (Event ID 1)

### Winlogbeat Setup
- Configured to forward Sysmon logs to Elasticsearch

### ElastAlert Rule Configuration
- Created detection rules for:
  - File creation in the Startup folder
  - Process execution using Sysmon event IDs

## 👁️ What Was Observed in the Logs

✅ **Sysmon and Winlogbeat logs captured:**
- **Event ID 11** – File creation event in the Startup folder
- **Event ID 1** – Process creation event when `evil.exe` is executed on reboot

### Example Log Entry for File Creation (Event ID 11)
```json
{
  "@timestamp": "2025-05-24T15:05:00Z",
  "event.code": "11",
  "event.provider": "Microsoft-Windows-Sysmon",
  "winlog.event_id": 11,
  "message": "File created in Startup folder: C:\\Users\\Username\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe"
}
```

### Example Log Entry for Process Creation (Event ID 1)
```json
{
  "@timestamp": "2025-05-24T15:05:00Z",
  "event.code": "1",
  "event.provider": "Microsoft-Windows-Sysmon",
  "winlog.event_id": 1,
  "message": "Process created: evil.exe"
}
```

## 🧠 How SIEM Flagged the Event

✔️ **ElastAlert triggered alerts when:**
- A file was created in the Startup folder (Event ID 11)
- The file was executed on system reboot (Event ID 1)

### Alert Details
- **Rule Name**: Persistence Mechanism Detection
- **Event IDs**: 11 (File Creation), 1 (Process Creation)
- **Description**: A file was copied to the Startup folder and executed, indicating a potential persistence mechanism

## 📊 Data Source Mapping Table

| Log Source | Event Type      | Event ID | Description                    |
|-----------|----------------|----------|--------------------------------|
| Sysmon    | File Creation  | 11       | Logs file creation events      |
| Sysmon    | Process Creation| 1        | Logs process creation events   |
| Winlogbeat| Log Forwarding | -        | Forwards all events to Elasticsearch |

## 📩 Sample Alert

![Screenshot 2025-05-24 203525](https://github.com/user-attachments/assets/97363d68-c094-4262-b6be-1d14b8cd145c)



## 🛡️ Analyst Action on Alert

✅ **Actions Taken:**
- Verified the file creation and process execution events in Kibana Discover
- Correlated the file path and process details to confirm the persistence mechanism
- Investigated the associated process and user context for signs of malicious behavior

## ⚠️ Possible False Positives

| Scenario | Description |
|----------|-------------|
| **Legitimate Software** | Some applications may legitimately place files in the Startup folder |
| **IT Automation** | Deployment scripts or installation processes might add startup entries |
| **User Customization** | Users might manually add programs to start on login |
| **Software Updaters** | Auto-updaters might modify startup configurations |
| **Endpoint Management** | Managed endpoint tools may configure startup items for management |

## 📋 Recommendations

1. **Whitelist Trusted Software**: Identify and whitelist known safe software that uses the Startup folder
2. **Contextual Analysis**: Combine file creation events with process telemetry and user identity
3. **Behavioral Correlation**: Match file creation in the Startup folder with other suspicious activities
4. **Rule Tuning**: Continuously update detection rules based on observed false positives
5. **UEBA Integration**: Implement User and Entity Behavior Analytics to flag anomalies

## ✅ Detection Status

**Successfully Triggered:**
- Sysmon logged the file creation in the Startup folder (Event ID 11) and process execution (Event ID 1)
- ElastAlert sent an email alert to the specified recipient
