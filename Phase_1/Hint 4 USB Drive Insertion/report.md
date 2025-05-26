## 🚨 USB Device and Process Creation Detection

### 📌 Objective
Detect suspicious USB device activity and process creation events on the target Windows VM using Sysmon, Winlogbeat, Elasticsearch, Kibana, and ElastAlert.

---

### 🧪 What Was Done

1. Simulated USB device activity by:
   - Inserting a USB removable drive.
   - Creating and deleting files on the USB device to trigger Sysmon Event ID 11 (File Creation).
2. Simulated process creation events by:
   - Running PowerShell scripts, batch files (`.bat`), and other executables.
## 🔥 Example Script:
    @echo off
    echo This is a dummy executable file for testing purposes.
    pause
4. Configured Sysmon to log:
   - Event ID 11 for file creation on USB/removable drives.
   - Event ID 1 for process creation.
   - Event ID 2106 for USB connected.
   - Event ID 1008 for USB Disconnected.
5. Winlogbeat was set up to forward these events to Elasticsearch.
6. ElastAlert configured rules to detect:
   - USB file creation activity.
   - Suspicious process creation events related to PowerShell, `.bat` files, etc.

---

### 👁️ What Was Observed in the Logs

✅ Sysmon and Winlogbeat logs showed:

- **Event ID 11** – File creation events corresponding to USB file writes. 📂🔌
- **Event ID 1** – Process creation events for PowerShell, batch files, and other monitored executables. 🏃‍♂️⚙️

---

### 🧠 How SIEM Flagged the Event

✔️ ElastAlert rules triggered alerts when:

- New file creation events on removable drives were detected.
- Suspicious process creations (e.g., `powershell.exe`, `.bat` files) occurred.
- Alerts aggregated multiple events within defined time windows to reduce noise.

📨 Email alerts were sent to the security team for timely investigation.

---

## 📊 Data Source Mapping

| Log Source     | Event Type       | Event ID | Description                              |
|----------------|------------------|----------|------------------------------------------|
| Sysmon         | File Creation    | 11       | USB/removable drive file creation events |
| Sysmon         | Process Creation | 1        | Execution of monitored processes         |
| Winlogbeat     | Log Forwarding   | -        | Forwarded all events to Elasticsearch    |
| Event Viwer    | USB Connection   | 2106     | Successful Connection of USB             |
| Event Viwer    | USB Connection   | 1008     | Successful Disconnection of USB          |
## 📩 Sample Alert 

![Screenshot 2025-05-23 190541](https://github.com/user-attachments/assets/8d3548c2-69a5-4966-897e-adaa9a47da19)


### 🛡️ Analyst Action on Alert

- ✅ Verified alerts in ElastAlert logs.
- ✅ Correlated event IDs, file paths, and process details in Kibana Discover.
- ✅ Confirmed USB insertion time and corresponding file creation events.
- ✅ Investigated suspicious process creation events for potential malware or misuse.

---

### ⚠️ Possible False Positives

| 🧩 Impact Area          | 📌 Description                                                           |
|-------------------------|-------------------------------------------------------------------------|
| 🔔 Alert Fatigue        | Frequent safe USB insertions causing alert overload.                    |
| ⏱ Time Waste            | Benign process executions triggering alerts unnecessarily.             |
| 😕 Desensitization       | Real USB attacks may be missed due to repeated benign alerts.          |
| 🔍 Analytical Bias      | Ignoring USB alerts assuming they are always benign.                    |
| 📉 Reduced Trust        | In alerting system due to false positives or noisy rules.               |

🛠️ **Recommendation:** Whitelist trusted USB devices and known safe processes to tune detection sensitivity.

---

### 🧪 Detection Status

**✅ Successfully Triggered**

📬 ElastAlert sent timely email alerts on USB activity and suspicious process creation.

---

