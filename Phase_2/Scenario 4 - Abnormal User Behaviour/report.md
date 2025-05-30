
# 🧠 Use Case: Abnormal User Behavior / Account Compromise (MITRE T1078)

---

## 📖 Scenario Summary
This simulation emulates suspicious insider behavior or a compromised account scenario. A valid domain user (or local user in our case) logs in during **non-business hours** and performs **bulk file access or copying** within a short time span (e.g., 100+ files in 10 minutes). This is often indicative of exfiltration or reconnaissance activity.

---
### 🖥️ Environment Setup
- **Attacker**: Windows 10 Home (Host)
- **Target**: Windows 10 Home (Victim)
- **Username**: `testuser`
- **Monitored Folder**: `C:\SensitiveFiles`
- **Monitoring Tools**: Sysmon, Winlogbeat, Elasticsearch, Kibana

### 👻 Attacker Mindmap
![image](https://github.com/user-attachments/assets/63b61896-85dd-410f-9206-c08010e5ab54)


### 🛠️ Attack Execution

1. **Log in to the target system** as `testuser` during off-hours (e.g., 2 AM).

2. **Simulate file access burst**:
   ```powershell
   for ($i=1; $i -le 120; $i++) {
       Copy-Item "C:\SensitiveFiles\file$i.txt" "C:\Users\Public\file$i.txt"
   }
   ```
   This generates multiple file access events quickly.

3. Let Sysmon and Winlogbeat forward the logs to Elasticsearch.

---

## 📊 Event IDs & Data Sources

| Event ID | Description                       | Source            |
|----------|-----------------------------------|-------------------|
| 4624     | Successful Logon                  | Windows Security  |
| 11       | File Created (access simulation)  | Sysmon            |
| 23       | File Deleted (optional)           | Sysmon            |

---

## 🔍 Detection Logic

- ✅ **4624**: Logon with **LogonType: 2 or 3** during **non-business hours**
- ✅ **Sysmon 11**: File creation burst (e.g., > 50 files in <10 minutes)

### 📌 KQL Example Queries

**Logon Detection (off-hours):**
```kql
event.code:4624 AND user.name:"testuser" AND winlog.event_data.LogonType:(2 OR 3)
```

**File Access Burst:**
```kql
event.code:11 AND file.path:"*SensitiveFiles*"
```

---

## 🧪 Sample Logs / IOCs

### ✅ Event ID 4624:
```
Account Name: testuser
Logon Type: 3
Time: 02:15 AM
```

### ✅ Sysmon ID 11:
```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\SensitiveFiles\file52.txt
UtcTime: 2025-05-29T02:18:41.000Z
```

---

## 📸 Screenshot
![alt text](<sample log.png>)

---

## 🛡️ Recommendations
- 🚨 Set thresholds for abnormal file access per user
- ⏰ Correlate with off-hours activity
- 🧠 Review accounts with admin rights showing odd patterns

---

## ⚠️ False Positives

| Scenario              | Explanation                          |
|----------------------|--------------------------------------|
| IT Admin after hours | Legit work but outside business time |
| Backup software      | May trigger similar file activity    |

---

## ✅ Detection Status

| Field             | Value               |
|------------------|---------------------|
| Detection Tested | ✅ Yes              |
| Environment      | Windows 10 Home     |
| Tools Used       | Sysmon, Winlogbeat  |
| Alerts Triggered | ✅ 4624, Sysmon 11  |

---
