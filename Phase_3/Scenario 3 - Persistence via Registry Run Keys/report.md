# 💻 Task: Persistence via Registry Run Keys (MITRE T1547.001)

---

## 📝 Scenario Summary

This simulation demonstrates **persistence** via the Windows Registry "Run" key. A batch script simulating malicious activity is added to the registry under the `HKCU` hive, ensuring it executes on every user login.

This tactic is commonly used by malware to maintain access to a system after reboot.

---

## 🧪 Lab Setup

* **Attacker VM**: Kali Linux (for monitoring if needed)
* **Victim VM**: Windows 10 Home/Pro Edition
* **Log Forwarding**: Sysmon + Winlogbeat → Elasticsearch → Kibana

---

## 🔧 Tools Used

* **Registry Editor / reg.exe / PowerShell**
* **Sysmon** (Event ID 13 – Registry Modification)
* **Winlogbeat** (Windows Event Logs)
* **Kibana** (log visualization)

---

## 🔥 Execution Steps

### Step 1: Create the Payload

Create a basic batch script as a placeholder payload.

```bat
:: evil.bat
@echo off
start notepad.exe
```

Save it to: `C:\Temp\evil.bat`

### Step 2: Add Persistence via Registry

**CMD Command:**

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v FakeUpdater /t REG_SZ /d "C:\Temp\evil.bat" /f
```

### Step 3: Reboot the System

After restart, `notepad.exe` will run automatically as a sign of successful persistence.

---

## 📊 Detection Strategy

### Relevant Event IDs

| Event ID | Description                 | Source       |
| -------- | --------------------------- | ------------ |
| 13       | Registry value set (Sysmon) | Sysmon       |
| 4688     | New process created         | Security Log |

### Kibana Query Examples

```kql
(event.code:13 AND registry.path:*\Run AND registry.value:*evil.bat)
```

---

## 📸 Kibana Screenshot Placeholder
![alt text](<sample log.png>)

---

## 🔐 Mitigation Recommendations

* Monitor changes to `HKCU\...\Run` and `HKLM\...\Run` registry keys
* Use AppLocker or WDAC to block batch/script files from executing from unusual paths
* Restrict user permissions to registry keys where possible

---

## ⚠️ Possible False Positives

* Legitimate applications that add themselves to startup via registry
* Software updaters (e.g., Chrome, Adobe)
* Whitelist known trusted paths and file hashes

---

## ✅ Detection Validated

| Field                 | Value       |
| --------------------- | ----------- |
| Detection Working     | ✅ Yes       |
| Sysmon Logging        | ✅ Enabled   |
| Log Forwarding Active | ✅ Confirmed |
| Visibility in Kibana  | ✅ Confirmed |

---

## 🧠 MITRE Mapping

* **Technique ID**: T1547.001
* **Tactic**: Persistence
* **Sub-technique**: Registry Run Keys / Startup Folder
