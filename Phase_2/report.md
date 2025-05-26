# 📦 Suspicious ZIP or RAR File Downloads Detection

## 🎯 Detection Objective

Detect when users download suspicious archive files (.zip, .rar, .7z) using PowerShell or similar tools from external sources.

## 🛠 Tools Used

* **SIEM Stack**: Elasticsearch, Kibana
* **Log Shippers**: Winlogbeat, Sysmon
* **Detection Engine**: ElastAlert
* **Simulation Tool**: PowerShell

## 🧪 Task Execution Steps

### ⚙️ Simulation on Target Windows VM

1. **Run PowerShell as Administrator**
2. Execute the following command to simulate a suspicious download:

```powershell
Invoke-WebRequest -Uri "https://speed.hetzner.de/100MB.bin" -OutFile "$env:USERPROFILE\Downloads\evil.zip"
```

> Optionally, rename the file:

```powershell
Rename-Item "$env:USERPROFILE\Downloads\100MB.bin" "evil.zip"
```

3. This action triggers Sysmon Event ID **11 (File Creation)**.

## 🔍 What Gets Logged

* event.code: 11 (Sysmon - File Creation)
* process.name: powershell.exe
* file.name: evil.zip
* file.path: *\Downloads*

## 📁 Data Source Mapping

| Source     | Event ID | Description                   |
| ---------- | -------- | ----------------------------- |
| Sysmon     | 11       | File creation                 |
| Winlogbeat | 1 (opt)  | Process creation (PowerShell) |

## 🧠 Detection Logic (KQL Example in Kibana)

```kql
event.code: 11 AND file.name: (*.zip OR *.rar OR *.7z) AND process.name: powershell.exe
```

## 📬 Log of File Creation
![alt text](<Screenshot 2025-05-26 210236.png>)
```

## 🚨 Analyst Action on Alert

* Validate if the file was intentionally downloaded.
* Check user behavior and command-line arguments.
* Investigate the source IP/domain.
* Quarantine the file if necessary.

## ⚠️ Possible False Positives

* Download a ZIP file containing software updates from a trusted source.
* Use PowerShell to download or transfer ZIP files internally within the organization.
* Automated scripts that use PowerShell to download ZIP files as part of routine tasks.
* Download a ZIP file from a legitimate external source for personal or work-related purposes.
* Transfer ZIP files between different systems within the organization.

## ✅ Detection Status

**Successfully Triggered**

* Alert was sent via email
* Events appeared in Kibana (Event ID 11 with PowerShell)

---

