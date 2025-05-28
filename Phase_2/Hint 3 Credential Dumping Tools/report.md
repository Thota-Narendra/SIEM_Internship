
# Hint 3: Credential Dumping – Detection via LaZagne

## 🎯 Objective
Simulate a credential dumping attack using the LaZagne tool and observe system-level logs and EDR/AV reactions. Analyze which logs can help detect this kind of activity.

---

## 🛠️ Tool Used
**Tool:** [LaZagne](https://github.com/AlessandroZ/LaZagne)  
**Purpose:** Extract stored credentials from browsers, Wi-Fi, Vault, and other Windows services.

---

## 🖥️ Lab Setup

- **Victim Machine:** Windows 10 Home Edition (VM)
- **Monitoring Tools:**
  - Sysmon
  - Winlogbeat
  - Elasticsearch + Kibana
- **Log Forwarding:** Winlogbeat sends Windows Event Logs and Sysmon logs to Elasticsearch.

---

## 🧪 Steps Performed

1. Downloaded and extracted `lazagne.exe` on the Windows VM.
2. Ran the tool using:
   ```bash
   lazagne.exe all
   ```
3. Observed credential extraction from:
   - Browsers (Chrome, Firefox)
   - Windows Credential Manager
   - Wi-Fi passwords
4. Collected logs in Kibana for analysis.

---

## 📄 Logs Generated

### ✅ Sysmon Logs

| Event ID | Description                   |
|----------|-------------------------------|
| **1**    | `lazagne.exe` process creation |
| **11**   | File creation (dump output file) |

### ✅ Windows Security Logs

| Event ID | Description                                                       |
|----------|-------------------------------------------------------------------|
| **4672** | Special privileges assigned (e.g., SeDebugPrivilege)              |
| **5379** | Credential Manager credentials were **read**                      |
| **5381** | Credential Manager credentials were **written** (uncommon)        |

---

## 🛡️ EDR/AV Reaction

- **Microsoft Defender:** Often flags LaZagne as a potentially unwanted program (PUP) or malware.
- **Behavioral Detection:** EDR solutions detect LaZagne activity based on:
  - Suspicious process creation (like `lazagne.exe`)
  - Access to credential stores (Credential Manager, browsers)
  - Attempts to read memory or protected files
- **Signature Detection:** Known binaries or file hashes are blacklisted.
- **In Memory Monitoring:** Some EDRs monitor API calls or memory access to detect credential harvesting behavior.

---

## 🔍 Detection Insights

### What system-level logs help detect credential access attempts?

- **Sysmon:**
  - **Event ID 1:** Detects execution of credential dumping tools.
  - **Event ID 10:** (if configured) Detects access to protected processes like LSASS.
  - **Event ID 11:** Logs when credential dump files are written to disk.

- **Windows Security Logs:**
  - **Event ID 4688:** Tracks process creation (e.g., `lazagne.exe` execution).
  - **Event ID 4672:** Indicates high-privilege access that may be needed for dumping credentials.
  - **Event ID 5379:** Logs read access to Windows Credential Manager.
  - **Event ID 5381:** Logs write access to Credential Manager.

These logs are crucial for detecting suspicious behavior associated with credential theft.

### ✅ Suggested KQL Query for Kibana:

```kql
event.code: "5379" or process.name: "lazagne.exe" or event.code: "4672"
```

---

## 📸 Sample Log

![alt text](<sample log.png>)


---
## 🚨 Analyst Action on Alert

- 🧪 Verify if the credential dumping tool (e.g., Mimikatz) was run interactively or by script.
- 🔍 Check the parent process (e.g., `cmd.exe`, `powershell.exe`).
- 📜 Review the logs for any suspicious activities (e.g., access to `lsass.exe`).
- 🔒 Block or isolate the user endpoint if needed.

---

## ⚠️ Possible False Positives

- 🧰 Admin scripts using obfuscated PowerShell or other scripting languages.
- 🔁 Automation tools invoking PowerShell or other command-line tools.
- 👨‍💼 Legitimate uses of tools for system administration or penetration testing.


## ✅ Detection Status

🎉 **Successfully Triggered**  