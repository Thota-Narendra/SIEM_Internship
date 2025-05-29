
# 🐍 Malicious PowerShell Execution Detection

## 🎯 Detection Objective

🔎 Detect encoded PowerShell commands or PowerShell executions originating from Office applications like `winword.exe`.

## 🛠 Tools Used

- 🧠 **SIEM Stack**: Elasticsearch, Kibana  
- 📦 **Log Shippers**: Winlogbeat, Sysmon  
- 🛡 **Detection Engine**: ElastAlert (optional)  
- 🧪 **Simulation Tool**: PowerShell, VBScript  

## 🧪 Task Execution Steps

### ⚙️ Simulation on Target Windows VM

#### 1️⃣ Simulate Encoded PowerShell Command Execution

📂 Open **PowerShell as Administrator** and run:

```powershell
powershell.exe -EncodedCommand SQBFAFgALQBTAGUAYwB1AHIAaQB0AHkA
```

💡 *This decodes to `IEX-Security`, a harmless string used to simulate malicious behavior.*

---

#### 2️⃣ Simulate PowerShell Spawned from Office-like Script

📄 Create and run a `.vbs` script to mimic an Office macro:

```vbscript
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgALQBTAGUAYwB1AHIAaQB0AHkA"
```

💾 Save it as simulate_macro.vbs and double-click to execute.

🧩 This simulates behavior like winword.exe → powershell.exe.

---

## 🔍 What Gets Logged

- 🛠 **Sysmon Event ID 1** — Process Creation (logs full PowerShell command and parent process)
- 📘 **Windows PowerShell Event ID 4104** — Script Block Logging (logs decoded PowerShell script)

---

## 📁 Data Source Mapping

| 📚 Source           | 🧾 Event ID | 📌 Description                   |
|---------------------|-------------|----------------------------------|
| Sysmon              | 1           | Process creation (PowerShell)    |
| Windows PowerShell  | 4104        | Script block logging             |
---

## 🧠 Detection Logic (KQL Example in Kibana)

🔍 **Detect Encoded PowerShell Command:**

```kql
event.code:1 AND process.command_line:*EncodedCommand*
```

📂 **Detect PowerShell Launched by Office Apps:**

```kql
event.code:1 AND parent.process.name:(winword.exe OR wscript.exe) AND process.name:powershell.exe
```

🧾 **Detect Logged Script Blocks:**

```kql
event.code:4104 AND message:(IEX OR EncodedCommand OR FromBase64String)
```



## 📬 Log of PowerShell Execution

![alt text](<kibana capture.png>)



## 🚨 Analyst Action on Alert

- 🧪 Verify if PowerShell was run interactively or by script
- 🔍 Check the parent process (e.g., winword.exe)
- 📜 Review decoded script contents (Event ID 4104)
- 🔒 Block or isolate the user endpoint if needed

---

## ⚠️ Possible False Positives

- 🧰 Admin scripts using obfuscated PowerShell
- 🔁 Automation tools invoking PowerShell
- 👨‍💼 Legitimate uses of encoded PowerShell for DevOps/admin tasks

---

## ✅ Detection Status

🎉 **Successfully Triggered**  
Event logs appeared in Kibana:
- 🛠 Sysmon Event ID 1
- 📘 PowerShell Event ID 4104

---
