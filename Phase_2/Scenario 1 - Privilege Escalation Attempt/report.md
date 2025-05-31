
# 🛡️ Use Case: Privilege Escalation via Local Account (MITRE T1055 / T1547)

---

## 📘 Scenario Summary

This simulation demonstrates a local privilege escalation attack on a **Windows 10 Home Edition** system. The attacker creates a local user account and elevates its privileges by adding it to the **Administrators** group, either using an existing admin session or exploiting **UAC bypass** via `fodhelper.exe`.

This activity tests detection of suspicious user management and process creation events using **Sysmon**, **Winlogbeat**, and **Kibana**.

---

## 🧪 Attack Steps

### 🛠️ Tools Used

- `Sysmon` – Process Creation Logs (Event ID 1)
- `Winlogbeat` – Forwards Windows Event Logs
- `Elasticsearch + Kibana` – Log storage and search
- `Command Prompt`
- `fodhelper.exe` – UAC Bypass

---

### 🔥 Commands Executed

```cmd
:: 1. Create a new local user
net user pentester Pass@123 /add

:: 2. Add that user to Administrators group
net localgroup administrators pentester /add

:: 3. UAC bypass for privilege escalation
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /f
fodhelper.exe
```

---

## 📊 Event IDs & Data Sources

| 🧾 Event ID | Description                              | Data Source                   |
|------------|------------------------------------------|-------------------------------|
| `4720`     | A user account was created               | Windows Security Log (Winlogbeat) |
| `4732`     | User added to local Admin group          | Windows Security Log (Winlogbeat) |
| `4672`     | Privileged logon                         | Windows Security Log (Winlogbeat) |
| `4728`     | A user was added to a domain group       |  Windows Security Log (Winlogbeat) |
| `1`        | Process creation (e.g., net.exe, cmd)    | Sysmon (Sysmon Event ID 1)    |

---

## 🔍 Detection Logic

- Alert when a **non-default user** is created (`event.code:4720`)
- Alert when a **new user is added to the Administrators group** (`event.code:4732`)
- Correlate if `event.code:1` (net.exe or cmd.exe) precedes these events
- Trigger alerts when **net.exe** or **cmd.exe** are run by users not typically using CLI tools

---

## 📸 Screenshot (Kibana Dashboard)

📌 ![alt text](<Dashboard.png>)

---

## 🧾 Sample Logs / IOCs

**Security Event Log – 4720:**
```json
{
  "event.code": "4720",
  "winlog.event_data.TargetUserName": "pentester",
  "winlog.event_data.SubjectUserName": "attacker"
}
```

**Sysmon Event Log – ID 1 (net.exe):**
```json
{
  "event.code": 1,
  "process.name": "net.exe",
  "process.command_line": "net user pentester Pass@123 /add"
}
```

---

## 🛡️ Recommendations

- Restrict the use of `net.exe`, `cmd.exe`, and `powershell.exe` for non-admin users
- Enable **UAC Prompt for Admin Approval** for all elevation
- Monitor for sudden user creation + elevation to privileged groups
- Use `AppLocker` or `WDAC` to block UAC bypass vectors like `fodhelper.exe`

---

## ⚠️ Possible False Positives

- Legitimate IT administrators creating and managing accounts
- Automation or software that uses `net.exe` for scripted user creation

🔧 **Tuning Tips**:
- Whitelist known admin users
- Monitor off-hours activity or suspicious hosts

---

## 📌 Status

| Field               | Value             |
|--------------------|-------------------|
| 🔬 Detection Tested | ✅ Yes            |
| 🧪 Detection Logic  | ✅ Working        |
| 🔄 Simulation Type  | Manual + Optional UAC Bypass |
| 📦 Data Visibility  | ✅ Confirmed in Kibana |
| 🛠️ Platform         | Windows 10 Home   |

---

## ✅ Detection Validated In

- 🖥️ Windows 10 Home (target VM)
- 📈 Kibana (for log visibility)
- 🔄 Winlogbeat + Sysmon forwarding stack

---
## 👻 Attacker Mindmap

![attacker mindmap](https://github.com/user-attachments/assets/dec31829-dfda-4473-b1d1-964b04192693)

