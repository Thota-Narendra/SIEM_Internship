# 🛡️ Use Case: Lateral Movement via RDP Brute Force (MITRE T1110 / T1021.001)

---

## 📘 Scenario Summary

This simulation demonstrates a **lateral movement attack via RDP brute force** from an attacker machine (Kali Linux) to a **Windows 10 Pro** target machine. The attacker uses **stolen credentials** to perform brute-force login attempts against RDP, aiming to compromise and laterally move across systems in the network.

The goal is to detect repeated failed logons (Event ID 4625), followed by a successful logon (Event ID 4624) using RDP (Logon Type 10).

---

## 🧪 Attack Setup

### 🔧 Tools Used

* `hydra` for RDP brute-force
* `xfreerdp` – to manually test valid RDP credentials
* Windows Event Logs (Security)
* Winlogbeat + Elasticsearch + Kibana stack for log visibility

---

## 🔥 Attack Steps

### ✅ Step 1: Prepare Target (Windows 10 Pro)

* Enable RDP:

  ```
  System > Remote Desktop > Enable Remote Desktop
  ```
* Create a local low-privileged user:

  ```cmd
  net user testuser Pass@123 /add
  ```

### ✅ Step 2: Run Brute Force Attack (Kali)

Using `hydra`:

```bash
hydra -t 4 -V -f -l testuser -P passwords.txt rdp://<viticm.ip>
```


---

## 📊 Event IDs & Detection Points

| Event ID | Description                   | Source                  |
| -------- | ----------------------------- | ----------------------- |
| `4625`   | Failed logon (wrong password) | Windows Security Log    |
| `4624`   | Successful logon              | Windows Security Log    |
| `10`     | Logon type for RDP session    | Part of 4624 event data |
| `3`      | Sysmon network connection     | Sysmon (Event ID 3)     |

---

## 🔍 Detection Logic

* **Multiple 4625 events from same IP** in short span (threshold: 5+ failures)
* Followed by a **4624** event from same IP with **Logon Type 10**
* Correlate with Sysmon Event ID 3 (network connection to port 3389)

### Sample Kibana Query

```json
(event.code:"4625" AND winlog.event_data.IpAddress:"192.168.29.17")
OR
(event.code:"4624" AND winlog.event_data.LogonType:"10")
```

---

## 📈 Sample Logs

**Failed Logon (4625):**
```json
{
  "event.code": "4625",
  "winlog.event_data.TargetUserName": "testuser",
  "winlog.event_data.IpAddress": "192.168.29.17"
}
```

**Successful RDP Logon (4624):**

```json
{
  "event.code": "4624",
  "winlog.event_data.LogonType": "10",
  "winlog.event_data.TargetUserName": "testuser"
}
```
---

## 🛡️ Recommendations

* Enable account lockout policy after N failed logon attempts
* Monitor RDP connections from unusual IPs or off-hours logons
* Use firewall rules to limit RDP access
* Deploy MFA for RDP logins where possible

---

## ⚠️ False Positives

* Remote helpdesk tools using RDP
* Legitimate remote access by IT staff


## 📊 Status

| Field               | Value                 |
| ------------------- | --------------------- |
| 🔬 Detection Tested | ✅ Yes                 |
| 🧪 Detection Logic  | ✅ Working             |
| 🔄 Simulation Type  | Brute Force via RDP   |
| 📆 Data Visibility  | ✅ Confirmed in Kibana |
| 🛠️ Platform        | Windows 10 Pro        |
