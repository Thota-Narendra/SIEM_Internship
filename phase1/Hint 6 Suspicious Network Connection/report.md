# 🚨 Suspicious Network Connection Detection

## 📌 Objective
Simulate a network connection to `http://testphp.vulnweb.com` and detect related events using Sysmon, Winlogbeat, Elasticsearch, and Kibana.

---

## 🧪 What Was Done

1. **Simulated Network Connection**:
   - Used PowerShell to make a web request to `http://testphp.vulnweb.com`.
   - Command used:
     ```powershell
     Invoke-WebRequest -Uri "http://testphp.vulnweb.com"
     ```

2. **Sysmon Configuration**:
   - Ensured Sysmon was configured to log network connection events (**Event ID 3**).

3. **Winlogbeat Setup**:
   - Configured to forward Sysmon logs to **Elasticsearch**.

4. **Kibana Monitoring**:
   - Used Kibana to monitor for **Sysmon Event ID 3**, filtering specifically for connections to `http://testphp.vulnweb.com`.

---

## 👁️ What Was Observed in the Logs

✅ **Sysmon and Winlogbeat logs** captured:

- **Event ID 3** – Network connection event.
- **Destination IP**: `172.104.149.86`.
- **Source IP**: `192.168.52.131`.
- **Process**: `powershell.exe`.

## 🧠 How SIEM Flagged the Event

✔️ **Detection workflow**:

- Sysmon captured the network connection event.
- Winlogbeat forwarded the log to Elasticsearch.
- Kibana was used to identify and analyze the network connection.

---

## 📊 Data Source Mapping

| Log Source | Event Type         | Event ID | Description                           |
|------------|--------------------|----------|---------------------------------------|
| Sysmon     | Network Connection | 3        | Logs network connections              |
| Winlogbeat | Log Forwarding     | -        | Forwarded all events to Elasticsearch |

---

## 📩 Sample Alert
![Screenshot 2025-05-24 135748](https://github.com/user-attachments/assets/6be65a09-771b-439e-b87b-f7ee06165625)



---

## 🛡️ Analyst Action on Alert

- ✅ Verified the network connection event in **Kibana Discover**.
- ✅ Correlated the destination IP and process details.
- ✅ Investigated the context of the connection for potential malicious activity.

---

## ⚠️ Possible False Positives

| 🧩 Scenario              | 📌 Description                                                                |
|--------------------------|------------------------------------------------------------------------------|
| **Legitimate Web Traffic**  | Normal web browsing or application traffic to the specified URL.            |
| **IT Automation Scripts**   | Scripts or automated tools accessing the URL as part of normal operations.  |
| **User Activity**           | Users accessing the URL for legitimate purposes.                            |
| **Software Updaters**       | Auto-updaters accessing the URL to check for updates.                       |
| **Background Services**     | Services or applications making periodic requests to the URL.               |

---

## 🛠️ Recommendations

- 🔍 **Whitelist Known Good Traffic**  
  Identify and whitelist known safe network destinations.

- 📚 **Context-Aware Detection**  
  Combine network connection events with other telemetry, such as process details or user identity.

- 📈 **Behavioral Correlation**  
  Match network connections with other suspicious activities, such as unusual process executions.

- 🔁 **Rule Tuning & Review**  
  Continuously update detection rules based on observed false positives and environment-specific patterns.

- 🤖 **UEBA Integration**  
  Implement User and Entity Behavior Analytics to flag anomalies beyond static rule-based alerts.

---

## 🧪 Detection Status

✅ **Successfully Triggered**  
- Sysmon logged the network connection event.  
- Event was successfully detected and visualized in Kibana.

