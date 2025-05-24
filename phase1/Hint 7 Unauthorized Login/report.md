# Unauthorized Access Attempt (Outside Business Hours)

## 🎯 Detection Objective
Detect successful or failed logins **outside defined business hours (9:00 AM to 7:00 PM IST)**, especially those involving **admin or privileged user accounts**, using Windows Security Event Logs and ElastAlert.

---

## 🛠️ Tools Used

- **SIEM Stack**: Elasticsearch, Kibana  
- **Log Forwarder**: Winlogbeat  
- **Monitoring Tool**: ElastAlert  
- **Target OS**: Windows 10 (Victim VM)  
- **Attack Source**: Internal system (simulated off-hours access)

---

## 🧪 Lab Setup

1. **Winlogbeat** installed on the victim Windows machine to forward logs to Elasticsearch.
2. **Elasticsearch** and **Kibana** are installed and configured on the monitoring machine.
3. **ElastAlert** is used to create custom rules and send alert emails.
4. Business hours were defined from **9:00 AM to 7:00 PM IST (UTC+5:30)**.
5. Rule triggers when a **4624 (successful login)** is recorded **outside** the defined hours by an **admin account**.

---

## 🔎 Detection Logic

ElastAlert rule detects:
- **Successful login (Event ID 4624)**  
- **Outside 9:00 AM to 7:00 PM IST**
- **From an admin or sensitive user account**
- Alert is triggered immediately

---

## 📜 Sample ElastAlert Rule

```yaml
name: unauthorized_login_outside_business_hours_admin_users
type: any
index: winlogbeat-*

num_events: 1
timeframe:
  minutes: 5

filter:
  - term:
      event.code: "4624"
  - bool:
      must_not:
        - range:
            "@timestamp":
              gte: "now/d+3h"
              lt: "now/d+14h"
  - terms:
      winlog.event_data.TargetUserName:
        - "Administrator"
        - "AdminUser1"
        - "DomainAdmin"
        - <your_adminname>
  - match_phrase:
      host.name: <"Your_hostname">

query_key: winlog.event_data.IpAddress

alert:
  - email

email:
  - <your_email@gmail.com>

alert_subject: "Unauthorized Admin Login Attempt After Hours from {0}"
alert_text: |
  Detected successful login for a privileged account outside business hours.
  User: {3}
  Source IP: {0}
  Time: {1}
  Host: {2}

alert_text_args:
  - winlog.event_data.IpAddress
  - "@timestamp"
  - "host.name"
  - "winlog.event_data.TargetUserName"
```

> ✅ Note: The timestamp range in the rule accounts for IST (UTC+5:30) by converting 9:00–19:00 IST to 3:00–14:00 UTC.

---
## Kibana Detection Query:
    event.code: "4624" AND 
    (winlog.event_data.TargetUserName: ("Administrator" OR "AdminUser1" OR "DomainAdmin" OR "BackupOperator")) AND 
    NOT @timestamp >= now/d+9h AND 
    @timestamp < now/d+19h


## 📊 Data Source Mapping

| Source      | Event ID | Description                             |
|-------------|----------|-----------------------------------------|
| Winlogbeat  | 4624     | Successful logon                        |
| Winlogbeat  | 4625     | Failed logon (used for correlation)     |
| Winlogbeat  | 4672     | Special privileges assigned (optional)  |

---

## 📸 Sample Alert Screenshot
![not_business@email](https://github.com/user-attachments/assets/bebc09e9-ee43-4e73-a635-6dbfcf29daf0)


---

## ✅ Detection Status

**Successfully Triggered** using an off-hours login test. Alert was delivered to the configured email via Gmail SMTP.

---

## 🛡️ Recommendation

### Analyst Actions
- Review login time and account details.
- Cross-check with legitimate user behavior and working hours.
- Investigate further if login came from unusual IP or location.
- Consider enforcing MFA for admin accounts.

### Possible False Positives
- Scheduled admin tasks after hours.
- Maintenance or remote support login windows.
- Users in different time zones.

---

## 🧠 Tip
To enhance detection, consider tagging users with AD group membership and correlating with `Event ID 4672` to ensure privileged access is truly happening.
