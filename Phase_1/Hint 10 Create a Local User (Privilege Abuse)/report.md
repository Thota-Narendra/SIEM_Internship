# 🚨 Local User Creation and Privilege Abuse Detection

## 📌 Objective
Detect the creation of a local user and addition to the administrators group using Sysmon, Winlogbeat, Elasticsearch, Kibana, and ElastAlert.

## 🧪 What Was Done

### Simulated Local User Creation and Privilege Abuse

**Created a new local user `attacker` with the password `P@ssword123`:**
```cmd
net user attacker P@ssword123 /add
```

**Added the user `attacker` to the administrators group:**
```cmd
net localgroup administrators attacker /add
```

### Sysmon Configuration
- Ensured Sysmon was configured to log security events related to user creation and group changes

### Winlogbeat Setup
- Configured to forward Windows Security logs to Elasticsearch

### ElastAlert Rule Configuration
- Created detection rules for user creation and group membership changes using Windows Event IDs

## 👁️ What Was Observed in the Logs

✅ **Windows Security logs captured:**
- **Event ID 4720** – A new user account was created
- **Event ID 4732** – A member was added to a security-enabled local group

### Example Log Entry for User Creation (Event ID 4720)
```json
{
  "@timestamp": "2025-05-24T15:30:00Z",
  "event.code": "4720",
  "event.provider": "Microsoft-Windows-Security-Auditing",
  "winlog.event_id": 4720,
  "message": "A new user account was created."
}
```

### Example Log Entry for Group Membership Change (Event ID 4732)
```json
{
  "@timestamp": "2025-05-24T15:35:00Z",
  "event.code": "4732",
  "event.provider": "Microsoft-Windows-Security-Auditing",
  "winlog.event_id": 4732,
  "message": "A member was added to a security-enabled local group."
}
```

## 🧠 How SIEM Flagged the Event

✔️ **ElastAlert triggered alerts when:**
- A new user was created (Event ID 4720)
- The user was added to the administrators group (Event ID 4732)

### Alert Details
- **Rule Name**: Local User Creation and Privilege Abuse
- **Event IDs**: 4720 (User Creation), 4732 (Group Membership Change)
- **Description**: A new local user was created and added to the administrators group, indicating potential privilege abuse

## 📊 Data Source Mapping

| Log Source | Event Type | Event ID | Description |
|-----------|-----------|----------|-------------|
| Windows Security | User Creation | 4720 | Logs the creation of new user accounts |
| Windows Security | Group Membership Change | 4732 | Logs changes to security group memberships |
| Winlogbeat | Log Forwarding | - | Forwards all events to Elasticsearch |

## 📩 Sample Alert
![Screenshot 2025-05-24 211704](https://github.com/user-attachments/assets/1b7f7ca9-182a-4102-a493-2361c40570b4)


## 🛡️ Analyst Action on Alert

✅ **Actions Taken:**
- Verified the user creation and group membership change events in Kibana Discover
- Correlated the events to confirm the user was added to the administrators group
- Investigated the associated process and user context for signs of malicious behavior

## ⚠️ Possible False Positives

| Scenario | Description |
|----------|-------------|
| **Legitimate User Management** | Administrators creating new user accounts or modifying group memberships |
| **IT Automation** | Automated scripts or processes that manage user accounts and permissions |
| **Service Accounts** | Creation of service accounts for applications or services |
| **User Provisioning** | HR or helpdesk activities involving user onboarding |
| **Testing/Development** | Activities in non-production environments that mimic real user management |

## 📋 Recommendations

1. **Whitelist Trusted Activities**: Identify and whitelist known user management activities by administrators or automated systems
2. **Contextual Analysis**: Analyze the context of user creation and group changes, including the source IP and user account used
3. **Regular Rule Tuning**: Update detection rules based on observed false positives to reduce noise
4. **Implement Multi-Factor Authentication (MFA)**: Require MFA for privileged accounts to prevent unauthorized access
5. **Least Privilege Principle**: Ensure users and services operate with the minimum level of privilege necessary

## ✅ Detection Status

**Successfully Triggered:**
- Windows Security logs recorded the user creation (Event ID 4720) and group membership change (Event ID 4732)
- ElastAlert sent an email alert to the specified recipient
