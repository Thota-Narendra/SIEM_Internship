# SOC Testing Lab Setup Guide

This guide walks you through building a mini SOC lab with one Windows "target" VM and one Linux "monitor" VM running your SIEM stack. Use this as your `README.md` in your GitHub repo.

---

## 🏗️ Lab Architecture

```
+----------------+       +----------------+
|  Windows 10 VM |       |   Kali Linux   |
| (Target Host)  |──────▶| (SIEM & Beats) |
|                |       |                |
+----------------+       +----------------+
        ▲                        ▲
        │                        │
        │ Sysmon & Winlogbeat    │ Elastic Stack & ElastAlert
        │ (Event collection)     │ (Storage, Analysis, Alerting)
        ▼                        ▼
   Event Logs            Alerts & Dashboards
```

---

## 📋 Prerequisites

- **💻 Hardware**  
  - 8 GB RAM minimum, 4 cores CPU  
  - 50 GB free disk space  

- **💿 Software**  
  - VirtualBox or VMware Workstation Player  
  - Windows 10 ISO or prebuilt VM  
  - Kali Linux ISO or prebuilt VM  

- **🌐 Network**  
  - Host-only or bridged network so both VMs can communicate  

---

## 💻 Step 1: Deploy VMs

1. **🪟 Windows 10 VM**  
   - Create a new VM, assign 2 vCPU, 4 GB RAM.  
   - Install Windows 10.  
   - Enable **Administrator** account.  

2. **🐉 Kali Linux VM**  
   - Create a new VM, assign 2 vCPU, 4 GB RAM.  
   - Install Kali Linux.  

3. **🌐 Network Settings**  
   - Use **Host-only Adapter** on both VMs (e.g. 192.168.56.0/24).  
   - Ensure they can ping each other.

---

## 🗄️ Step 2: Install & Configure Sysmon + Winlogbeat (Windows VM)

1. **📥 Download Sysmon & Config**  
   - Get from Microsoft Sysinternals:  
     https://docs.microsoft.com/sysinternals/downloads/sysmon  
   - Use a community XML config (e.g. SwiftOnSecurity).  

2. **🔧 Install Sysmon**  
   ```powershell
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```

3. **📥 Download Winlogbeat**  
   https://www.elastic.co/downloads/beats/winlogbeat

4. **⚙️ Configure winlogbeat.yml**  
   ```yaml
   winlogbeat.event_logs:
     - name: Microsoft-Windows-Sysmon/Operational
     - name: Security
   output.elasticsearch:
     hosts: ["http://<KALI_IP>:9200"]
   ```

5. **🚀 Install & Start Winlogbeat**  
   ```powershell
   .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   ```

---

## 🛢️ Step 3: Install ELK Stack (Kali Linux VM)

1. **☕ Install Java**  
   ```bash
   sudo apt update
   sudo apt install openjdk-11-jdk -y
   ```

2. **🔍 Install Elasticsearch**  
   ```bash
   wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.10.2-amd64.deb
   sudo dpkg -i elasticsearch-8.10.2-amd64.deb
   sudo systemctl enable --now elasticsearch
   ```

3. **📊 Install Kibana**  
   ```bash
   wget https://artifacts.elastic.co/downloads/kibana/kibana-8.10.2-amd64.deb
   sudo dpkg -i kibana-8.10.2-amd64.deb
   sudo systemctl enable --now kibana
   ```

4. **⚙️ Configure Elasticsearch & Kibana**  
   Edit `/etc/elasticsearch/elasticsearch.yml` and `/etc/kibana/kibana.yml` to set `network.host: 0.0.0.0`.
   
   🔄 Restart services.

---

## 📊 Step 4: Install & Configure ElastAlert

1. **🐍 Install Python & Pip**  
   ```bash
   sudo apt install python3-pip -y
   pip3 install elastalert
   ```

2. **📝 Create Config (config.yaml)**  
   ```yaml
   es_host: 127.0.0.1
   es_port: 9200
   rules_folder: rules
   run_every:
     minutes: 1
   buffer_time:
     minutes: 15
   writeback_index: elastalert_status
   alert_time_limit:
     days: 2
   ```

3. **📏 Write a Sample Rule (rules/sample_rule.yaml)**  
   ```yaml
   name: Brute Force Attempt
   type: frequency
   index: winlogbeat-*
   num_events: 10
   timeframe:
     minutes: 5
   filter:
     - term:
         event.code: "4625"
   alert:
     - "email"
   email:
     - "youremail@domain.com"
   ```

4. **🚀 Run ElastAlert**  
   ```bash
   elastalert --config config.yaml
   ```

---

## 📖 Step 5: Test & Validate

### 🎯 Simulate Events on Windows VM

1. **🔓 Brute force:**  
   ```powershell
   for ($i=1; $i -le 10; $i++) {
     net use \\localhost\IPC$ /user:FakeUser WrongPass
   }
   ```

2. **🦠 Malware simulation:**  
   ```powershell
   @echo off > C:\Temp\malware.bat
   echo ping 8.8.8.8 -n 5 >> C:\Temp\malware.bat
   C:\Temp\malware.bat
   ```

3. **🔄 Persistence:**  
   ```powershell
   Copy-Item C:\Temp\evil.exe `
     "$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"
   Restart-Computer
   ```

### 🔍 Verify in Kibana Discover

Use KQL queries like `event.code: 4625`, `event.code: 1`, `event.code: 11`.

### 🚨 Watch for Alerts

Check the ElastAlert console for triggered rules.
