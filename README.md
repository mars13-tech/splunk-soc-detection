# Splunk SOC Lab: Brute Force & Lateral Movement Detection

## 🔐 Overview

This project demonstrates a real-world SOC (Security Operations Center) detection engineering lab using Splunk Enterprise. It simulates and detects:

* SSH brute force attacks on Linux (Ubuntu)
* Successful authentication after brute force
* Lateral movement into Windows systems
* Privilege escalation and suspicious process execution
* Full attack timeline correlation
* Automated alerting with email notifications
* SOC dashboard visualization

This project is designed to demonstrate Blue Team and SOC Analyst skills.

---

## 🏗️ Architecture

```text
Kali Linux (Attacker Simulation)
        ↓
Ubuntu VM (mars-VirtualBox)
        ↓ /var/log/auth.log
Windows Host (LAPTOP-7S5H8RIM)
        ↓ WinEventLog:Security
Splunk Enterprise (Running on Windows Host)
```

---

## 🖥️ Environment Details

| System       | Role                                    | Logs                |
| ------------ | --------------------------------------- | ------------------- |
| Kali Linux   | Attack Simulation                       | SSH Attempts        |
| Ubuntu VM    | Target System                           | /var/log/auth.log   |
| Windows Host | Splunk Server & Lateral Movement Target | Security Event Logs |

---

## 📊 Data Sources

### Ubuntu

* Log File: `/var/log/auth.log`
* Sourcetype: `auth`
* Index: `main`

### Windows

* Source: `WinEventLog:Security`
* Sourcetype: `WinEventLog:Security`
* Index: `main`

---

## ⚔️ Attack Scenario

### Phase 1 — SSH Brute Force

An attacker performs repeated SSH login attempts against the Ubuntu VM.

Detection Goal:

* Identify excessive failed SSH logins from the same source IP.

### Phase 2 — Successful Login

After multiple failed attempts, a successful login occurs.

Detection Goal:

* Detect failed logins followed by successful authentication.

### Phase 3 — Lateral Movement

The attacker accesses the Windows host after compromising Ubuntu.

Detection Goal:

* Detect Windows network logons.

### Phase 4 — Privilege Escalation

The attacker gains elevated privileges.

Detection Goal:

* Detect administrative privilege assignment.

### Phase 5 — Process Execution

The attacker executes tools and commands.

Detection Goal:

* Detect suspicious process creation activity.

---

## 🔍 Detection Queries

### 1. SSH Brute Force Detection

```spl
index=main host="mars-VirtualBox" "Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count by src
| where count > 10
```

### 2. Brute Force Success Detection

```spl
index=main host="mars-VirtualBox"
("Failed password" OR "Accepted password")
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| transaction src maxspan=10m
| search eventcount > 5 AND "Accepted password"
```

### 3. Windows Lateral Movement Detection

```spl
index=main host="LAPTOP-7S5H8RIM"
source="WinEventLog:Security"
EventCode=4624 Logon_Type=3
| stats count by Account_Name Source_Network_Address
```

### 4. Privilege Escalation Detection

```spl
index=main host="LAPTOP-7S5H8RIM"
source="WinEventLog:Security"
EventCode=4672
| stats count by Account_Name
```

### 5. Suspicious Process Execution Detection

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4688
| search Image="*cmd*" OR Image="*powershell*" OR Image="*psexec*"
| table _time Account_Name Image CommandLine
```

### 6. Full Attack Timeline Correlation

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| sort _time
| table _time host EventCode _raw
```

---

## 🚨 Alerts Configured

### Alert 1 — SSH Brute Force Detection

* Condition: Failed login count greater than 10
* Severity: High
* Action: Email Notification

### Alert 2 — Brute Force Success Detection

* Condition: Multiple failed logins followed by successful login
* Severity: Critical
* Action: Email Notification

### Alert 3 — Lateral Movement Detection

* Condition: Windows login, privilege assignment, and process execution activity
* Severity: Critical
* Action: Email Notification

---

## 📊 Dashboard Panels

### Panel 1 — SSH Brute Force Activity

**Visualization:** Line Chart

```spl
index=main host="mars-VirtualBox" "Failed password"
| timechart span=1m count
```

### Panel 2 — Top Attacking IP Addresses

**Visualization:** Bar Chart

```spl
index=main host="mars-VirtualBox" "Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| top src
```

### Panel 3 — Successful SSH Logins

**Visualization:** Line Chart

```spl
index=main host="mars-VirtualBox" "Accepted password"
| timechart count
```

### Panel 4 — Windows Logons

**Visualization:** Area Chart

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624
| timechart count
```

### Panel 5 — Privilege Escalation and Process Execution

**Visualization:** Column Chart

```spl
index=main host="LAPTOP-7S5H8RIM"
(EventCode=4672 OR EventCode=4688)
| timechart count
```

### Panel 6 — Attack Timeline

**Visualization:** Table

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| table _time host EventCode _raw
| sort _time
```

---

## 🧠 Skills Demonstrated

* SIEM Administration
* Splunk Enterprise
* Detection Engineering
* Log Analysis
* Security Monitoring
* Threat Hunting
* Alert Engineering
* Windows Security Monitoring
* Linux Security Monitoring
* Incident Investigation
* Event Correlation
* Dashboard Development

---

## 🔥 Project Outcome

This project demonstrates a complete SOC workflow:

1. Attack Simulation
2. Log Collection
3. Detection Creation
4. Correlation Search Development
5. Alert Generation
6. Email Notification
7. Dashboard Visualization
8. Incident Investigation

---

## 📚 MITRE ATT&CK Mapping

| Attack Stage         | Technique                                     |
| -------------------- | --------------------------------------------- |
| SSH Brute Force      | T1110 - Brute Force                           |
| Successful Login     | T1078 - Valid Accounts                        |
| Lateral Movement     | T1021 - Remote Services                       |
| Privilege Escalation | T1068 - Exploitation for Privilege Escalation |
| Process Execution    | T1059 - Command and Scripting Interpreter     |

---

## 👨‍💻 Author

Blue Team SOC Lab Project

Built using Splunk Enterprise, Ubuntu Linux, Windows Security Logs, and Blue Team Detection Engineering methodologies.
