# Splunk SOC Detection — Brute Force and Lateral Movement

**Author:** Karthikeyan  
**Target Role:** SOC Analyst (Blue Team)  
**Platform:** Splunk Enterprise  
**Environment:** Kali Linux · Ubuntu VM · Windows Host  
**Status:** Complete  
🔗 [LinkedIn](https://www.linkedin.com/in/karthi-keyan-9042862bb) · 🐙 [GitHub](https://github.com/mars13-tech)

---

## What This Is

A complete SOC detection engineering project using Splunk Enterprise.

Simulates a real-world attack chain — SSH brute force on Linux,
successful compromise, lateral movement to Windows, privilege
escalation, and process execution — then detects every phase
using SPL correlation rules, automated alerts, and a SOC dashboard.

Built using skills developed in:
🔗 [splunk-lab](https://github.com/mars13-tech/splunk-lab)

---

## Attack Architecture

```
Kali Linux (Attacker)
        ↓ SSH Brute Force
Ubuntu VM — mars-VirtualBox (Target)
        ↓ /var/log/auth.log
        ↓ Lateral Movement
Windows Host — LAPTOP-7S5H8RIM
        ↓ WinEventLog:Security
Splunk Enterprise (Detection)
        ↓
Alerts → Email Notification → SOC Dashboard
```

---

## Environment

| System | Role | Log Source |
|---|---|---|
| Kali Linux | Attacker simulation | SSH attempts |
| Ubuntu VM | Target — Linux endpoint | /var/log/auth.log |
| Windows Host | Lateral movement target + Splunk server | WinEventLog:Security |

---

## Repository Structure

```
splunk-soc-detection/
│
├── README.md
├── architecture.png              — Full attack chain diagram
├── incident_report.md            — Formal incident report
│
├── detections/
│   ├── brute_force_detection.spl     — Phase 1 — SSH brute force SPL
│   ├── brute_force_success.spl       — Phase 2 — Compromise detection SPL
│   └── lateral_movement_detection.spl — Phase 3-5 — Lateral movement SPL
│
├── alerts/
│   ├── brute_force_alert.txt         — Alert config — Phase 1
│   ├── brute_force_success_alert.txt — Alert config — Phase 2
│   └── lateral_movement_alert.txt    — Alert config — Phase 3-5
│
├── dashboards/
│   └── splunk_soc_dashboard.md       — Full dashboard panel documentation
│
├── screenshots/
│   ├── screenshots_overview.md       — Index and description of all screenshots
│   ├── brute_force_activity.png      — Phase 1 — SSH brute force activity chart
│   ├── top_attacking_ips.png         — Phase 1 — Top attacking source IPs
│   ├── successful_ssh_logins.png     — Phase 2 — Successful login after brute force
│   ├── windows_logons.png            — Phase 3 — Lateral movement Windows logon
│   ├── privilege_process_activity.png — Phase 4-5 — Privilege escalation and process execution
│   ├── attack_timeline.png           — Full correlated attack timeline
│   ├── dashboard_overview.png        — Complete SOC dashboard view
│   └── alert.png                     — Alert firing with email notification
│
└── notes/
    ├── splunk_queries.md             — SPL query reference
    └── investigation-notes.md        — What happened when alerts fired
```

---

## Attack Scenario — 5 Phases

### Phase 1 — SSH Brute Force
Attacker performs repeated SSH login attempts against Ubuntu VM.

**Detection:**
```spl
index=main host="mars-VirtualBox" "Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count by src
| where count > 10
```
**Alert:** Fires when failed login count exceeds 10 from same IP
**Severity:** High
**MITRE:** T1110.001 — Brute Force: Password Guessing

---

### Phase 2 — Successful Compromise
After brute force — successful SSH authentication occurs.

**Detection:**
```spl
index=main host="mars-VirtualBox"
("Failed password" OR "Accepted password")
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| transaction src maxspan=10m
| search eventcount > 5 AND "Accepted password"
```
**Alert:** Fires when failures followed by success from same IP
**Severity:** Critical
**MITRE:** T1078 — Valid Accounts

---

### Phase 3 — Lateral Movement
Attacker moves from compromised Ubuntu to Windows host.

**Detection:**
```spl
index=main host="LAPTOP-7S5H8RIM"
source="WinEventLog:Security"
EventCode=4624 Logon_Type=3
| stats count by Account_Name Source_Network_Address
```
**Alert:** Fires on Windows network logon from Ubuntu IP
**Severity:** Critical
**MITRE:** T1021.004 — Remote Services: SSH

---

### Phase 4 — Privilege Escalation
Attacker gains elevated privileges on Windows host.

**Detection:**
```spl
index=main host="LAPTOP-7S5H8RIM"
source="WinEventLog:Security"
EventCode=4672
| stats count by Account_Name
```
**MITRE:** T1068 — Exploitation for Privilege Escalation

---

### Phase 5 — Process Execution
Attacker executes tools and commands on Windows host.

**Detection:**
```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4688
| search Image="*cmd*" OR Image="*powershell*" OR Image="*psexec*"
| table _time Account_Name Image CommandLine
```
**MITRE:** T1059.004 — Command and Scripting Interpreter: Unix Shell

---

### Full Attack Timeline Correlation

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| sort _time
| table _time host EventCode _raw
```

---

## Alerts Configured

| Alert | Condition | Severity | Action |
|---|---|---|---|
| SSH Brute Force | Failed logins > 10 from same IP | High | Email notification |
| Brute Force Success | Failures followed by success | Critical | Email notification |
| Lateral Movement | Windows network logon + privilege + process | Critical | Email notification |

---

## SOC Dashboard Panels

| Panel | Visualization | What It Shows |
|---|---|---|
| SSH Brute Force Activity | Line chart | Failed SSH logins over time |
| Top Attacking IPs | Bar chart | Source IPs with highest failure count |
| Successful SSH Logins | Line chart | Successful logins — compromise indicator |
| Windows Logons | Area chart | Windows authentication events |
| Privilege and Process Activity | Column chart | Event ID 4672 and 4688 activity |
| Attack Timeline | Table | Full correlated attack chain |

---

## MITRE ATT&CK Mapping

| Attack Phase | Technique | ID |
|---|---|---|
| SSH Brute Force | Brute Force: Password Guessing | T1110.001 |
| Successful Login | Valid Accounts | T1078 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Process Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 |

---

## Skills Demonstrated

| Skill | Evidence |
|---|---|
| SIEM Administration | Splunk Enterprise configured across 3 systems |
| Detection Engineering | detections/ — 3 SPL detection files |
| Alert Engineering | alerts/ — 3 alerts with email notification |
| Cross-Platform Log Analysis | Linux auth.log + Windows Security Event Logs |
| Dashboard Development | dashboards/splunk_soc_dashboard.md |
| Incident Investigation | incident_report.md — formal IR report |
| Attack Simulation | Full 5-phase attack chain executed and documented |
| MITRE ATT&CK Mapping | All 5 attack phases mapped to techniques |

---

## Project Outcome

Complete SOC workflow demonstrated end to end:

1. Attack simulation across Linux and Windows
2. Log collection from two different OS environments
3. SPL detection rules for each attack phase
4. Correlation searches linking events across hosts
5. Automated alerts with email notification
6. SOC dashboard showing full attack visibility
7. Formal incident report documenting findings

---

## Foundation

This project was built using SPL and Splunk skills developed in:
🔗 [splunk-lab](https://github.com/mars13-tech/splunk-lab)

---

## Future Improvements

- [ ] Add Sysmon for deeper Windows process visibility
- [ ] Build EQL correlation searches
- [ ] Add threat intelligence lookups
- [ ] Automate response actions via Splunk SOAR
- [ ] Add network traffic capture alongside log analysis

---

## Author

**Karthikeyan**  
Cybersecurity Engineering Student | Blue Team | SOC Analyst in the Making  
🔗 [LinkedIn](https://www.linkedin.com/in/karthi-keyan-9042862bb)  
🐙 [GitHub](https://github.com/mars13-tech)
