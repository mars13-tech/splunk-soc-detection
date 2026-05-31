# Screenshots Overview — Splunk SOC Lab
# Brute Force & Lateral Movement Detection

**Author:** Karthikeyan
**Project:** splunk-bruteforce-lateral-movement-detection
**Last Updated:** May 2026

---

## Screenshots Index

| File | What It Shows | Attack Phase | MITRE |
|---|---|---|---|
| brute_force_activity.png | SSH failed login attempts over time — line chart showing attack volume | Phase 1 — Brute Force | T1110.001 |
| top_attacking_ips.png | Bar chart of top source IPs with highest failed login count | Phase 1 — Brute Force | T1110.001 |
| successful_ssh_logins.png | Successful SSH authentication after brute force — alert condition met | Phase 2 — Compromise | T1078 |
| windows_logons.png | Windows network logon events (Event ID 4624 Logon Type 3) from Ubuntu IP | Phase 3 — Lateral Movement | T1021.004 |
| privilege_process_activity.png | Privilege escalation (Event ID 4672) and process execution (Event ID 4688) | Phase 4 — Privilege Escalation | T1068, T1059.004 |
| attack_timeline.png | Full correlated attack timeline across Ubuntu and Windows hosts | All Phases | Multiple |
| dashboard_overview.png | Full SOC dashboard showing all 6 panels simultaneously | All Phases | Multiple |
| alert.png | Splunk alert firing with email notification triggered | Alert Engineering | Multiple |

---

## Screenshot Descriptions

### brute_force_activity.png
**Panel:** SSH Brute Force Activity — Line Chart
**Query used:**
```spl
index=main host="mars-VirtualBox" "Failed password"
| timechart span=1m count
```
**What to look for:** Spike in failed login count within a short time window.
A legitimate user does not fail 47 times in 2 minutes.
**MITRE:** T1110.001 — Brute Force: Password Guessing

---

### top_attacking_ips.png
**Panel:** Top Attacking IP Addresses — Bar Chart
**Query used:**
```spl
index=main host="mars-VirtualBox" "Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| top src
```
**What to look for:** One IP dominating the chart — single-source brute force.
Multiple IPs with equal counts may indicate distributed attack.
**MITRE:** T1110.001 — Brute Force: Password Guessing

---

### successful_ssh_logins.png
**Panel:** Successful SSH Logins — Line Chart
**Query used:**
```spl
index=main host="mars-VirtualBox" "Accepted password"
| timechart count
```
**What to look for:** Successful login appearing shortly after brute force spike.
Timing correlation between failed and accepted password events confirms compromise.
**MITRE:** T1078 — Valid Accounts

---

### windows_logons.png
**Panel:** Windows Logons — Area Chart
**Query used:**
```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624
| timechart count
```
**What to look for:** Network logon (Logon Type 3) from Ubuntu VM IP address.
This confirms lateral movement from compromised Linux host to Windows.
**MITRE:** T1021.004 — Remote Services: SSH

---

### privilege_process_activity.png
**Panel:** Privilege Escalation and Process Execution — Column Chart
**Query used:**
```spl
index=main host="LAPTOP-7S5H8RIM"
(EventCode=4672 OR EventCode=4688)
| timechart count
```
**What to look for:**
- Event ID 4672 — admin privileges assigned to account
- Event ID 4688 — cmd.exe or powershell.exe spawned after privilege escalation
Both appearing together after lateral movement confirms attacker has elevated access.
**MITRE:** T1068 — Exploitation for Privilege Escalation, T1059.004 — Unix Shell

---

### attack_timeline.png
**Panel:** Full Attack Timeline — Table
**Query used:**
```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| sort _time
| table _time host EventCode _raw
```
**What to look for:** Chronological sequence showing:
1. Brute force on Ubuntu
2. Successful SSH login on Ubuntu
3. Windows network logon from Ubuntu IP
4. Privilege escalation on Windows
5. Process execution on Windows

This is the full attack kill chain visible in one table.
**MITRE:** Multiple — T1110.001, T1078, T1021.004, T1068, T1059.004

---

### dashboard_overview.png
**What it shows:** All 6 SOC dashboard panels visible simultaneously
- SSH Brute Force Activity (line chart)
- Top Attacking IPs (bar chart)
- Successful SSH Logins (line chart)
- Windows Logons (area chart)
- Privilege and Process Activity (column chart)
- Attack Timeline (table)

**Why it matters:** A SOC analyst monitoring this dashboard can see the
full attack progression from initial brute force to lateral movement
in a single view without running individual queries.

---

### alert.png
**What it shows:** Splunk alert firing with email notification
**Alert triggered:** Brute force success detection — failed logins
followed by successful authentication
**Severity:** Critical
**Action:** Email notification sent automatically

**Why it matters:** Automated alerting means the SOC analyst does not
need to watch the dashboard continuously. The SIEM notifies when
conditions are met. This is how real SOC alerting works.

---

## Attack Flow Summary

```
Phase 1 — Brute Force
Kali Linux → SSH failed passwords → mars-VirtualBox (Ubuntu)
Screenshot: brute_force_activity.png, top_attacking_ips.png

Phase 2 — Compromise
Accepted password → successful SSH login
Screenshot: successful_ssh_logins.png

Phase 3 — Lateral Movement
Ubuntu IP → Windows network logon (Event ID 4624, Logon Type 3)
Screenshot: windows_logons.png

Phase 4 — Privilege Escalation + Process Execution
Event ID 4672 (privilege) + Event ID 4688 (process)
Screenshot: privilege_process_activity.png

Full Timeline
All phases correlated across both hosts
Screenshot: attack_timeline.png

Alert Fired
Email notification triggered automatically
Screenshot: alert.png
```

---

## Connected Files

- `detections/brute_force_detection.spl` — SPL for Phase 1 detection
- `detections/brute_force_success.spl` — SPL for Phase 2 detection
- `detections/lateral_movement_detection.spl` — SPL for Phase 3 and 4 detection
- `alerts/brute_force_alert.txt` — Alert config for Phase 1
- `alerts/brute_force_success_alert.txt` — Alert config for Phase 2
- `alerts/lateral_movement_alert.txt` — Alert config for Phase 3 and 4
- `dashboards/splunk_soc_dashboard.md` — Full dashboard panel documentation
- `notes/splunk_queries.md` — SPL query reference
- `incident_report.md` — Full incident report
- `architecture.png` — Attack chain architecture diagram
