# Splunk Queries Reference

## Overview

This document contains the SPL (Search Processing Language) queries used throughout the Brute Force and Lateral Movement Detection project.

---

# Linux Authentication Queries

## View All SSH Authentication Events

```spl
index=main host="mars-VirtualBox"
source="/var/log/auth.log"
```

Purpose:

* Verify log ingestion
* Review authentication activity

---

## View Failed SSH Logins

```spl
index=main host="mars-VirtualBox"
"Failed password"
```

Purpose:

* Identify failed authentication attempts
* Detect brute force activity

---

## View Successful SSH Logins

```spl
index=main host="mars-VirtualBox"
"Accepted password"
```

Purpose:

* Monitor successful SSH authentication

---

## Extract Source IP Addresses

```spl
index=main host="mars-VirtualBox"
"Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
```

Purpose:

* Extract attacker IP addresses from raw logs

---

# Brute Force Detection

## Detect Excessive Failed SSH Logins

```spl
index=main host="mars-VirtualBox"
"Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count by src
| where count > 10
```

Purpose:

* Identify source IPs generating excessive failed logins

---

## Top Attacking IP Addresses

```spl
index=main host="mars-VirtualBox"
"Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| top src
```

Purpose:

* Identify the most active attackers

---

# Brute Force Success Detection

## Detect Successful Login After Multiple Failures

```spl
index=main host="mars-VirtualBox"
("Failed password" OR "Accepted password")
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| transaction src maxspan=10m
| search eventcount > 5 AND "Accepted password"
```

Purpose:

* Detect potential credential compromise

---

# Windows Security Monitoring

## Successful Windows Logons

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624
```

Purpose:

* Monitor successful Windows authentication events

---

## Network Logons

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624 Logon_Type=3
```

Purpose:

* Identify possible lateral movement activity

---

## Failed Windows Logons

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4625
```

Purpose:

* Monitor failed authentication attempts

---

## Privilege Escalation Events

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4672
```

Purpose:

* Detect assignment of special privileges

---

## Process Creation Events

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4688
```

Purpose:

* Monitor process execution activity

---

## Suspicious Process Execution

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4688
| search Image="*cmd*" OR Image="*powershell*" OR Image="*psexec*"
| table _time Account_Name Image CommandLine
```

Purpose:

* Detect potentially suspicious command execution

---

# Correlation Searches

## Full Attack Timeline

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| sort _time
| table _time host EventCode _raw
```

Purpose:

* Reconstruct attack progression

---

## Windows Activity Summary

```spl
index=main host="LAPTOP-7S5H8RIM"
(EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| stats count by EventCode
```

Purpose:

* Summarize Windows security events

---

# Dashboard Queries

## SSH Brute Force Activity

```spl
index=main host="mars-VirtualBox"
"Failed password"
| timechart span=1m count
```

Visualization:

* Line Chart

---

## Top Attacking IPs

```spl
index=main host="mars-VirtualBox"
"Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| top src
```

Visualization:

* Bar Chart

---

## Successful SSH Logins

```spl
index=main host="mars-VirtualBox"
"Accepted password"
| timechart count
```

Visualization:

* Line Chart

---

## Windows Authentication Activity

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624
| timechart count
```

Visualization:

* Area Chart

---

## Privilege Escalation and Process Activity

```spl
index=main host="LAPTOP-7S5H8RIM"
(EventCode=4672 OR EventCode=4688)
| timechart count
```

Visualization:

* Column Chart

---

## Attack Timeline

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| table _time host EventCode _raw
| sort _time
```

Visualization:

* Table

---

# Key Windows Event IDs

| Event ID | Description                 |
| -------- | --------------------------- |
| 4624     | Successful Logon            |
| 4625     | Failed Logon                |
| 4672     | Special Privileges Assigned |
| 4688     | Process Creation            |

---

# Key Skills Demonstrated

* Log Analysis
* SPL Query Development
* Detection Engineering
* Threat Hunting
* Security Monitoring
* Event Correlation
* Dashboard Development
* Alert Engineering
* Incident Investigation
