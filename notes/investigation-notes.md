# Investigation Notes — Brute Force and Lateral Movement

**Author:** Karthikeyan
**Project:** Splunk SOC Lab — Brute Force and Lateral Movement Detection

---

## What Happened When the Alerts Fired

### Alert 1 — SSH Brute Force Detected

Alert condition triggered when failed SSH login count exceeded 10
from the same source IP.

**What I investigated:**
- Confirmed source IP was the Kali Linux attacker machine
- Counted failed attempts — 47 failed logins in under 2 minutes
- Identified target username being brute forced
- Verified no successful login at this stage

**MITRE:** T1110.001 — Brute Force: Password Guessing

**SOC Action:** P2 High — block source IP, notify system owner

---

### Alert 2 — Brute Force Success Detected

Alert triggered when successful SSH login appeared after multiple failures.

**What I investigated:**
- Confirmed same source IP from brute force alert
- Verified successful authentication followed 47 failed attempts
- Checked timestamp — success came 3 minutes after attack started
- Confirmed this was the same session as the brute force

**MITRE:** T1078 — Valid Accounts

**SOC Action:** P1 Critical — isolate affected system immediately

---

### Alert 3 — Lateral Movement Detected

Alert triggered on Windows network logon (Event ID 4624, Logon Type 3)
after Ubuntu compromise.

**What I investigated:**
- Confirmed Windows logon came from Ubuntu VM IP address
- Checked Account_Name — admin account used for lateral movement
- Reviewed subsequent Event ID 4672 — privileged logon confirmed
- Checked Event ID 4688 — cmd.exe and powershell.exe spawned after logon

**MITRE:** T1021.004 — Remote Services: SSH, T1068 — Privilege Escalation

**SOC Action:** P1 Critical — isolate Windows host, reset credentials,
begin full incident response

---

## Key Lessons From This Investigation

1. Brute force alerts alone are P2 — annoying but common
2. Brute force followed by success is P1 — attacker is inside
3. Lateral movement after initial compromise is the most dangerous stage
4. Event ID correlation across two hosts (Linux + Windows) is what
   reveals the full attack chain — single host visibility is not enough
5. Alert tuning threshold matters — too low = noise, too high = missed attacks
