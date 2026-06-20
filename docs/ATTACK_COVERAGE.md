# MITRE ATT&CK coverage

Techniques the shipped rules cover, by tactic. This is the starting set; the
roadmap grows it toward broad coverage with correlation and more sensors.

| Tactic | Technique | Rule | Status |
|--------|-----------|------|--------|
| Execution | T1059 Command and Scripting Interpreter | R-0007, R-0062 | covered |
| Persistence | T1053.003 Scheduled Task/Job: Cron | R-0003 | covered |
| Persistence | T1543.002 Create/Modify System Process: systemd | R-0004 | covered |
| Persistence | T1098.004 Account Manipulation: SSH Keys | R-0005 | covered |
| Persistence | T1574.006 Hijack Execution Flow: Linker | R-0006 | covered |
| Persistence | T1547.006 Kernel Modules and Extensions | R-0061 | covered |
| Privilege Escalation | T1548.001 Abuse Elevation: Setuid/Setgid | R-0015 | covered |
| Privilege Escalation | T1548 Abuse Elevation Control Mechanism | R-0065 | covered |
| Defense Evasion | T1036 Masquerading | R-0001 | covered |
| Defense Evasion | T1055 Process Injection (ptrace, RWX mmap) | R-0060, R-0064 | covered |
| Defense Evasion | T1070 Indicator Removal | R-0014 | covered |
| Defense Evasion | T1070.003 Clear Command History | R-0016 | partial |
| Defense Evasion | T1620 Reflective Code Loading (memfd) | R-0063 | covered |
| Credential Access | T1003 OS Credential Dumping | R-0002 | covered (read via security_file_open) |
| Command and Control | T1571 Non-Standard Port | R-0008 | covered |
| Command and Control | T1071.004 Application Layer Protocol: DNS | R-0066 | covered |

**partial** means the rule is correct but live coverage is limited by current
telemetry (documented in `KNOWN_LIMITATIONS.md` and `DETECTIONS.md`).

Planned next (sensors + rules): T1611 Escape to Host (container escape),
T1021 Lateral Movement (cross-host, control plane), and broader rule content
(Phase 5).
