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
| Credential Access | T1003 OS Credential Dumping | R-0002 | covered (read via security_file_open; kernel-level deny in enforce) |
| Command and Control | T1571 Non-Standard Port | R-0008 | covered |
| Command and Control | T1071.004 Application Layer Protocol: DNS | R-0066 | covered |
| Command and Control | T1105 Ingress Tool Transfer | R-0043 | covered |
| Command and Control | T1059 Command and Scripting (reverse shell) | R-0044 | covered |
| Command and Control | T1572 Protocol Tunneling | R-0045 | covered |
| Command and Control | T1090 Proxy | R-0046 | covered |
| Discovery | T1033 System Owner/User Discovery | R-0017 | covered |
| Discovery | T1082 System Information Discovery | R-0018 | covered |
| Discovery | T1083 File and Directory Discovery | R-0019 | covered |
| Discovery | T1087.001 Account Discovery: Local Account | R-0020 | covered |
| Discovery | T1018 Remote System Discovery | R-0021 | covered |
| Discovery | T1016 System Network Configuration Discovery | R-0022 | covered |
| Discovery | T1057 Process Discovery | R-0023 | covered |
| Discovery | T1046 Network Service Discovery | R-0024 | covered |
| Lateral Movement | T1021.004 Remote Services: SSH | R-0025, R-0026 | covered |
| Lateral Movement | T1570 Lateral Tool Transfer | R-0027 | covered |
| Lateral Movement | T1021 Remote Services | R-0028 | covered |
| Collection | T1560.001 Archive Collected Data: via Utility | R-0029 | covered |
| Collection | T1074.001 Local Data Staging | R-0031 | covered |
| Collection | T1560 Archive Collected Data | R-0032 | covered |
| Credential Access | T1552.001 Unsecured Credentials In Files | R-0030 | covered |
| Credential Access | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow | R-0070 | covered |
| Credential Access | T1110 Brute Force | R-0071 | covered |
| Credential Access | T1003.007 OS Credential Dumping: Proc Filesystem | R-0072 | covered |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol | R-0033 | covered |
| Exfiltration | T1567.002 Exfiltration to Cloud Storage | R-0034 | covered |
| Exfiltration | T1041 Exfiltration Over C2 Channel | R-0035 | covered |
| Impact | T1486 Data Encrypted for Impact | R-0036 | covered |
| Impact | T1490 Inhibit System Recovery | R-0037 | covered |
| Impact | T1489 Service Stop | R-0038 | covered |
| Impact | T1485 Data Destruction | R-0039 | covered |
| Impact | T1496 Resource Hijacking | R-0040 | covered |
| Impact | T1529 System Shutdown/Reboot | R-0041 | covered |
| Impact | T1561.002 Disk Wipe: Disk Structure Wipe | R-0042 | covered |
| Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | R-0067 | covered |
| Defense Evasion | T1562.001 Impair Defenses (tamper with the agent) | R-0074 | covered (LSM task_kill/ptrace self-protection) |
| Defense Evasion | T1070.002 Clear Linux or Mac System Logs | R-0068 | covered |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | R-0069 | covered |
| Execution | T1204.002 User Execution: Malicious File (YARA) | R-0073 | covered |

**partial** means the rule is correct but live coverage is limited by current
telemetry (documented in `KNOWN_LIMITATIONS.md` and `DETECTIONS.md`).

Discovery rules are intentionally low-severity: a single `whoami` is benign, so
they are tuned to accumulate toward an incident under correlation rather than
alert loudly on their own.

Planned next: T1611 Escape to Host (container escape), and deeper correlation of
the discovery/collection/exfiltration chain.
