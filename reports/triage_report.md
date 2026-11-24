# SOC Triage Report

Alerts triaged: **12** | P1: 5 | P2: 1 | P3: 2 | P4: 4

| Priority | Score | Alert | Rule | Verdict |
|---|---|---|---|---|
| P1 | 100 | ALT-1002 | Suspicious PowerShell execution | true_positive |
| P1 | 91 | ALT-1001 | Multiple failed logons followed by success | true_positive |
| P1 | 90 | ALT-1005 | Credential dumping tool detected | true_positive |
| P1 | 88 | ALT-1011 | Certutil used to download file | true_positive |
| P1 | 75 | ALT-1007 | Outbound connection to known C2 | true_positive |
| P2 | 58 | ALT-1003 | Phishing URL clicked | likely_true_positive |
| P3 | 36 | ALT-1012 | Account added to privileged group | suspicious_needs_review |
| P3 | 27 | ALT-1009 | Port scan detected | suspicious_needs_review |
| P4 | 18 | ALT-1006 | Admin scheduled backup script | benign_or_low_risk |
| P4 | 5 | ALT-1008 | VPN login from new country | benign_or_low_risk |
| P4 | 0 | ALT-1004 | Failed logon | benign_or_low_risk |
| P4 | 0 | ALT-1010 | Windows update download | benign_or_low_risk |

## ALT-1002: Suspicious PowerShell execution (P1)

Suspicious PowerShell execution on DC01 (user: asmith) scored 100/100 -> P1 (true_positive). Key factors: command line: encoded PowerShell command, hidden window; vendor severity: high; 2 correlated alert(s) on same user/host/IP. ATT&CK: T1059.001 PowerShell.

**Score breakdown**
- vendor severity: high: +25
- host criticality: critical: +15
- privileged account involved: +10
- command line: encoded PowerShell command, hidden window: +35
- 2 correlated alert(s) on same user/host/IP: +16

**MITRE ATT&CK**
- T1059.001 PowerShell (Execution)

**Recommended actions**
- Open a P1 incident and page the on-call responder.
- Collect the PowerShell script block logs and decode the payload.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, analyze_command_line_

## ALT-1001: Multiple failed logons followed by success (P1)

Multiple failed logons followed by success on DC01 (user: asmith) scored 91/100 -> P1 (true_positive). Key factors: malicious indicator in threat intel; 2 correlated alert(s) on same user/host/IP; vendor severity: medium. ATT&CK: T1110 Brute Force.

**Score breakdown**
- vendor severity: medium: +15
- malicious indicator in threat intel: +30
- host criticality: critical: +15
- privileged account involved: +10
- high-impact ATT&CK tactic: +5
- 2 correlated alert(s) on same user/host/IP: +16

**MITRE ATT&CK**
- T1110 Brute Force (Credential Access)

**Recommended actions**
- Open a P1 incident and page the on-call responder.
- Reset credentials and revoke active sessions for asmith.
- Block at firewall/proxy: 185.220.101.45.
- Isolate host DC01 via EDR pending investigation.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, lookup_ip_reputation_

## ALT-1005: Credential dumping tool detected (P1)

Credential dumping tool detected on SQL-PROD-02 (user: svc_backup) scored 90/100 -> P1 (true_positive). Key factors: command line: credential dumping tool; vendor severity: high; host criticality: critical. ATT&CK: T1003 OS Credential Dumping.

**Score breakdown**
- vendor severity: high: +25
- host criticality: critical: +15
- privileged account involved: +10
- command line: credential dumping tool: +35
- high-impact ATT&CK tactic: +5

**MITRE ATT&CK**
- T1003 OS Credential Dumping (Credential Access)

**Recommended actions**
- Open a P1 incident and page the on-call responder.
- Isolate the host and rotate all credentials cached on it.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, analyze_command_line_

## ALT-1011: Certutil used to download file (P1)

Certutil used to download file on WKS-FIN-114 (user: jdoe) scored 88/100 -> P1 (true_positive). Key factors: malicious indicator in threat intel; command line: certutil remote download; vendor severity: medium. ATT&CK: T1105 Ingress Tool Transfer.

**Score breakdown**
- vendor severity: medium: +15
- malicious indicator in threat intel: +30
- host criticality: medium: +5
- command line: certutil remote download: +25
- high-impact ATT&CK tactic: +5
- 1 correlated alert(s) on same user/host/IP: +8

**MITRE ATT&CK**
- T1105 Ingress Tool Transfer (Command and Control)

**Recommended actions**
- Open a P1 incident and page the on-call responder.
- Block at firewall/proxy: 203.0.113.50.
- Isolate host WKS-FIN-114 via EDR pending investigation.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, lookup_ip_reputation, analyze_command_line_

## ALT-1007: Outbound connection to known C2 (P1)

Outbound connection to known C2 on WKS-ENG-207 (user: mlee) scored 75/100 -> P1 (true_positive). Key factors: malicious indicator in threat intel; vendor severity: high; known C2 infrastructure. ATT&CK: T1071 Application Layer Protocol.

**Score breakdown**
- vendor severity: high: +25
- malicious indicator in threat intel: +30
- known C2 infrastructure: +15
- high-impact ATT&CK tactic: +5

**MITRE ATT&CK**
- T1071 Application Layer Protocol (Command and Control)

**Recommended actions**
- Open a P1 incident and page the on-call responder.
- Block at firewall/proxy: 45.155.205.233.
- Isolate host WKS-ENG-207 via EDR pending investigation.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, lookup_ip_reputation_

## ALT-1003: Phishing URL clicked (P2)

Phishing URL clicked on WKS-FIN-114 (user: jdoe) scored 58/100 -> P2 (likely_true_positive). Key factors: malicious indicator in threat intel; vendor severity: medium; 1 correlated alert(s) on same user/host/IP. ATT&CK: T1566 Phishing.

**Score breakdown**
- vendor severity: medium: +15
- malicious indicator in threat intel: +30
- host criticality: medium: +5
- 1 correlated alert(s) on same user/host/IP: +8

**MITRE ATT&CK**
- T1566 Phishing (Initial Access)

**Recommended actions**
- Escalate to a tier-2 analyst within 1 hour.
- Block at firewall/proxy: 203.0.113.50.
- Isolate host WKS-FIN-114 via EDR pending investigation.
- Search mail logs for other recipients and purge the message.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, lookup_ip_reputation, lookup_domain_reputation_

## ALT-1012: Account added to privileged group (P3)

Account added to privileged group on DC01 (user: asmith) scored 36/100 -> P3 (suspicious_needs_review). Key factors: 2 correlated alert(s) on same user/host/IP; vendor severity: medium; host criticality: critical. ATT&CK: T1098 Account Manipulation.

**Score breakdown**
- vendor severity: medium: +15
- host criticality: critical: +15
- privileged account involved: +10
- 2 correlated alert(s) on same user/host/IP: +16
- benign context (ticketed/scheduled/routine): -20

**MITRE ATT&CK**
- T1098 Account Manipulation (Persistence)

**Recommended actions**
- Queue for analyst review within 24 hours.
- Verify the change ticket and review group membership changes.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation_

## ALT-1009: Port scan detected (P3)

Port scan detected on WEB-DMZ-01 (user: n/a) scored 27/100 -> P3 (suspicious_needs_review). Key factors: suspicious indicator in threat intel; host criticality: high; vendor severity: low. ATT&CK: T1046 Network Service Discovery.

**Score breakdown**
- vendor severity: low: +5
- suspicious indicator in threat intel: +12
- host criticality: high: +10

**MITRE ATT&CK**
- T1046 Network Service Discovery (Discovery)

**Recommended actions**
- Queue for analyst review within 24 hours.
- Confirm the target is patched and rate-limit the source IP.

_Tools called: map_mitre, find_related_alerts, lookup_host_context, lookup_ip_reputation, lookup_ip_reputation_

## ALT-1006: Admin scheduled backup script (P4)

Admin scheduled backup script on SQL-PROD-02 (user: svc_backup) scored 18/100 -> P4 (benign_or_low_risk). Key factors: host criticality: critical; privileged account involved; 1 correlated alert(s) on same user/host/IP. ATT&CK: T1059.001 PowerShell.

**Score breakdown**
- vendor severity: low: +5
- host criticality: critical: +15
- privileged account involved: +10
- 1 correlated alert(s) on same user/host/IP: +8
- benign context (ticketed/scheduled/routine): -20

**MITRE ATT&CK**
- T1059.001 PowerShell (Execution)

**Recommended actions**
- Close as benign/low risk; no action required.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, analyze_command_line_

## ALT-1008: VPN login from new country (P4)

VPN login from new country on VPN-GW (user: rpatel) scored 5/100 -> P4 (benign_or_low_risk). Key factors: vendor severity: medium. ATT&CK: T1078 Valid Accounts.

**Score breakdown**
- vendor severity: medium: +15
- indicator is known-clean: -10

**MITRE ATT&CK**
- T1078 Valid Accounts (Initial Access)

**Recommended actions**
- Close as benign/low risk; no action required.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation_

## ALT-1004: Failed logon (P4)

Failed logon on WKS-ENG-207 (user: mlee) scored 0/100 -> P4 (benign_or_low_risk). Key factors: 1 correlated alert(s) on same user/host/IP; vendor severity: low. ATT&CK: no ATT&CK match.

**Score breakdown**
- vendor severity: low: +5
- 1 correlated alert(s) on same user/host/IP: +8
- benign context (ticketed/scheduled/routine): -20

**Recommended actions**
- Close as benign/low risk; no action required.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation_

## ALT-1010: Windows update download (P4)

Windows update download on WKS-ENG-207 (user: mlee) scored 0/100 -> P4 (benign_or_low_risk). Key factors: 1 correlated alert(s) on same user/host/IP; vendor severity: low. ATT&CK: no ATT&CK match.

**Score breakdown**
- vendor severity: low: +5
- indicator is known-clean: -10
- 1 correlated alert(s) on same user/host/IP: +8
- benign context (ticketed/scheduled/routine): -20

**Recommended actions**
- Close as benign/low risk; no action required.

_Tools called: map_mitre, find_related_alerts, lookup_user_context, lookup_host_context, lookup_ip_reputation, lookup_domain_reputation_
