"""
Contexta Backend - AI Agents Routes

Provides endpoints for multi-agent analysis and orchestration.
Includes a built-in discussion engine that works without external AI APIs.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog
import re
import hashlib

from app.database import get_db
from app.agents.orchestrator import get_orchestrator
from app.services.incident_service import IncidentService
from app.auth.jwt import get_current_active_user, get_current_user_optional, TokenData
from app.ledger.chain import get_ledger, LedgerEventTypes
from app.services.gemini_service import GeminiService, GeminiServiceError

logger = structlog.get_logger()
router = APIRouter()


# ── Built-in Agent Discussion Engine ──────────────────────────────────────
# Deterministic, keyword-driven multi-agent conversation generator.
# Follows the SOC pipeline: Analyst → Intel → Forensics → Business → Response.

ATTACK_KNOWLEDGE = {
    "ddos": {
        "label": "DDoS Attack",
        "analyst": [
            "Detecting volumetric traffic anomaly — inbound packet rate at {rate}K pps, {bw} Gbps sustained on port {port}. SYN flood ratio at 92%. Source IPs distributed across {geo} — classic amplification pattern. Affected hosts: {hosts}.",
            "Traffic spike confirmed — {bw} Gbps inbound, {rate}K packets/sec targeting port {port}. TCP SYN ratio 89%, ICMP reflection detected. Triggering rate-limit on edge routers. Source distribution: {geo}.",
        ],
        "intel": [
            "Cross-referencing source IPs with threat feeds — 73% match known Mirai-variant botnet infrastructure. {c2} flagged as C2 in CISA advisory AA24-{advid}. MITRE ATT&CK: T1498 (Network DoS), T1499 (Endpoint DoS). This campaign aligns with recent attacks on {sector} sector targets.",
            "Threat intel correlation: Source ASNs traced to bullet-proof hosting in {geo}. 68% of source IPs appear in AbuseIPDB. IOCs match Killnet/Anonymous Sudan campaign TTPs. MITRE: T1498.001 (Direct Network Flood). Recommend checking for lateral probing.",
        ],
        "forensics": [
            "Building on Analyst's traffic data and Intel's botnet attribution — packet captures show {proto} amplification factor of 54x. Attack timeline: initiated {time_start}, peak at {time_peak}. No evidence of data exfiltration during the distraction. DNS logs clean. Edge firewall absorbed 78% before backend impact.",
            "Forensic deep-dive per Intel's Mirai attribution — capturing amplified {proto} reflectors. Payload analysis shows identical nonce across requests confirming scripted attack. Timeline reconstruction: ramp-up over 4 minutes, sustained for {dur} minutes. No internal host compromise detected.",
        ],
        "business": [
            "Based on Forensics' {dur}-minute attack window — customer-facing services degraded for approximately {downtime} minutes. Estimated revenue impact: ${revenue}K based on average transaction volume. {sla} SLA breach threshold approached but not exceeded. Recommend proactive customer communication.",
            "Per Forensics timeline — {downtime} minutes of service degradation on primary web stack. {users}K users affected during peak hours. SLA compliance at risk. Reputational impact: moderate — no data breach, but availability metrics dropped below {sla}% target.",
        ],
        "response": [
            "DECISION: Synthesizing all findings — activating 3-phase response:\n\n1️⃣ IMMEDIATE (0-15 min): Enable GeoIP blackhole for identified ASNs per Intel's attribution. Activate Cloudflare Under Attack Mode. Rate-limit to {rate_limit}K pps on edge.\n\n2️⃣ SHORT-TERM (15-60 min): Deploy updated WAF rules targeting {proto} amplification signatures from Forensics. Coordinate with upstream ISP for scrubbing.\n\n3️⃣ FOLLOW-UP: Post-incident review within 24h. Update runbook based on Business impact of ${revenue}K. Add C2 IPs {c2} to permanent blocklist.\n\nEscalation: SOC Level 2 notified. No law enforcement needed at this stage.",
        ],
    },
    "bruteforce": {
        "label": "Brute Force Attack",
        "analyst": [
            "Authentication anomaly detected — {attempts} failed login attempts against {target} in {window} minutes. Source IP: {src}. Targeting {service} service on port {port}. Account lockout threshold nearly reached on {accounts} accounts. Credential spraying pattern — low-and-slow with {delay}s delays between attempts.",
            "Alert triggered: {attempts} failed auth events from {src} targeting {service}:{port}. Attack pattern: password spraying across {accounts} accounts with dictionary wordlist. Rate: ~{rate}/min. Geo-location: {geo}. No successful auth yet.",
        ],
        "intel": [
            "Source IP {src} flagged in OTX and GreyNoise as known brute-force scanner. Associated with credential-stuffing campaigns using ComboList breach data. Last seen targeting {sector} organizations. MITRE ATT&CK: T1110.003 (Password Spraying), T1078 (Valid Accounts). Recommend checking for credential exposure on HaveIBeenPwned.",
            "IP {src} — reputation: MALICIOUS in 4/6 threat feeds. Part of a distributed credential stuffing network. Previous campaign targeted {sector} in Q{quarter}. MITRE: T1110.001 (Password Guessing). Associated wordlists: RockYou2024, BreachCompilation. Recommend preemptive password rotation for targeted accounts.",
        ],
        "forensics": [
            "Correlating Analyst's auth logs with Intel's attribution — user-agent analysis shows Python-requests/{pyver} (automated tool). HTTP headers inconsistent with legitimate client. {success} successful logins detected from same subnet in past 72h — potential compromised credentials. Examining those sessions for privilege escalation.",
            "Deep analysis per Intel's credential-stuffing attribution — log analysis reveals the attacker rotated through {proxies} proxy IPs before settling on {src}. Timing analysis: {delay}s ± 0.2s between attempts (bot precision). Found {success} potentially compromised sessions. Checking for persistence mechanisms.",
        ],
        "business": [
            "Per Forensics' finding of {success} potentially compromised sessions — triggering mandatory password reset for targeted accounts. Risk assessment: {accounts} accounts in {dept} department — includes {priv} privileged accounts. Compliance impact: potential {compliance} notification requirement if data accessed. Cost of forced reset: minimal vs. breach risk.",
            "Business impact from Forensics analysis — {success} sessions under investigation, {priv} with admin privileges. If confirmed compromised: potential {compliance} breach notification within 72h. Estimated incident cost: ${cost}K including investigation, reset, and monitoring. Recommend immediate containment.",
        ],
        "response": [
            "DECISION: Based on cross-agent analysis — executing containment protocol:\n\n1️⃣ IMMEDIATE:\n• Block IP {src} and associated /24 subnet at perimeter\n• Force password reset on {accounts} targeted accounts\n• Terminate {success} suspicious sessions identified by Forensics\n• Enable MFA enforcement for all {service} access\n\n2️⃣ INVESTIGATION:\n• Preserve auth logs for {window}-minute window\n• Examine {success} potentially compromised sessions for data access\n• Check for lateral movement from compromised accounts\n\n3️⃣ HARDENING:\n• Implement progressive lockout: 5 attempts → 15min, 10 → 1h, 15 → permanent\n• Deploy CAPTCHA on public-facing {service} endpoints\n• Update credential monitoring with Intel's IOCs\n\nEscalation: {priv} privileged accounts affected — notifying CISO.",
        ],
    },
    "sqli": {
        "label": "SQL Injection Attack",
        "analyst": [
            "WAF triggered on suspicious query patterns — {count} requests containing SQL metacharacters detected from {src}. Target: {target} endpoint. Payloads include UNION SELECT, OR 1=1, and time-based blind injection attempts. Response codes: mix of 200/500 — some payloads may be succeeding. Dumping request logs for deep analysis.",
            "SQL injection signatures detected — {count} malicious requests from {src} against {target}. Attack vectors: error-based (extractvalue), boolean-based blind, and UNION-based extraction. WAF blocked 62% but some encoded payloads bypassed initial ruleset. Priority: CRITICAL.",
        ],
        "intel": [
            "Source {src} identified in SQLMap user-agent database. Attack signatures match automated scanning tool (sqlmap/1.7). Target endpoint {target} matches known vulnerable pattern CVE-2024-{cveid}. MITRE ATT&CK: T1190 (Exploit Public-Facing App), T1059.004 (SQL). Attacker may be using Shodan dorks to target {tech} deployments.",
            "IP {src} linked to web application scanning campaign targeting {tech} applications. Tool fingerprint: sqlmap with tamper scripts (space2comment, charencode). MITRE: T1190, T1059.004. This vector has been actively exploited in {sector} — patch advisory published {days} days ago.",
        ],
        "forensics": [
            "Per Analyst's payload analysis and Intel's sqlmap attribution — examining database query logs. Found {exfil} successful data extraction queries. Attacker enumerated {tables} tables, extracted {rows} rows from {db_name}. No evidence of DROP/DELETE — read-only exfiltration. Time-to-first-success: {ttfs} minutes after initial probe. WAF bypass method: hex encoding + comment injection.",
            "Forensic timeline based on Intel's CVE reference — initial scan at {scan_time}, first successful injection at {breach_time}. Attacker extracted schema metadata first, then targeted {db_name}.{table}. Total data accessed: {rows} records including {pii_fields}. No privilege escalation to OS level. Database user had SELECT-only permissions (limited blast radius).",
        ],
        "business": [
            "CRITICAL from Forensics — {rows} records from {db_name} potentially exfiltrated, including {pii_fields}. Regulatory exposure: {regulation} Article {article} — mandatory breach notification within {notify_hours}h if PII confirmed. Affected user count: approximately {affected_users}. Legal counsel notified. Data classification: {classification}.",
            "Based on Forensics' data scope: {rows} records accessed from {db_name}. PII fields involved: {pii_fields}. Under {regulation}, this triggers mandatory notification. Estimated cost: ${cost}K (notification ${notify_cost}K + monitoring ${monitor_cost}K + legal ${legal_cost}K). Reputational risk: HIGH.",
        ],
        "response": [
            "DECISION: Data breach protocol ACTIVATED — full response:\n\n1️⃣ IMMEDIATE CONTAINMENT:\n• Block {src} at WAF and network perimeter\n• Disable {target} endpoint pending patching\n• Revoke database credentials and rotate API keys\n• Deploy virtual patch for CVE-2024-{cveid}\n\n2️⃣ EVIDENCE PRESERVATION:\n• Snapshot affected database and WAF logs\n• Preserve all query logs from {scan_time} to present\n• Create forensic image of web server\n\n3️⃣ REMEDIATION:\n• Apply parameterized queries to {target} endpoint\n• Conduct full application scan for similar vulnerabilities\n• Update WAF rules to detect hex-encoded SQL payloads\n\n4️⃣ COMPLIANCE:\n• Initiate {regulation} notification process per Business assessment\n• Engage external IR counsel within 4 hours\n• Prepare affected user notification for {affected_users} individuals\n\nEscalation: CISO, Legal, and DPO briefed. Severity: P1.",
        ],
    },
    "ransomware": {
        "label": "Ransomware Incident",
        "analyst": [
            "CRITICAL ALERT — File encryption activity detected on {hosts} hosts. Process '{proc}' spawning rapid file I/O with entropy >7.9 (encryption signature). Extension '.{ext}' being appended to files. Ransom note '{note}' dropped in {dirs} directories. Network shares being enumerated via SMB. Lateral movement via {lateral} detected.",
            "Ransomware execution confirmed — {hosts} endpoints affected. Binary {proc} (SHA256: {hash}) encrypting files with .{ext} extension. Ransom note demands {btc} BTC. Observed: shadow copy deletion (vssadmin), disabling Windows Defender, and SMB lateral movement to {shares} network shares.",
        ],
        "intel": [
            "Binary signature matches {family} ransomware (RaaS). Affiliate ID in ransom note links to threat actor '{actor}'. Kill switch domain: {domain} — currently resolving (not sinkholed). MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1021.002 (SMB). TTPs consistent with initial access via {access}.",
            "Threat intel match: {family} ransomware variant, associated with {actor} threat group. C2 communication to {c2} on port 443. MITRE: T1486, T1490, T1059.001 (PowerShell). This group's typical dwell time is {dwell} days — suggesting initial access occurred ~{dwell} days ago. Decryptor availability: {decryptor}.",
        ],
        "forensics": [
            "Full forensic timeline built from Intel's {dwell}-day dwell estimate:\n\nDay 1: Initial access via {access} — phishing email to {user}\nDay {dwell_mid}: Cobalt Strike beacon deployed, AD enumeration\nDay {dwell}: Domain admin compromised, ransomware deployed via GPO\n\nEncryption scope: {enc_tb} TB across {hosts} hosts. {backup_status}. Evidence collected: memory dumps, event logs, prefetch files. Admin account '{admin}' was compromised via pass-the-hash.",
            "Based on Intel's attribution to {actor} — initial entry point: {user}'s workstation. Cobalt Strike payload delivered via {access}. Attacker pivoted to DC within {pivot_hours}h. Ransomware deployed to {hosts} endpoints simultaneously via PsExec. Encryption started at {enc_time}. Total encrypted: {enc_tb} TB. {backup_status}.",
        ],
        "business": [
            "CRITICAL IMPACT from Forensics assessment — {enc_tb} TB encrypted across {hosts} systems. Operational status: {ops_status}. {backup_status_biz}. Ransom demand: {btc} BTC (~${ransom_usd}K). FBI/CISA recommendation: do not pay. Estimated recovery time without payment: {recovery_days} days. Business continuity plan: {bcp}. Revenue impact: ~${rev_impact}K/day of downtime.",
            "Maximum severity business impact: {hosts} systems offline affecting {dept} operations. {backup_status_biz}. Ransom: ${ransom_usd}K equivalent — legal counsel advises against payment per OFAC guidelines. Recovery cost estimate: ${recovery_cost}K. Insurance deductible: ${deductible}K. Board notification required within {board_hours}h per IR policy.",
        ],
        "response": [
            "DECISION: Full Incident Response — CRITICALLY CRITICAL:\n\n1️⃣ IMMEDIATE (0-30 min):\n• ISOLATE all affected segments — kill switch SMB/RDP at network boundary\n• Preserve one encrypted host for forensic evidence (DO NOT REIMAGE)\n• Disable compromised admin account '{admin}' per Forensics\n• Block C2 {c2} and kill switch domain at DNS/firewall\n\n2️⃣ CONTAINMENT (30 min - 4h):\n• Reset ALL domain admin passwords — assume full AD compromise\n• Deploy EDR containment on {hosts} hosts\n• Verify backup integrity: {backup_action}\n• Engage external IR firm (retainer: {ir_firm})\n\n3️⃣ ERADICATION & RECOVERY:\n• Rebuild domain controllers from known-good media\n• Restore from {backup_source} — estimated {recovery_days} days\n• Re-image affected workstations\n• Patch {access} vector identified by Forensics\n\n4️⃣ NOTIFICATION:\n• FBI IC3 report filed\n• {regulation} notification per Business assessment\n• Board briefing at {board_hours}h mark\n• Employee communication re: operational impact\n\nEscalation: P1 — CISO, CTO, Legal, CEO briefed. War room established.",
        ],
    },
    "portscan": {
        "label": "Port Scan/Reconnaissance",
        "analyst": [
            "Reconnaissance activity detected — {src} scanning {scan_count} ports on {targets} hosts in {window} minutes. Scan type: {scan_type}. Top targeted ports: {top_ports}. {services_found} open services discovered. This is pre-attack reconnaissance — no exploitation attempts yet. Pattern suggests automated tool ({tool}).",
        ],
        "intel": [
            "Source {src} flagged as known scanner in Shodan/Censys crawler database. However, scan pattern differs from legitimate research — targeting internal RFC1918 space suggests compromised host or insider. MITRE: T1046 (Network Service Discovery), T1595 (Active Scanning). Correlating with recent vulnerability disclosures for discovered services.",
        ],
        "forensics": [
            "Analyzing scan results per Analyst's data — attacker discovered {services_found} services: {service_list}. Of these, {vuln_count} have known CVEs. Most critical: {critical_service} (CVE-2024-{cveid}, CVSS {cvss}). No exploitation payloads detected in PCAP yet — purely reconnaissance phase. DNS queries from {src} show additional enumeration of internal hostnames.",
        ],
        "business": [
            "Per Forensics — {vuln_count} vulnerable services exposed. If exploited, highest-risk target is {critical_service} which supports {business_function}. Potential impact: {impact_desc}. Current exposure: {exposure_window}. Recommend prioritizing patching per risk-ranked list from Forensics.",
        ],
        "response": [
            "DECISION: Proactive defense — reconnaissance detected, no breach yet:\n\n1️⃣ IMMEDIATE:\n• Rate-limit {src} at IDS — don't fully block (monitor for next-stage attacks)\n• Deploy honeypot on discovered open ports to detect exploitation attempts\n• Fast-track patching for {critical_service} (CVE-2024-{cveid})\n\n2️⃣ HARDENING:\n• Close unnecessary ports identified by scan: {close_ports}\n• Update firewall ACLs to restrict lateral access\n• Enable enhanced logging on {services_found} discovered services\n\n3️⃣ MONITORING:\n• Set up alert for any connection from {src} to discovered services\n• Watch for follow-up exploitation within 48h window\n\nEscalation: SOC Level 1 — monitoring. Upgrade to P2 if exploitation detected.",
        ],
    },
    "phishing": {
        "label": "Phishing Campaign",
        "analyst": [
            "Email security alert — {count} phishing emails detected targeting {dept} department. Subject: '{subject}'. Sender: {sender} (SPF fail, DKIM invalid). {clicked} users clicked the link, {submitted} entered credentials on the spoofed page. Landing page: {phish_url} — clone of {legitimate} login portal. Malicious attachment: {attachment}.",
        ],
        "intel": [
            "Phishing infrastructure analysis — domain {phish_domain} registered {reg_days} days ago on {registrar}. SSL cert from Let's Encrypt (common for phish). IP {phish_ip} hosts {other_phish} other phishing pages. Campaign matches {actor} group's TTPs — previously targeted {sector}. MITRE: T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link). Kit identified: {phish_kit}.",
        ],
        "forensics": [
            "Per Intel's attribution — analyzing {submitted} submitted credential sets. Checking for post-compromise activity: {compromised} accounts show suspicious login from {phish_ip} within {window} minutes of credential submission. Attacker created mail forwarding rules on {forward} accounts. OAuth tokens granted to malicious app '{app_name}'. Timeline: first click {first_click}, first compromise {first_compromise}.",
        ],
        "business": [
            "Forensics confirms {compromised} accounts compromised, {forward} with active forwarding rules (potential data exfiltration). Affected departments: {dept}. Sensitive data at risk: {data_type}. Compliance implications: {compliance_note}. Loss estimate: ${cost}K. Mandatory phishing re-training for {training_count} employees.",
        ],
        "response": [
            "DECISION: Credential compromise response:\n\n1️⃣ IMMEDIATE:\n• Force password reset on {submitted} accounts that entered credentials\n• Revoke OAuth tokens for malicious app '{app_name}'\n• Remove mail forwarding rules on {forward} compromised accounts\n• Block {phish_domain} at DNS and proxy\n\n2️⃣ CONTAINMENT:\n• Review email logs for data exfiltrated via forwarding rules\n• Check for persistence: OAuth apps, app passwords, MFA changes\n• Quarantine remaining phishing emails from {count} deliveries\n\n3️⃣ REMEDIATION:\n• Report {phish_domain} to registrar and Google Safe Browsing\n• Update email gateway rules with new IOCs\n• Deploy mandatory security awareness training for {dept}\n• Implement conditional access policies requiring compliant devices\n\nEscalation: P2 — {compromised} accounts compromised. Legal notified if {data_type} includes PII.",
        ],
    },
    "bot": {
        "label": "Bot/C2 Activity",
        "analyst": [
            "C2 beacon detected — host {host} generating periodic outbound connections to {c2} every {interval}s (±{jitter}s jitter). Protocol: {proto} over port {port}. Beacon payload: {payload_size} bytes, encrypted. Process: {proc} (PID: {pid}). Parent process: {parent}. Host has been beaconing for approximately {duration}.",
        ],
        "intel": [
            "C2 server {c2} identified as {framework} infrastructure. Domain registered to {registrant}. Hosting: {host_provider}. MITRE: T1071.001 (Web Protocols), T1573 (Encrypted Channel), T1105 (Ingress Tool Transfer). Associated campaigns: {campaign}. Estimated botnet size: {botnet_size} hosts globally. Recommend checking for additional infected hosts on network.",
        ],
        "forensics": [
            "Based on Intel's {framework} attribution — memory forensics on {host}: found {framework} implant in {proc} memory space. Persistence via {persistence}. Capabilities: shell access, file exfiltration, keylogging, screenshot capture. Data staging directory: {staging_dir}. {exfil_data} of data queued for exfiltration. Lateral movement attempts to {lateral_targets} detected via {lateral_method}.",
        ],
        "business": [
            "CRITICAL from Forensics — active C2 implant with data exfiltration capability. {exfil_data} staged for theft from {host}. If {host} has access to {sensitive_systems}, assume data compromise. Affected business unit: {dept}. Regulatory notification may be required under {regulation}. Estimated remediation cost: ${cost}K.",
        ],
        "response": [
            "DECISION: Active threat — C2 implant containment:\n\n1️⃣ IMMEDIATE:\n• Network-isolate {host} — maintain power for memory acquisition\n• Block C2 {c2} at DNS, proxy, and firewall (all protocols)\n• Capture full memory dump before any remediation\n• Scan network for additional {framework} beacons (IOCs from Intel)\n\n2️⃣ INVESTIGATION:\n• Analyze staged data in {staging_dir} per Forensics\n• Determine initial access vector (check incoming email, web history)\n• Sweep for lateral movement to {lateral_targets}\n• Review {proc} execution chain in EDR telemetry\n\n3️⃣ REMEDIATION:\n• Reimage {host} from known-good baseline\n• Remove {persistence} persistence mechanism\n• Rotate all credentials stored/accessed on {host}\n• Deploy enhanced monitoring on {lateral_targets}\n\nEscalation: P1 — active data exfiltration attempt. IR team engaged. {regulation} assessment in progress.",
        ],
    },
    "infiltration": {
        "label": "Network Infiltration",
        "analyst": [
            "Suspicious lateral movement — host {host} initiating unusual connections to {targets} internal hosts. Protocols: {protos}. Behavior anomaly score: {anomaly_score}/100. Unusual process execution: {proc} spawning {child_proc}. Credential usage: {cred_user} authenticating to systems outside normal baseline. Time: outside business hours ({time}).",
        ],
        "intel": [
            "Behavior pattern consistent with APT-style network infiltration. TTPs match {apt_group}: living-off-the-land techniques, WMI lateral movement, scheduled task persistence. MITRE mapping: T1021 (Remote Services), T1053 (Scheduled Task), T1047 (WMI). This group targets {sector} for {objective}. Average campaign duration: {campaign_duration}.",
        ],
        "forensics": [
            "Corroborating Analyst's anomaly detection with Intel's APT attribution — discovered {artifacts} artifacts: {artifact_list}. Initial compromise: {entry_point}. Attacker moved from {host} to {pivot_host} using {lateral_method}. Domain admin token harvested from LSASS on {pivot_host}. Data collection targeting: {target_data}. Evidence of {tool} tool usage.",
        ],
        "business": [
            "APT-grade infiltration per Forensics — attacker accessing {target_data}. Intellectual property at risk: {ip_value}. Competitive intelligence exposure: {ci_risk}. If {target_data} exfiltrated, estimated loss: ${ip_cost}M. Investigation timeline: {investigation_days} days estimated. Board and legal notification: mandatory.",
        ],
        "response": [
            "DECISION: APT incident — controlled response to avoid tipping attacker:\n\n1️⃣ PHASE 1 — SILENT MONITORING (0-4h):\n• Deploy enhanced telemetry on affected hosts WITHOUT alerting attacker\n• Map full extent of compromise using EDR historical data\n• Identify all compromised accounts and lateral movement paths\n\n2️⃣ PHASE 2 — COORDINATED CONTAINMENT (scheduled):\n• Simultaneously reset ALL identified compromised credentials\n• Network-isolate affected segment\n• Block all identified C2 and exfiltration channels\n• Deploy memory forensics on {pivot_host} per Forensics findings\n\n3️⃣ PHASE 3 — ERADICATION:\n• Remove {tool} tooling and persistence mechanisms\n• Rebuild compromised systems from trusted media\n• Implement network segmentation to prevent future lateral movement\n• Deploy deception technology (honeypots) in affected segments\n\n4️⃣ PHASE 4 — INTELLIGENCE:\n• Share IOCs with sector ISAC per Intel's {apt_group} attribution\n• Engage threat hunting team for full environment sweep\n• Report to FBI/CISA per APT notification guidelines\n\nEscalation: P1 CRITICAL — CEO, CISO, Legal, Board notified. External IR firm engaged. Law enforcement coordination initiated.",
        ],
    },
}

# Generic fallback for unrecognized attack types — multiple templates per agent for variety
GENERIC_KNOWLEDGE = {
    "analyst": [
        "Security event detected — analyzing indicators for '{title}'. Examining network telemetry, endpoint logs, and authentication events for anomalies. Initial severity assessment: {severity}. Affected scope: {scope}. Correlation engine flagged {correlated} related events in the past {window} minutes. Source IP: {src}. Target system: {host}. Alert triggered at {time_start}.",
        "ALERT: Anomalous activity correlated to '{title}' — {attempts} events across {hosts} hosts in {window}-minute window. Primary indicators on port {port}, service {service}. Endpoint telemetry shows unusual process execution: {proc} → {child_proc}. Behavioral anomaly score: {anomaly_score}/100. Affected sector: {dept} department infrastructure.",
        "Investigating '{title}' — IDS/IPS triggered on {count} suspicious events from source {src}. Traffic analysis reveals {bw} Mbps anomalous flow to {host}. Protocol analysis: {proto} on port {port}. Correlation with historical baselines shows {anomaly_score}% deviation. Endpoint agent on {host} reports {proc} spawning child processes. Recommending immediate deep-dive.",
    ],
    "intel": [
        "Correlating Analyst's IOCs against threat intelligence platforms (OTX, VirusTotal, AbuseIPDB). {match_count} indicators found in threat feeds. Source {src} reputation: flagged in {match_count} out of 7 feeds. MITRE ATT&CK mapping: T{cveid} pattern matches known TTPs. Sector threat landscape for {sector}: elevated. Checking for campaign attribution related to '{title}'.",
        "Running Analyst's indicators — IP {src} linked to {campaign} campaign infrastructure. Geo-trace: {geo}. Domain registrar: {registrar}. MITRE framework: multiple TTPs overlap with {apt_group}. {match_count} IOCs correlated. Threat actor profile suggests {objective} motivation. Sector targeting aligns with {sector} vertical. Intel confidence: HIGH.",
        "Threat intel enrichment for Analyst's findings on '{title}' — source {src} previously observed in {sector} attacks. VirusTotal community score: {anomaly_score}/100. Associated infrastructure: {c2}. MITRE mapping: T1190, T1059. Known toolkit: {framework}. Attack complexity assessment: {severity}. Recommend expanding hunt for related IOCs across the environment.",
    ],
    "forensics": [
        "Collecting evidence based on Analyst's {count} alerts and Intel's {match_count} IOC matches — preserving {artifact_count} artifacts: logs, memory dumps, and network captures. Timeline reconstruction started at {scan_time}. Evidence chain of custody established under case #{cveid}. Key finding: {proc} process on {host} correlating with Intel's {framework} attribution. Full forensic report ETA: {eta}.",
        "Deep forensic analysis responding to '{title}' — examining {artifact_count} artifacts across {hosts} affected hosts. Timeline: initial event at {scan_time}, escalation at {breach_time}. Disk forensics on {host} reveals {proc} with anomalous behavior. Memory analysis shows {exfil_data} of suspicious data staging in {staging_dir}. Network captures confirm communication to {c2} identified by Intel. {backup_status}.",
        "Building forensic timeline per Analyst and Intel findings — {artifact_count} evidence items collected from {host}. Process tree analysis: {parent} → {proc} → {child_proc}. File system changes: {dirs} modified directories. Registry modifications detected in {persistence}. Cross-referencing with Intel's {apt_group} TTPs: {artifacts} matching artifacts found. No evidence of data exfiltration confirmed yet — analysis ongoing.",
    ],
    "business": [
        "Assessing business impact from Forensics findings on '{title}'. Affected systems support {function} in {dept} department. Current operational status: {ops_status}. Risk level: {risk_level}. {compliance} compliance review initiated. Stakeholder notification prepared for {affected_users} affected users. Estimated revenue impact: ${revenue}K. Recovery time estimate: {rte}.",
        "Business impact assessment for '{title}' based on Forensics scope of {hosts} hosts — {dept} operations at {ops_status} status. {priv} privileged accounts potentially affected per Forensics. Financial exposure: ${cost}K estimated. {regulation} notification requirements under review. Customer impact: {users}K users in affected service window. Recommending executive briefing within {board_hours}h.",
        "Impact analysis from Forensics timeline — '{title}' event window: {dur} minutes. Systems supporting {function} in {dept} experienced {ops_status} conditions. Compliance: {compliance} review triggered. If data exposure confirmed, mandatory notification within {notify_hours}h under {regulation}. Estimated remediation cost: ${cost}K. Business continuity: {bcp}.",
    ],
    "response": [
        "DECISION: Implementing response protocol for '{title}' based on cross-agent analysis:\n\n1️⃣ CONTAINMENT (0-{dur} min): Isolate {host} per Forensics findings. Block {src} and C2 {c2} per Intel attribution. Disable compromised account {cred_user}.\n2️⃣ INVESTIGATION: Continue forensic analysis on {artifact_count} artifacts. Expand IOC hunt across {hosts} hosts per Intel's {match_count} indicators.\n3️⃣ REMEDIATION: Patch {critical_service} per vulnerability assessment. Reset credentials for {dept} department.\n4️⃣ RECOVERY: Restore from verified backups. {backup_action}. Validate system integrity.\n5️⃣ MONITORING: Enhanced detection for 72h on affected segment.\n\nEscalation: {risk_level} — {dept} leadership and CISO notified. IR retainer: {ir_firm}.",
        "DECISION: Coordinated response to '{title}':\n\n1️⃣ IMMEDIATE:\n• Block source {src} at perimeter and WAF\n• Isolate {host} — preserve for forensics\n• Revoke sessions for {cred_user} per Forensics findings\n• Apply virtual patch for identified vulnerability\n\n2️⃣ SHORT-TERM (4-8h):\n• Deploy updated detection rules based on Intel's {match_count} IOCs\n• Complete forensic analysis of {artifact_count} remaining artifacts\n• {backup_action}\n\n3️⃣ FOLLOW-UP:\n• {regulation} compliance assessment per Business impact of ${cost}K\n• Post-incident review within 48h\n• Update runbooks for '{title}' scenario\n\nEscalation: {risk_level}. SOC Level 2 engaged. Monitoring enhanced for 72h.",
    ],
}


def _detect_attack_type(title: str) -> str:
    """Detect attack type from risk title using keyword matching."""
    title_lower = title.lower()
    patterns = {
        "ddos": r"ddos|dos[_ ]|denial.?of.?service|flood|amplif",
        "bruteforce": r"brute.?force|credential.?stuff|password.?spray|login.?attempt|auth.?fail",
        "sqli": r"sql.?inject|sqli|union.?select|xss|inject",
        "ransomware": r"ransom|encrypt|lockbit|blackcat|clop|ryuk|conti|\.locked|\.crypt",
        "portscan": r"port.?scan|recon|nmap|scan|enumerat|discovery",
        "phishing": r"phish|spear|social.?eng|credential.?harvest|spoof.?email",
        "bot": r"bot|c2|c&c|beacon|command.?and.?control|cobalt|implant|trojan|malware",
        "infiltration": r"infiltrat|apt|lateral|pivot|exfiltrat|advanced.?persist|insider",
    }
    for attack_type, pattern in patterns.items():
        if re.search(pattern, title_lower):
            return attack_type
    return "generic"


def _seeded_random(title: str, index: int) -> float:
    """Deterministic pseudo-random based on title + index for reproducible discussions."""
    h = hashlib.md5(f"{title}:{index}".encode()).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def _pick(options: list, title: str, index: int) -> str:
    """Pick from list deterministically."""
    r = _seeded_random(title, index)
    return options[int(r * len(options))]


def _fill_template(template: str, title: str, seed_offset: int = 0) -> str:
    """Fill in template placeholders with realistic values."""
    def rv(low, high, idx):
        return int(_seeded_random(title, idx + seed_offset) * (high - low) + low)
    
    ips = [f"{rv(10,220,i)}.{rv(1,254,i+1)}.{rv(1,254,i+2)}.{rv(1,254,i+3)}" for i in range(0, 20, 4)]
    
    replacements = {
        "{rate}": str(rv(50, 800, 10)),
        "{bw}": str(rv(2, 45, 11)),
        "{port}": _pick(["80","443","22","3389","445","8080","3306","53"], title, 12),
        "{geo}": _pick(["Eastern Europe/CIS region","Southeast Asia","South America","West Africa","Multiple geolocations"], title, 13),
        "{hosts}": _pick(["3","5","7","12","15","8"], title, 14),
        "{c2}": _pick(["185.220.101.x","91.215.85.x","194.156.98.x","45.155.205.x","23.106.215.x"], title, 15),
        "{advid}": str(rv(100, 999, 16)),
        "{sector}": _pick(["financial services","healthcare","energy/utilities","government","technology","manufacturing"], title, 17),
        "{proto}": _pick(["DNS","NTP","SSDP","memcached","CLDAP"], title, 18),
        "{time_start}": f"{rv(0,23,19):02d}:{rv(0,59,20):02d} UTC",
        "{time_peak}": f"{rv(0,23,21):02d}:{rv(0,59,22):02d} UTC",
        "{dur}": str(rv(8, 45, 23)),
        "{downtime}": str(rv(5, 30, 24)),
        "{revenue}": str(rv(15, 250, 25)),
        "{sla}": _pick(["99.9%","99.95%","99.5%"], title, 26),
        "{users}": str(rv(2, 50, 27)),
        "{rate_limit}": str(rv(10, 100, 28)),
        "{src}": ips[0],
        "{target}": _pick(["/api/v2/auth","/login","/admin/dashboard","/api/users","/wp-admin","/graphql"], title, 30),
        "{service}": _pick(["SSH","RDP","O365","VPN","SMTP","LDAP","HTTP-Auth"], title, 31),
        "{attempts}": str(rv(500, 15000, 32)),
        "{window}": str(rv(15, 120, 33)),
        "{accounts}": str(rv(5, 50, 34)),
        "{delay}": str(rv(2, 30, 35)),
        "{rate}": str(rv(5, 100, 36)),
        "{quarter}": str(rv(1, 4, 37)),
        "{pyver}": _pick(["2.31.0","2.28.1","2.32.3"], title, 38),
        "{success}": str(rv(0, 5, 39)),
        "{proxies}": str(rv(3, 15, 40)),
        "{dept}": _pick(["Engineering","Finance","HR","Executive","Operations","IT","Legal"], title, 41),
        "{priv}": str(rv(1, 4, 42)),
        "{compliance}": _pick(["GDPR","HIPAA","PCI-DSS","SOX","CCPA"], title, 43),
        "{cost}": str(rv(50, 500, 44)),
        "{count}": str(rv(10, 500, 45)),
        "{tech}": _pick(["MySQL/PHP","PostgreSQL","MSSQL/.NET","MongoDB","Oracle DB"], title, 46),
        "{cveid}": str(rv(10000, 99999, 47)),
        "{exfil}": str(rv(3, 25, 48)),
        "{tables}": str(rv(2, 12, 49)),
        "{rows}": str(rv(100, 50000, 50)),
        "{db_name}": _pick(["users_db","main_prod","customer_data","app_backend","inventory"], title, 51),
        "{table}": _pick(["users","credentials","transactions","pii_records","contacts"], title, 52),
        "{pii_fields}": _pick(["email, hashed_password","full_name, SSN, DOB","email, phone, address","credit_card (last4), email","employee_id, salary, SSN"], title, 53),
        "{ttfs}": str(rv(5, 45, 54)),
        "{scan_time}": f"{rv(0,23,55):02d}:{rv(0,59,56):02d}",
        "{breach_time}": f"{rv(0,23,57):02d}:{rv(0,59,58):02d}",
        "{regulation}": _pick(["GDPR","HIPAA","PCI-DSS","CCPA","SOC 2"], title, 59),
        "{article}": _pick(["33","34","12","7.2","164.400"], title, 60),
        "{notify_hours}": _pick(["72","48","24","36"], title, 61),
        "{affected_users}": str(rv(100, 25000, 62)),
        "{classification}": _pick(["PII — Restricted","PHI — Confidential","Financial — Critical","Internal — Sensitive"], title, 63),
        "{notify_cost}": str(rv(20, 150, 64)),
        "{monitor_cost}": str(rv(30, 200, 65)),
        "{legal_cost}": str(rv(50, 300, 66)),
        "{proc}": _pick(["svchost.exe","rundll32.exe","regsvr32.exe","powershell.exe","msiexec.exe","chrome_update.exe"], title, 67),
        "{ext}": _pick(["locked","crypt","enc","blackcat","XXXXXX"], title, 68),
        "{note}": _pick(["README_RESTORE.txt","DECRYPT_FILES.html","!!! READ ME !!!.txt","RECOVER-FILES.txt"], title, 69),
        "{dirs}": str(rv(50, 500, 70)),
        "{lateral}": _pick(["PsExec","WMI","RDP","SMB share copy","GPO deployment"], title, 71),
        "{hash}": f"a{rv(1,9,72)}b{rv(1,9,73)}c...{rv(100,999,74)}",
        "{btc}": _pick(["2.5","5","10","15","25","50"], title, 75),
        "{shares}": str(rv(3, 20, 76)),
        "{family}": _pick(["LockBit 3.0","BlackCat/ALPHV","Clop","Royal","Play","Rhysida"], title, 77),
        "{actor}": _pick(["UNC3944","FIN7","Scattered Spider","REvil affiliate","DarkSide successor"], title, 78),
        "{domain}": _pick(["check-update.xyz","cdn-global.top","secure-verify.cloud","api-endpoint.info"], title, 79),
        "{access}": _pick(["phishing email","VPN credential theft","RDP brute-force","supply chain compromise","exposed Citrix gateway"], title, 80),
        "{framework}": _pick(["Cobalt Strike","Sliver","Brute Ratel","Metasploit","Havoc"], title, 81),
        "{dwell}": str(rv(3, 21, 82)),
        "{dwell_mid}": str(rv(2, 10, 83)),
        "{decryptor}": _pick(["not available","available for v1 only","in development by NoMoreRansom","not applicable"], title, 84),
        "{enc_tb}": _pick(["0.8","1.5","2.3","4.1","6.7"], title, 85),
        "{backup_status}": _pick(["Offline backups intact — last verified 24h ago","Backup server compromised — attacker deleted snapshots","Cloud backups available — 48h RPO","Tape backups available — 7-day RPO"], title, 86),
        "{admin}": _pick(["svc_admin","domain_admin","backup_admin","enterprise_admin"], title, 87),
        "{user}": _pick(["j.smith@corp","m.jones@finance","a.patel@engineering","c.williams@hr"], title, 88),
        "{pivot_hours}": str(rv(4, 48, 89)),
        "{enc_time}": f"{rv(0,23,90):02d}:{rv(0,59,91):02d} UTC",
        "{ops_status}": _pick(["60% degraded","fully offline","critical systems only","partial operations"], title, 92),
        "{backup_status_biz}": _pick(["Offline backups verified — recovery possible","All backups compromised — full rebuild required","Cloud DR available — 4h RTO","Partial backups — 72h estimated recovery"], title, 93),
        "{ransom_usd}": str(rv(250, 5000, 94)),
        "{recovery_days}": str(rv(3, 21, 95)),
        "{bcp}": _pick(["activating DR site","manual operations commenced","cloud failover initiated","degraded mode — paper processes"], title, 96),
        "{rev_impact}": str(rv(100, 2000, 97)),
        "{recovery_cost}": str(rv(200, 3000, 98)),
        "{deductible}": str(rv(50, 500, 99)),
        "{board_hours}": _pick(["4","8","12","24"], title, 100),
        "{ir_firm}": _pick(["CrowdStrike IR","Mandiant","Secureworks","Unit 42","Kroll"], title, 101),
        "{backup_source}": _pick(["offline tape backups","cloud DR snapshots","immutable S3 backups","replicated standby DC"], title, 102),
        "{backup_action}": _pick(["verify offline backup integrity immediately","initiate cloud DR failover","test tape restore on isolated host","validate immutable snapshot chain"], title, 103),
        "{scan_count}": str(rv(1000, 65535, 104)),
        "{targets}": str(rv(5, 50, 105)),
        "{scan_type}": _pick(["SYN stealth scan","full TCP connect","UDP scan","XMAS scan","ACK scan"], title, 106),
        "{top_ports}": _pick(["22, 80, 443, 3389, 8080","21, 22, 23, 25, 80","445, 3306, 5432, 6379, 27017","80, 443, 8443, 8080, 9090"], title, 107),
        "{services_found}": str(rv(5, 25, 108)),
        "{tool}": _pick(["Nmap","Masscan","ZMap","Angry IP Scanner","custom Python scanner"], title, 109),
        "{service_list}": _pick(["SSH(22), HTTP(80), HTTPS(443), MySQL(3306), RDP(3389)","FTP(21), SSH(22), SMTP(25), HTTP(80), SMB(445)","HTTP(80), HTTPS(443), PostgreSQL(5432), Redis(6379), MongoDB(27017)"], title, 110),
        "{vuln_count}": str(rv(2, 8, 111)),
        "{critical_service}": _pick(["Apache Tomcat 9.0.x","OpenSSH 8.2","Microsoft Exchange","Citrix ADC","VMware vCenter"], title, 112),
        "{cvss}": _pick(["9.8","9.1","8.6","8.1","7.5"], title, 113),
        "{business_function}": _pick(["customer portal","internal HR system","payment processing","email infrastructure","CI/CD pipeline"], title, 114),
        "{impact_desc}": _pick(["full customer data access","internal communications compromise","payment card data exposure","source code theft","supply chain risk"], title, 115),
        "{exposure_window}": _pick(["unknown — service unpatched since deployment","72h since CVE disclosure","30 days since last scan","recently deployed — first exposure"], title, 116),
        "{close_ports}": _pick(["FTP(21), Telnet(23), SMB(445)","RDP(3389), VNC(5900), MySQL(3306)","Redis(6379), MongoDB(27017), Elasticsearch(9200)"], title, 117),
        "{subject}": _pick(["Urgent: Password Reset Required","Invoice #INV-2024-{id} Attached","[IT Support] Account Verification","Meeting Recording: Q4 Review","DocuSign: Document Ready for Signature"], title, 118),
        "{sender}": _pick(["it-support@c0rp-mail.com","admin@micros0ft-verify.com","noreply@docusign-secure.net","helpdesk@support-portal.xyz"], title, 119),
        "{clicked}": str(rv(3, 25, 120)),
        "{submitted}": str(rv(1, 10, 121)),
        "{phish_url}": _pick(["hxxps://c0rp-login.com/auth","hxxps://verify-account.xyz/login","hxxps://secure-portal.cloud/sso"], title, 122),
        "{legitimate}": _pick(["Microsoft 365","Google Workspace","Okta SSO","corporate VPN"], title, 123),
        "{attachment}": _pick(["Invoice_2024.xlsm (macro-enabled)","Meeting_Notes.iso","Security_Update.exe","Document.html (credential harvester)","none — link-only"], title, 124),
        "{phish_domain}": _pick(["c0rp-login.com","verify-account.xyz","secure-portal.cloud","micros0ft-auth.net"], title, 125),
        "{reg_days}": str(rv(1, 14, 126)),
        "{registrar}": _pick(["Namecheap","Tucows","GoDaddy","Porkbun"], title, 127),
        "{phish_ip}": ips[1],
        "{other_phish}": str(rv(3, 20, 129)),
        "{phish_kit}": _pick(["EvilGinx2","Gophish","Modlishka","custom kit"], title, 130),
        "{compromised}": str(rv(1, 8, 131)),
        "{forward}": str(rv(1, 5, 132)),
        "{first_click}": f"{rv(8,17,133):02d}:{rv(0,59,134):02d}",
        "{first_compromise}": f"{rv(8,17,135):02d}:{rv(0,59,136):02d}",
        "{app_name}": _pick(["Mail Sync Pro","Cloud Backup Assistant","Security Scanner","Document Viewer"], title, 137),
        "{data_type}": _pick(["PII (employee records)","financial data","customer contracts","source code","strategic plans"], title, 138),
        "{compliance_note}": _pick(["GDPR Art. 33 notification required","HIPAA breach notification triggered","SOX audit implications","PCI-DSS incident reporting required"], title, 139),
        "{training_count}": str(rv(50, 500, 140)),
        "{host}": _pick(["WS-FIN-042","SRV-APP-017","DC-PROD-01","WS-ENG-088","LAPTOP-EXEC-03"], title, 141),
        "{interval}": str(rv(30, 300, 142)),
        "{jitter}": str(rv(2, 30, 143)),
        "{payload_size}": str(rv(64, 1024, 144)),
        "{pid}": str(rv(1000, 65535, 145)),
        "{parent}": _pick(["explorer.exe","wmiprvse.exe","services.exe","cmd.exe","outlook.exe"], title, 146),
        "{duration}": _pick(["~6 hours","~2 days","~12 hours","~4 days","~36 hours"], title, 147),
        "{registrant}": _pick(["privacy-protected WHOIS","fake registrant in Russia","shell company in Seychelles","compromised legitimate account"], title, 148),
        "{host_provider}": _pick(["DigitalOcean VPS","Hetzner dedicated","OVH cloud","bullet-proof hosting"], title, 149),
        "{campaign}": _pick(["SolarPhoenix","DarkHarvest","OperationWebShell","SilentTrident"], title, 150),
        "{botnet_size}": _pick(["~5,000","~12,000","~50,000","~200,000"], title, 151),
        "{persistence}": _pick(["HKLM\\Run registry key","scheduled task 'WindowsUpdate'","WMI event subscription","DLL search order hijack","service creation 'SysMonitor'"], title, 152),
        "{staging_dir}": _pick(["C:\\ProgramData\\.cache","C:\\Users\\Public\\Downloads","C:\\Windows\\Temp\\svc","C:\\Intel\\Logs"], title, 153),
        "{exfil_data}": _pick(["2.3 GB","450 MB","8.1 GB","1.1 GB","340 MB"], title, 154),
        "{lateral_targets}": _pick(["DC-PROD-01, SRV-FILE-03","SRV-DB-01, WS-FIN-042","SRV-APP-017, SRV-WEB-02"], title, 155),
        "{lateral_method}": _pick(["pass-the-hash","WMI remote execution","PSRemoting","RDP with stolen creds"], title, 156),
        "{sensitive_systems}": _pick(["financial database","customer PII store","source code repository","executive email","HR system"], title, 157),
        "{protos}": _pick(["SMB, WMI, RDP","SSH, RDP, WinRM","LDAP, Kerberos, SMB","RPC, WMI, PSRemoting"], title, 158),
        "{anomaly_score}": str(rv(75, 98, 159)),
        "{child_proc}": _pick(["cmd.exe → whoami","powershell.exe → Invoke-Expression","wmic.exe → shadowcopy delete","net.exe → net user /domain"], title, 160),
        "{cred_user}": _pick(["svc_backup","admin_tier0","da_maintenance","enterprise_svc"], title, 161),
        "{time}": f"{rv(22,4,162) % 24:02d}:{rv(0,59,163):02d} local",
        "{apt_group}": _pick(["APT29 (Cozy Bear)","APT41 (Double Dragon)","Lazarus Group","FIN7","Turla"], title, 164),
        "{objective}": _pick(["intellectual property theft","financial fraud","espionage","supply chain access","ransomware deployment"], title, 165),
        "{campaign_duration}": _pick(["6-18 months","3-9 months","12-24 months","2-6 months"], title, 166),
        "{artifacts}": str(rv(8, 30, 167)),
        "{artifact_list}": _pick(["modified DLLs, scheduled tasks, registry keys, web shells","encoded PowerShell scripts, tunneling tools, credential dumps","custom backdoors, DNS tunneling configs, exfiltration scripts"], title, 168),
        "{entry_point}": _pick(["spearphishing email to executive","compromised VPN credentials","supply chain software update","exposed Citrix gateway","watering hole on industry blog"], title, 169),
        "{pivot_host}": _pick(["DC-PROD-01","SRV-FILE-03","WS-EXEC-01","SRV-EXCHANGE-01"], title, 170),
        "{target_data}": _pick(["R&D project files","M&A documents","customer database","financial projections","proprietary algorithms"], title, 171),
        "{ip_value}": _pick(["estimated $50M+ in R&D investment","core competitive advantage","regulated customer data","strategic planning documents"], title, 172),
        "{ci_risk}": _pick(["HIGH — active competitor intelligence operation suspected","CRITICAL — state-sponsored espionage indicators","MEDIUM — opportunistic data theft","HIGH — targeted industry vertical"], title, 173),
        "{ip_cost}": _pick(["5-15","10-50","2-8","25-100"], title, 174),
        "{investigation_days}": str(rv(14, 90, 175)),
        "{title}": title,
        "{severity}": _pick(["HIGH","CRITICAL","MEDIUM"], title, 177),
        "{scope}": _pick(["3 hosts in DMZ","production web cluster","finance department workstations","single endpoint"], title, 178),
        "{correlated}": str(rv(3, 20, 179)),
        "{match_count}": str(rv(2, 15, 180)),
        "{artifact_count}": str(rv(5, 25, 181)),
        "{eta}": _pick(["2-4 hours","4-8 hours","24 hours","ongoing"], title, 182),
        "{function}": _pick(["customer-facing web services","internal communications","payment processing","HR operations","DevOps pipeline"], title, 183),
        "{ops_status}": _pick(["operational — monitoring enhanced","degraded — non-critical services affected","critical — primary services impacted"], title, 184),
        "{risk_level}": _pick(["HIGH","CRITICAL","ELEVATED"], title, 185),
        "{rte}": _pick(["4-8 hours","24-48 hours","2-5 business days","under assessment"], title, 186),
    }
    
    result = template
    for key, value in replacements.items():
        result = result.replace(key, value)
    return result


def generate_local_discussion(
    risk_title: str,
    agents: Optional[List[str]] = None,
) -> list:
    """
    Generate a multi-agent discussion locally without external AI APIs.
    Follows the SOC pipeline: Analyst → Intel → Forensics → Business → Response.
    """
    allowed = ["analyst", "intel", "forensics", "business", "response"]
    selected = [a for a in (agents or allowed) if a in allowed]
    if not selected:
        selected = allowed

    attack_type = _detect_attack_type(risk_title)
    
    if attack_type != "generic" and attack_type in ATTACK_KNOWLEDGE:
        knowledge = ATTACK_KNOWLEDGE[attack_type]
    else:
        knowledge = None

    discussion = []
    offsets = {"analyst": 0, "intel": 15, "forensics": 45, "business": 90, "response": 120}
    
    for i, agent in enumerate(selected):
        if knowledge and agent in knowledge:
            templates = knowledge[agent]
        elif agent in GENERIC_KNOWLEDGE:
            templates = GENERIC_KNOWLEDGE[agent]
        else:
            continue
        
        template = _pick(templates, risk_title, i * 100)
        message = _fill_template(template, risk_title, seed_offset=i * 200)
        
        discussion.append({
            "agent": agent,
            "message": message,
            "timestamp_offset_seconds": offsets.get(agent, i * 30),
        })

    return discussion


@router.post("/analyze/{incident_id}")
async def analyze_incident(
    incident_id: str,
    risk_title: Optional[str] = Query(None),
    agents: Optional[List[str]] = Query(
        None,
        description="Specific agents to use (analyst, intel, forensics, business, response). Uses all if not specified."
    ),
    current_user: Optional[TokenData] = Depends(get_current_user_optional),
    db: Optional[AsyncSession] = Depends(get_db)
):
    """
    Run AI agent analysis on an incident.
    """
    
    # DEMO MODE: Bypass auth and logic if incident_id is 'demo'
    if incident_id == "demo":
        import asyncio
        from datetime import datetime, timedelta
        
        # Brief processing delay
        await asyncio.sleep(0.3)
        
        current_time_obj = datetime.now()
        
        def get_time(offset_seconds):
            return (current_time_obj + timedelta(seconds=offset_seconds)).strftime("%H:%M:%S")

        # Dynamic discussion generation based on risk_title
        title = risk_title or "Detected Security Event"
        
        discussion = []

        # Try Gemini first, fall back to built-in engine
        try:
            gemini = GeminiService()
            gemini_discussion = await gemini.generate_agent_discussion(
                risk_title=title,
                agents=agents
            )
            discussion = [
                {
                    "agent": item["agent"],
                    "message": item["message"],
                    "timestamp": get_time(item.get("timestamp_offset_seconds", 0))
                }
                for item in gemini_discussion
            ]
            logger.info("✓ Generated agent discussion using Gemini API", risk_title=title, num_messages=len(discussion))
            
            return {
                "status": "completed",
                "incident_id": "demo",
                "discussion": discussion,
                "generated_by": "gemini"
            }
        except (GeminiServiceError, Exception) as e:
            logger.warning("Gemini unavailable, using built-in discussion engine", error=str(e))
            
            # ── Built-in fallback: deterministic agent discussion ──
            local_discussion = generate_local_discussion(title, agents)
            discussion = [
                {
                    "agent": item["agent"],
                    "message": item["message"],
                    "timestamp": get_time(item["timestamp_offset_seconds"])
                }
                for item in local_discussion
            ]
            logger.info("✓ Generated agent discussion using built-in engine", risk_title=title, num_messages=len(discussion))
            
            return {
                "status": "completed",
                "incident_id": "demo",
                "discussion": discussion,
                "generated_by": "built-in"
            }

    # Normal flow requires auth
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    # Get incident data
    incident_service = IncidentService(db)
    incident = await incident_service.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Prepare incident data for agents
    incident_data = {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "type": incident.incident_type,
        "status": incident.status,
        "created_at": incident.created_at.isoformat() if incident.created_at else None
    }
    
    # Get orchestrator
    orchestrator = get_orchestrator()
    
    # Run analysis
    if agents:
        # Targeted analysis with specific agents
        valid_agents = ["analyst", "intel", "forensics", "business", "response"]
        invalid = [a for a in agents if a not in valid_agents]
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid agent types: {invalid}. Valid options: {valid_agents}"
            )
        
        result = await orchestrator.targeted_analysis(
            incident_data=incident_data,
            agent_types=agents
        )
    else:
        # Full multi-agent analysis
        result = await orchestrator.full_analysis(incident_data=incident_data)
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.ANALYSIS_COMPLETE,
        data={
            "incident_id": incident_id,
            "agents_used": agents or ["all"],
            "consensus_severity": result.get("consensus_report", {}).get("consensus_severity")
        },
        actor=current_user.user_id
    )
    
    logger.info(
        "Agent analysis complete",
        incident_id=incident_id,
        agents=agents or "all",
        user_id=current_user.user_id
    )
    
    return result


@router.get("/status")
async def get_agent_status(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get status of all AI agents.
    """
    orchestrator = get_orchestrator()
    
    return {
        "agents": {
            name: {
                "name": agent.name,
                "type": agent.agent_type,
                "status": "active"
            }
            for name, agent in orchestrator.agents.items()
        },
        "orchestrator_status": "active"
    }


@router.post("/query")
async def query_agent(
    agent_type: str,
    query: str,
    context: Optional[Dict[str, Any]] = None,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Query a specific agent directly with custom input.
    
    - **agent_type**: Agent to query (analyst, intel, forensics, business, response)
    - **query**: Question or analysis request
    - **context**: Optional additional context
    """
    valid_agents = ["analyst", "intel", "forensics", "business", "response"]
    
    if agent_type not in valid_agents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid agent type. Must be one of: {valid_agents}"
        )
    
    orchestrator = get_orchestrator()
    agent = orchestrator.agents[agent_type]
    
    # Create pseudo-incident data from query
    incident_data = {
        "id": "direct-query",
        "type": "custom_query",
        "severity": "medium",
        "description": query
    }
    
    result = await agent.analyze(incident_data, context)
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.AGENT_INVOKED,
        data={
            "agent_type": agent_type,
            "query_length": len(query),
            "has_context": context is not None
        },
        actor=current_user.user_id
    )
    
    return result


@router.get("/capabilities")
async def get_agent_capabilities(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get capabilities of all AI agents.
    """
    return {
        "agents": [
            {
                "type": "analyst",
                "name": "Security Analyst",
                "capabilities": [
                    "Log analysis and correlation",
                    "Attack pattern recognition",
                    "Initial triage and classification",
                    "Severity assessment"
                ]
            },
            {
                "type": "intel",
                "name": "Threat Intelligence Specialist",
                "capabilities": [
                    "Threat actor attribution",
                    "TTP mapping to MITRE ATT&CK",
                    "IOC extraction and correlation",
                    "Threat landscape assessment"
                ]
            },
            {
                "type": "forensics",
                "name": "Digital Forensics Analyst",
                "capabilities": [
                    "Evidence analysis",
                    "Timeline reconstruction",
                    "Artifact examination",
                    "Chain of custody documentation"
                ]
            },
            {
                "type": "business",
                "name": "Business Impact Analyst",
                "capabilities": [
                    "Financial impact assessment",
                    "Operational impact analysis",
                    "Regulatory compliance checking",
                    "Stakeholder communication planning"
                ]
            },
            {
                "type": "response",
                "name": "Response Coordinator",
                "capabilities": [
                    "Incident response planning",
                    "Playbook recommendations",
                    "Resource coordination",
                    "Recovery planning"
                ]
            }
        ],
        "orchestrator": {
            "name": "Multi-Agent Orchestrator",
            "capabilities": [
                "Parallel agent execution",
                "Consensus generation",
                "Cross-agent validation",
                "Prioritized recommendations"
            ]
        }
    }
