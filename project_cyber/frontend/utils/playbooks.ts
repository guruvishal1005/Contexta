
export interface PlaybookStep {
    order: number;
    name: string;
    description: string;
    action_type: string;
    automation_script?: string;
    timeout_minutes: number;
    required: boolean;
}

export interface Playbook {
    id: string;
    name: string;
    description: string;
    version: string;
    category: string;
    severity_threshold: string;
    steps: PlaybookStep[];
}

export const PLAYBOOKS: Record<string, Playbook> = {
    'malware-containment': {
        "id": "malware-containment",
        "name": "Malware Containment Playbook",
        "description": "Standard playbook for containing malware incidents",
        "version": "1.0",
        "category": "containment",
        "severity_threshold": "medium",
        "steps": [
            {
                "order": 1,
                "name": "Isolate Affected System",
                "description": "Disconnect the affected system from the network",
                "action_type": "manual",
                "timeout_minutes": 15,
                "required": true
            },
            {
                "order": 2,
                "name": "Preserve Evidence",
                "description": "Capture memory dump and disk image before remediation",
                "action_type": "manual",
                "timeout_minutes": 60,
                "required": true
            },
            {
                "order": 3,
                "name": "Identify Malware Type",
                "description": "Run malware analysis tools to identify the threat",
                "action_type": "automated",
                "automation_script": "analyze_malware.py",
                "timeout_minutes": 30,
                "required": true
            },
            {
                "order": 4,
                "name": "Block IOCs",
                "description": "Add identified IOCs to blocklists",
                "action_type": "automated",
                "automation_script": "block_iocs.py",
                "timeout_minutes": 10,
                "required": true
            },
            {
                "order": 5,
                "name": "Scan Related Systems",
                "description": "Scan systems that communicated with affected host",
                "action_type": "automated",
                "automation_script": "network_scan.py",
                "timeout_minutes": 60,
                "required": false
            },
            {
                "order": 6,
                "name": "Remediate System",
                "description": "Remove malware or reimage system",
                "action_type": "manual",
                "timeout_minutes": 120,
                "required": true
            },
            {
                "order": 7,
                "name": "Restore Network Access",
                "description": "Reconnect system after verification",
                "action_type": "manual",
                "timeout_minutes": 15,
                "required": true
            }
        ]
    },
    'data-breach-response': {
        "id": "data-breach-response",
        "name": "Data Breach Response Playbook",
        "description": "Comprehensive playbook for responding to data breach incidents",
        "version": "1.0",
        "category": "breach_response",
        "severity_threshold": "high",
        "steps": [
            {
                "order": 1,
                "name": "Confirm Data Breach",
                "description": "Verify that a data breach has occurred",
                "action_type": "manual",
                "timeout_minutes": 30,
                "required": true
            },
            {
                "order": 2,
                "name": "Activate Incident Response Team",
                "description": "Notify and assemble the IR team including legal and PR",
                "action_type": "automated",
                "automation_script": "notify_ir_team.py",
                "timeout_minutes": 15,
                "required": true
            },
            {
                "order": 3,
                "name": "Contain the Breach",
                "description": "Stop ongoing data exfiltration",
                "action_type": "manual",
                "timeout_minutes": 60,
                "required": true
            },
            {
                "order": 4,
                "name": "Preserve Evidence",
                "description": "Secure logs, network captures, and forensic images",
                "action_type": "automated",
                "automation_script": "preserve_evidence.py",
                "timeout_minutes": 120,
                "required": true
            },
            {
                "order": 5,
                "name": "Assess Data Exposure",
                "description": "Determine what data was accessed or exfiltrated",
                "action_type": "manual",
                "timeout_minutes": 240,
                "required": true
            },
            {
                "order": 6,
                "name": "Identify Affected Individuals",
                "description": "Compile list of affected customers/employees",
                "action_type": "manual",
                "timeout_minutes": 480,
                "required": true
            },
            {
                "order": 7,
                "name": "Legal Assessment",
                "description": "Determine regulatory notification requirements",
                "action_type": "manual",
                "timeout_minutes": 120,
                "required": true
            },
            {
                "order": 8,
                "name": "Prepare Notifications",
                "description": "Draft notifications for regulators and affected parties",
                "action_type": "manual",
                "timeout_minutes": 240,
                "required": true
            },
            {
                "order": 9,
                "name": "Submit Regulatory Notifications",
                "description": "Submit required notifications (CERT-In within 6 hours)",
                "action_type": "manual",
                "timeout_minutes": 60,
                "required": true
            },
            {
                "order": 10,
                "name": "Notify Affected Parties",
                "description": "Send notifications to affected individuals",
                "action_type": "automated",
                "automation_script": "send_breach_notifications.py",
                "timeout_minutes": 480,
                "required": true
            },
            {
                "order": 11,
                "name": "Remediate Vulnerabilities",
                "description": "Fix the security gaps that led to the breach",
                "action_type": "manual",
                "timeout_minutes": 1440,
                "required": true
            },
            {
                "order": 12,
                "name": "Post-Incident Review",
                "description": "Conduct lessons learned session",
                "action_type": "manual",
                "timeout_minutes": 120,
                "required": true
            }
        ]
    }
};
