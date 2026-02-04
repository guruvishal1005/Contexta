"""
Contexta Backend - Response Coordination Agent

This agent plans and coordinates incident response actions.
"""

from typing import Dict, Any, List
import structlog

from app.agents.base import BaseAgent

logger = structlog.get_logger()


class ResponseAgent(BaseAgent):
    """
    Response Coordination Agent.
    
    Responsibilities:
    - Response action planning
    - Resource coordination
    - Playbook recommendations
    - Communication coordination
    - Recovery planning
    """
    
    def __init__(self):
        super().__init__(
            name="Response Coordinator",
            agent_type="response"
        )
    
    async def analyze(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Plan response actions for an incident.
        
        Args:
            incident_data: Incident details
            context: Additional context including:
                - available resources
                - existing playbooks
                - affected systems status
                
        Returns:
            Response plan with:
                - immediate_actions
                - containment_steps
                - eradication_plan
                - recovery_steps
                - playbook_recommendations
        """
        logger.info(
            "Response agent starting analysis",
            incident_id=incident_data.get("id")
        )
        
        # Call Gemini for AI-powered analysis
        analysis = await self._call_gemini(incident_data, context)
        
        # Add structured response plan
        enriched = self._create_response_plan(analysis, incident_data, context)
        
        return self._format_result(enriched)
    
    def _create_response_plan(
        self,
        analysis: Dict[str, Any],
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create structured response plan.
        
        Args:
            analysis: Raw AI analysis
            incident_data: Original incident data
            context: Additional context
            
        Returns:
            Response plan
        """
        context = context or {}
        incident_type = incident_data.get("type", "unknown")
        severity = incident_data.get("severity", "medium")
        
        # Map incident types to playbook recommendations
        playbook_map = {
            "malware": ["malware-containment", "endpoint-isolation", "forensic-collection"],
            "ransomware": ["ransomware-response", "backup-verification", "ransom-decision-tree"],
            "data_breach": ["data-breach-response", "evidence-preservation", "notification-workflow"],
            "ddos": ["ddos-mitigation", "traffic-analysis", "capacity-scaling"],
            "phishing": ["phishing-response", "credential-reset", "awareness-campaign"],
            "insider_threat": ["insider-threat-response", "access-revocation", "legal-coordination"],
            "apt": ["apt-response", "threat-hunting", "network-segmentation"],
            "vulnerability_exploitation": ["patch-management", "vulnerability-remediation", "network-isolation"],
            "unauthorized_access": ["access-incident-response", "credential-reset", "mfa-enforcement"],
            "unknown": ["generic-incident-response", "triage-workflow"]
        }
        
        analysis["recommended_playbooks"] = playbook_map.get(
            incident_type, 
            playbook_map["unknown"]
        )
        
        # Create phase-based response plan
        analysis["response_phases"] = {
            "phase_1_detection": {
                "status": "completed",
                "duration": "0-15 minutes",
                "actions": [
                    "Alert received and acknowledged",
                    "Initial triage completed",
                    "Severity assessment done"
                ]
            },
            "phase_2_containment": {
                "status": "in_progress" if severity in ["critical", "high"] else "pending",
                "duration": "15-60 minutes",
                "actions": self._get_containment_actions(incident_type)
            },
            "phase_3_eradication": {
                "status": "pending",
                "duration": "1-24 hours",
                "actions": self._get_eradication_actions(incident_type)
            },
            "phase_4_recovery": {
                "status": "pending",
                "duration": "24-72 hours",
                "actions": [
                    "Restore from clean backups",
                    "Validate system integrity",
                    "Gradual service restoration",
                    "Monitor for recurrence"
                ]
            },
            "phase_5_lessons_learned": {
                "status": "pending",
                "duration": "1-2 weeks post-incident",
                "actions": [
                    "Conduct post-incident review",
                    "Document timeline and actions",
                    "Identify improvement areas",
                    "Update playbooks and procedures"
                ]
            }
        }
        
        # Add resource requirements
        analysis["resource_requirements"] = self._estimate_resources(severity)
        
        # Add communication plan
        analysis["communication_plan"] = {
            "internal": {
                "frequency": "Every 30 minutes" if severity == "critical" else "Every hour",
                "channels": ["Incident Slack channel", "Status page", "Email"],
                "stakeholders": ["SOC Team", "Management", "Affected teams"]
            },
            "external": {
                "required": severity in ["critical", "high"],
                "channels": ["Customer portal", "PR statement", "Regulatory filing"],
                "approval_required": True
            }
        }
        
        return analysis
    
    def _get_containment_actions(self, incident_type: str) -> List[str]:
        """Get containment actions based on incident type."""
        containment_map = {
            "malware": [
                "Isolate affected endpoints from network",
                "Block malicious IPs/domains at firewall",
                "Disable compromised accounts",
                "Preserve evidence before remediation"
            ],
            "ransomware": [
                "Immediately disconnect affected systems",
                "Block lateral movement paths",
                "Isolate backup systems",
                "Engage incident response team"
            ],
            "data_breach": [
                "Identify and isolate compromised systems",
                "Revoke compromised credentials",
                "Block data exfiltration channels",
                "Enable enhanced logging"
            ],
            "ddos": [
                "Enable DDoS protection services",
                "Rate limit suspicious traffic",
                "Scale infrastructure capacity",
                "Activate CDN caching"
            ],
            "phishing": [
                "Block phishing URLs/domains",
                "Quarantine phishing emails",
                "Reset compromised credentials",
                "Alert targeted users"
            ],
            "unauthorized_access": [
                "Disable compromised accounts",
                "Terminate active sessions",
                "Block source IPs",
                "Review access logs"
            ]
        }
        
        return containment_map.get(incident_type, [
            "Isolate affected systems",
            "Block suspicious activity",
            "Preserve evidence",
            "Assess scope of impact"
        ])
    
    def _get_eradication_actions(self, incident_type: str) -> List[str]:
        """Get eradication actions based on incident type."""
        eradication_map = {
            "malware": [
                "Run full antimalware scans",
                "Remove malicious files and registry entries",
                "Patch exploited vulnerabilities",
                "Rebuild severely compromised systems"
            ],
            "ransomware": [
                "Wipe and reimage affected systems",
                "Restore from clean backups",
                "Patch entry point vulnerabilities",
                "Strengthen endpoint protection"
            ],
            "data_breach": [
                "Remove attacker persistence mechanisms",
                "Rotate all potentially compromised credentials",
                "Patch exploited vulnerabilities",
                "Implement additional controls"
            ],
            "phishing": [
                "Remove phishing emails from all mailboxes",
                "Block attacker infrastructure",
                "Reset all potentially compromised passwords",
                "Enable MFA for affected accounts"
            ]
        }
        
        return eradication_map.get(incident_type, [
            "Remove malicious artifacts",
            "Patch vulnerabilities",
            "Reset compromised credentials",
            "Strengthen security controls"
        ])
    
    def _estimate_resources(self, severity: str) -> Dict[str, Any]:
        """Estimate resource requirements based on severity."""
        resource_map = {
            "critical": {
                "team_size": "Full SOC team + external IR support",
                "estimated_hours": "100-500 hours",
                "roles_needed": [
                    "Incident Commander",
                    "Technical Lead",
                    "Forensics Analyst",
                    "Communications Lead",
                    "Legal Counsel"
                ],
                "external_support": "Recommended"
            },
            "high": {
                "team_size": "5-8 responders",
                "estimated_hours": "40-100 hours",
                "roles_needed": [
                    "Incident Lead",
                    "Security Analysts (2-3)",
                    "System Administrators (1-2)",
                    "Communications"
                ],
                "external_support": "As needed"
            },
            "medium": {
                "team_size": "2-4 responders",
                "estimated_hours": "8-40 hours",
                "roles_needed": [
                    "Security Analyst",
                    "System Administrator"
                ],
                "external_support": "Not typically required"
            },
            "low": {
                "team_size": "1-2 responders",
                "estimated_hours": "2-8 hours",
                "roles_needed": ["Security Analyst"],
                "external_support": "Not required"
            }
        }
        
        return resource_map.get(severity, resource_map["medium"])
