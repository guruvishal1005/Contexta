"""
Contexta Backend - Digital Forensics Agent

This agent performs forensic analysis and evidence assessment.
"""

from typing import Dict, Any
import structlog

from app.agents.base import BaseAgent

logger = structlog.get_logger()


class ForensicsAgent(BaseAgent):
    """
    Digital Forensics Agent.
    
    Responsibilities:
    - Evidence analysis
    - Attack reconstruction
    - Root cause identification
    - Scope assessment
    - Evidence preservation guidance
    """
    
    def __init__(self):
        super().__init__(
            name="Digital Forensics Investigator",
            agent_type="forensics"
        )
    
    async def analyze(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Perform forensic analysis on an incident.
        
        Args:
            incident_data: Incident details
            context: Additional context
                
        Returns:
            Forensic analysis with:
                - evidence_analysis
                - attack_reconstruction
                - root_cause
                - entry_point
                - scope_assessment
                - preservation_steps
        """
        logger.info(
            "Forensics agent starting analysis",
            incident_id=incident_data.get("id")
        )
        
        # Call Gemini for AI-powered analysis
        analysis = await self._call_gemini(incident_data, context)
        
        # Enrich with forensic guidance
        enriched = self._add_forensic_guidance(analysis, incident_data)
        
        return self._format_result(enriched)
    
    def _add_forensic_guidance(
        self,
        analysis: Dict[str, Any],
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add forensic best practices and guidance.
        
        Args:
            analysis: Raw AI analysis
            incident_data: Original incident data
            
        Returns:
            Enriched analysis
        """
        # Add standard evidence collection checklist
        affected_assets = incident_data.get("affected_assets", [])
        
        evidence_checklist = [
            "Memory dump from affected systems",
            "Disk images (forensic copy)",
            "Network packet captures",
            "System and security logs",
            "Application logs",
            "Email headers and attachments",
            "Malware samples (isolated)",
            "Registry exports (Windows)",
            "Browser history and cache",
            "Cloud service logs"
        ]
        
        analysis["evidence_collection_checklist"] = evidence_checklist
        
        # Add chain of custody reminder
        analysis["chain_of_custody"] = {
            "reminder": "Maintain strict chain of custody for all evidence",
            "steps": [
                "Document who collected the evidence",
                "Record date, time, and location",
                "Use write blockers for disk imaging",
                "Calculate and record hash values",
                "Store evidence in secure location",
                "Log all access to evidence"
            ]
        }
        
        # Add timeline reconstruction guidance
        analysis["timeline_guidance"] = {
            "key_timestamps": [
                "Initial compromise/entry point",
                "Privilege escalation events",
                "Lateral movement activities",
                "Data access/exfiltration",
                "Persistence mechanism installation",
                "Detection/discovery"
            ],
            "sync_note": "Ensure all timestamps are normalized to UTC"
        }
        
        return analysis
