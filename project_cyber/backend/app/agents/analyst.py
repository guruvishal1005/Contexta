"""
Contexta Backend - Security Analyst Agent

This agent performs initial security analysis and threat classification.
"""

from typing import Dict, Any
import structlog

from app.agents.base import BaseAgent

logger = structlog.get_logger()


class AnalystAgent(BaseAgent):
    """
    Security Analyst Agent.
    
    Responsibilities:
    - Initial threat classification
    - Attack stage identification
    - IOC extraction
    - Affected systems identification
    - Timeline analysis
    """
    
    def __init__(self):
        super().__init__(
            name="Senior Security Analyst",
            agent_type="analyst"
        )
    
    async def analyze(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Perform security analysis on an incident.
        
        Args:
            incident_data: Incident details including:
                - title
                - description
                - severity
                - iocs
                - affected_assets
                - timeline
            context: Additional context such as:
                - organization profile
                - historical incidents
                - asset inventory
                
        Returns:
            Analysis result with:
                - threat_classification
                - attack_stage
                - key_findings
                - indicators_of_compromise
                - affected_systems
                - timeline_analysis
                - recommendations
        """
        logger.info(
            "Analyst agent starting analysis",
            incident_id=incident_data.get("id")
        )
        
        # Call Gemini for AI-powered analysis
        analysis = await self._call_gemini(incident_data, context)
        
        # Post-process and enrich the analysis
        enriched = self._enrich_analysis(analysis, incident_data)
        
        return self._format_result(enriched)
    
    def _enrich_analysis(
        self,
        analysis: Dict[str, Any],
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich AI analysis with additional processing.
        
        Args:
            analysis: Raw AI analysis
            incident_data: Original incident data
            
        Returns:
            Enriched analysis
        """
        # Merge IOCs from incident with those identified by AI
        incident_iocs = incident_data.get("iocs", {})
        ai_iocs = analysis.get("indicators_of_compromise", {})
        
        merged_iocs = {
            "ips": list(set(
                incident_iocs.get("ips", []) + ai_iocs.get("ips", [])
            )),
            "domains": list(set(
                incident_iocs.get("domains", []) + ai_iocs.get("domains", [])
            )),
            "hashes": list(set(
                incident_iocs.get("hashes", []) + ai_iocs.get("hashes", [])
            )),
            "other": list(set(
                incident_iocs.get("other", []) + ai_iocs.get("other", [])
            ))
        }
        
        analysis["indicators_of_compromise"] = merged_iocs
        
        # Add severity context based on attack stage
        attack_stage = analysis.get("attack_stage", "").lower()
        if attack_stage in ["actions", "command_control", "installation"]:
            analysis["severity_upgrade_recommended"] = True
            analysis["recommendations"].insert(
                0,
                "URGENT: Attack appears to be in advanced stage. Immediate containment required."
            )
        
        return analysis
