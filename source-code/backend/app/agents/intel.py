"""
Contexta Backend - Threat Intelligence Agent

This agent provides threat intelligence context and attribution.
"""

from typing import Dict, Any
import structlog

from app.agents.base import BaseAgent

logger = structlog.get_logger()


class IntelAgent(BaseAgent):
    """
    Threat Intelligence Agent.
    
    Responsibilities:
    - Threat actor identification/attribution
    - Campaign analysis
    - TTP mapping (MITRE ATT&CK)
    - Historical threat context
    - Industry targeting analysis
    """
    
    def __init__(self):
        super().__init__(
            name="Threat Intelligence Analyst",
            agent_type="intel"
        )
    
    async def analyze(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Provide threat intelligence analysis.
        
        Args:
            incident_data: Incident details
            context: Additional context
                
        Returns:
            Intelligence analysis with:
                - threat_actor
                - campaign_analysis
                - related_threats
                - ttps (MITRE mapping)
                - industry_targeting
                - geographic_targeting
        """
        logger.info(
            "Intel agent starting analysis",
            incident_id=incident_data.get("id")
        )
        
        # Call Gemini for AI-powered analysis
        analysis = await self._call_gemini(incident_data, context)
        
        # Enrich with additional intelligence
        enriched = self._enrich_with_intel(analysis, incident_data)
        
        return self._format_result(enriched)
    
    def _enrich_with_intel(
        self,
        analysis: Dict[str, Any],
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich analysis with threat intelligence context.
        
        Args:
            analysis: Raw AI analysis
            incident_data: Original incident data
            
        Returns:
            Enriched analysis
        """
        # Map TTPs to MITRE ATT&CK IDs if not present
        ttps = analysis.get("ttps", {})
        techniques = ttps.get("techniques", [])
        
        # Add MITRE technique IDs based on common patterns
        mitre_mapping = self._map_to_mitre(techniques)
        analysis["mitre_attack_mapping"] = mitre_mapping
        
        # Add threat level assessment
        threat_actor = analysis.get("threat_actor", {})
        actor_type = threat_actor.get("type", "unknown")
        
        threat_level = "MEDIUM"
        if actor_type == "APT":
            threat_level = "CRITICAL"
        elif actor_type == "cybercrime":
            threat_level = "HIGH"
        
        analysis["threat_level"] = threat_level
        
        return analysis
    
    def _map_to_mitre(self, techniques: list) -> Dict[str, list]:
        """
        Map technique descriptions to MITRE ATT&CK IDs.
        
        Args:
            techniques: List of technique descriptions
            
        Returns:
            MITRE mapping
        """
        # Common technique to MITRE mapping
        mitre_mapping = {
            "phishing": ["T1566"],
            "spearphishing": ["T1566.001", "T1566.002"],
            "credential dumping": ["T1003"],
            "mimikatz": ["T1003.001"],
            "pass the hash": ["T1550.002"],
            "lateral movement": ["T1021"],
            "rdp": ["T1021.001"],
            "smb": ["T1021.002"],
            "command and control": ["T1071"],
            "data exfiltration": ["T1041"],
            "ransomware": ["T1486"],
            "encryption": ["T1486"],
            "persistence": ["T1547"],
            "registry": ["T1547.001"],
            "scheduled task": ["T1053.005"],
            "powershell": ["T1059.001"],
            "cmd": ["T1059.003"],
        }
        
        mapped = []
        for tech in techniques:
            tech_lower = tech.lower()
            for keyword, ids in mitre_mapping.items():
                if keyword in tech_lower:
                    mapped.extend(ids)
        
        return {
            "technique_ids": list(set(mapped)),
            "techniques": techniques
        }
