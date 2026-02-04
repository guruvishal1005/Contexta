"""
Contexta Backend - Business Impact Agent

This agent assesses business impact and stakeholder implications.
"""

from typing import Dict, Any
import structlog

from app.agents.base import BaseAgent

logger = structlog.get_logger()


class BusinessAgent(BaseAgent):
    """
    Business Impact Agent.
    
    Responsibilities:
    - Financial impact assessment
    - Operational impact analysis
    - Reputational risk evaluation
    - Regulatory/compliance implications
    - Stakeholder communication planning
    """
    
    def __init__(self):
        super().__init__(
            name="Business Impact Analyst",
            agent_type="business"
        )
    
    async def analyze(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Assess business impact of an incident.
        
        Args:
            incident_data: Incident details
            context: Additional context including:
                - asset criticality
                - business unit information
                - regulatory requirements
                
        Returns:
            Business impact analysis with:
                - impact_assessment (financial, operational, reputational, regulatory)
                - business_continuity
                - stakeholder_communication
        """
        logger.info(
            "Business agent starting analysis",
            incident_id=incident_data.get("id")
        )
        
        # Call Gemini for AI-powered analysis
        analysis = await self._call_gemini(incident_data, context)
        
        # Enrich with business context
        enriched = self._add_business_context(analysis, incident_data, context)
        
        return self._format_result(enriched)
    
    def _add_business_context(
        self,
        analysis: Dict[str, Any],
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Add business-specific context and calculations.
        
        Args:
            analysis: Raw AI analysis
            incident_data: Original incident data
            context: Additional context
            
        Returns:
            Enriched analysis
        """
        context = context or {}
        
        # Add regulatory checklist based on incident type
        severity = incident_data.get("severity", "medium")
        
        regulatory_checklist = []
        
        # Common regulations to consider
        if severity in ["critical", "high"]:
            regulatory_checklist = [
                {
                    "regulation": "CERT-In (India)",
                    "requirement": "Report cyber incident within 6 hours",
                    "deadline": "6 hours from detection",
                    "contact": "incident@cert-in.org.in"
                },
                {
                    "regulation": "SEBI",
                    "requirement": "Report material cyber incidents",
                    "deadline": "As per SEBI guidelines",
                    "applicable_if": "Listed company or market infrastructure"
                },
                {
                    "regulation": "RBI",
                    "requirement": "Report cyber security incidents",
                    "deadline": "Within 2-6 hours based on severity",
                    "applicable_if": "Regulated financial entity"
                },
                {
                    "regulation": "IT Act 2000",
                    "requirement": "Data breach notification",
                    "deadline": "As per rules",
                    "applicable_if": "Personal data affected"
                }
            ]
        
        analysis["regulatory_checklist"] = regulatory_checklist
        
        # Add executive briefing template
        analysis["executive_briefing_template"] = {
            "situation": "Brief description of what happened",
            "impact": "Business impact summary",
            "actions_taken": "Immediate response actions",
            "current_status": "Current containment status",
            "next_steps": "Planned remediation steps",
            "resource_needs": "Additional resources required",
            "timeline": "Expected resolution timeline"
        }
        
        # Add stakeholder notification matrix
        analysis["stakeholder_matrix"] = {
            "immediate": [
                "CISO/Security Team",
                "IT Operations",
                "Legal/Compliance"
            ],
            "within_1_hour": [
                "Executive Leadership",
                "Affected Business Unit Heads",
                "PR/Communications (if media risk)"
            ],
            "within_24_hours": [
                "Board (if material)",
                "Customers (if data affected)",
                "Regulators (as required)"
            ]
        }
        
        return analysis
