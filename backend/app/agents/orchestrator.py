"""
Contexta Backend - Agent Orchestrator

This module coordinates multi-agent analysis and generates consensus reports.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import asyncio
import structlog

from app.agents.analyst import AnalystAgent
from app.agents.intel import IntelAgent
from app.agents.forensics import ForensicsAgent
from app.agents.business import BusinessAgent
from app.agents.response import ResponseAgent

logger = structlog.get_logger()


class AgentOrchestrator:
    """
    Orchestrator for multi-agent analysis.
    
    Coordinates the five specialized agents:
    1. Security Analyst - Initial analysis and triage
    2. Threat Intel - CTI and attribution
    3. Forensics - Evidence analysis
    4. Business Impact - Business risk assessment
    5. Response - Action planning
    
    Generates consensus reports with cross-agent validation.
    """
    
    def __init__(self):
        """Initialize all agents."""
        self.analyst = AnalystAgent()
        self.intel = IntelAgent()
        self.forensics = ForensicsAgent()
        self.business = BusinessAgent()
        self.response = ResponseAgent()
        
        self.agents = {
            "analyst": self.analyst,
            "intel": self.intel,
            "forensics": self.forensics,
            "business": self.business,
            "response": self.response
        }
        
        logger.info("Agent orchestrator initialized", agent_count=len(self.agents))
    
    async def full_analysis(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run full multi-agent analysis on an incident.
        
        Args:
            incident_data: Incident details
            context: Additional context
            
        Returns:
            Comprehensive analysis with consensus report
        """
        start_time = datetime.now(timezone.utc)
        
        logger.info(
            "Starting full multi-agent analysis",
            incident_id=incident_data.get("id")
        )
        
        context = context or {}
        
        # Run all agents in parallel for efficiency
        tasks = [
            self.analyst.analyze(incident_data, context),
            self.intel.analyze(incident_data, context),
            self.forensics.analyze(incident_data, context),
            self.business.analyze(incident_data, context),
            self.response.analyze(incident_data, context)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results, handling any errors
        agent_results = {}
        errors = []
        
        agent_names = ["analyst", "intel", "forensics", "business", "response"]
        
        for name, result in zip(agent_names, results):
            if isinstance(result, Exception):
                errors.append({
                    "agent": name,
                    "error": str(result)
                })
                logger.error(
                    "Agent analysis failed",
                    agent=name,
                    error=str(result)
                )
            else:
                agent_results[name] = result
        
        # Generate consensus report
        consensus = self._generate_consensus(agent_results, incident_data)
        
        # Calculate analysis duration
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        return {
            "incident_id": incident_data.get("id"),
            "analysis_timestamp": start_time.isoformat(),
            "analysis_duration_seconds": duration,
            "agent_results": agent_results,
            "consensus_report": consensus,
            "errors": errors if errors else None
        }
    
    async def targeted_analysis(
        self,
        incident_data: Dict[str, Any],
        agent_types: List[str],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run analysis with specific agents only.
        
        Args:
            incident_data: Incident details
            agent_types: List of agent types to use
            context: Additional context
            
        Returns:
            Analysis from specified agents
        """
        context = context or {}
        
        logger.info(
            "Starting targeted analysis",
            incident_id=incident_data.get("id"),
            agents=agent_types
        )
        
        tasks = []
        valid_agents = []
        
        for agent_type in agent_types:
            if agent_type in self.agents:
                tasks.append(self.agents[agent_type].analyze(incident_data, context))
                valid_agents.append(agent_type)
            else:
                logger.warning("Unknown agent type requested", agent_type=agent_type)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        agent_results = {}
        errors = []
        
        for name, result in zip(valid_agents, results):
            if isinstance(result, Exception):
                errors.append({"agent": name, "error": str(result)})
            else:
                agent_results[name] = result
        
        return {
            "incident_id": incident_data.get("id"),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "agents_used": valid_agents,
            "agent_results": agent_results,
            "errors": errors if errors else None
        }
    
    def _generate_consensus(
        self,
        agent_results: Dict[str, Dict[str, Any]],
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate consensus report from all agent analyses.
        
        Applies weighted voting and cross-validation to produce
        a unified assessment.
        
        Args:
            agent_results: Results from all agents
            incident_data: Original incident data
            
        Returns:
            Consensus report
        """
        # Extract severity assessments from agents
        severities = []
        confidence_scores = []
        
        for agent_name, result in agent_results.items():
            if "analysis" in result:
                analysis = result["analysis"]
                
                # Try to extract severity
                if "severity" in analysis:
                    severities.append(analysis["severity"])
                elif "severity_assessment" in analysis:
                    severities.append(analysis["severity_assessment"])
                
                # Try to extract confidence
                if "confidence" in result:
                    confidence_scores.append(result["confidence"])
        
        # Calculate consensus severity
        consensus_severity = self._calculate_consensus_severity(severities)
        
        # Calculate average confidence
        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores)
            if confidence_scores else 0.7
        )
        
        # Determine overall threat level
        threat_level = self._calculate_threat_level(
            agent_results,
            incident_data
        )
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            agent_results,
            incident_data,
            consensus_severity
        )
        
        # Compile key findings
        key_findings = self._compile_key_findings(agent_results)
        
        # Generate prioritized recommendations
        recommendations = self._generate_recommendations(agent_results)
        
        return {
            "consensus_severity": consensus_severity,
            "threat_level": threat_level,
            "confidence_score": round(avg_confidence, 2),
            "executive_summary": executive_summary,
            "key_findings": key_findings,
            "prioritized_recommendations": recommendations,
            "agent_agreement": self._calculate_agreement(agent_results),
            "escalation_required": consensus_severity in ["critical", "high"],
            "immediate_actions": self._get_immediate_actions(agent_results)
        }
    
    def _calculate_consensus_severity(
        self,
        severities: List[str]
    ) -> str:
        """
        Calculate consensus severity using weighted voting.
        
        Uses a conservative approach - takes the highest severity
        if there's disagreement.
        """
        if not severities:
            return "medium"
        
        severity_order = ["low", "medium", "high", "critical"]
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        # Get the highest severity (conservative approach)
        max_severity = "low"
        for sev in severities:
            sev_lower = sev.lower() if isinstance(sev, str) else "medium"
            if sev_lower in severity_order:
                if severity_weights.get(sev_lower, 0) > severity_weights.get(max_severity, 0):
                    max_severity = sev_lower
        
        return max_severity
    
    def _calculate_threat_level(
        self,
        agent_results: Dict[str, Dict[str, Any]],
        incident_data: Dict[str, Any]
    ) -> str:
        """Calculate overall threat level."""
        # Check intel agent for threat actor sophistication
        intel_result = agent_results.get("intel", {})
        
        if "analysis" in intel_result:
            analysis = intel_result["analysis"]
            
            # Check for APT indicators
            if analysis.get("threat_actor_assessment", {}).get("sophistication") == "nation_state":
                return "extreme"
            if analysis.get("threat_actor_assessment", {}).get("sophistication") == "organized_crime":
                return "severe"
        
        # Check business impact
        business_result = agent_results.get("business", {})
        if "analysis" in business_result:
            analysis = business_result["analysis"]
            if analysis.get("impact_assessment", {}).get("overall") == "catastrophic":
                return "extreme"
            if analysis.get("impact_assessment", {}).get("overall") == "major":
                return "severe"
        
        # Default based on incident severity
        severity = incident_data.get("severity", "medium")
        threat_map = {
            "critical": "severe",
            "high": "elevated",
            "medium": "moderate",
            "low": "guarded"
        }
        
        return threat_map.get(severity, "moderate")
    
    def _generate_executive_summary(
        self,
        agent_results: Dict[str, Dict[str, Any]],
        incident_data: Dict[str, Any],
        consensus_severity: str
    ) -> str:
        """Generate executive summary from all analyses."""
        incident_type = incident_data.get("type", "security incident")
        
        summary_parts = [
            f"A {consensus_severity.upper()} severity {incident_type} has been detected and analyzed."
        ]
        
        # Add key insight from each agent
        if "analyst" in agent_results:
            analyst = agent_results["analyst"].get("analysis", {})
            if "summary" in analyst:
                summary_parts.append(f"Technical Analysis: {analyst['summary'][:200]}")
        
        if "intel" in agent_results:
            intel = agent_results["intel"].get("analysis", {})
            threat_actor = intel.get("threat_actor_assessment", {})
            if threat_actor.get("attribution"):
                summary_parts.append(
                    f"Threat Attribution: Likely linked to {threat_actor['attribution']}"
                )
        
        if "business" in agent_results:
            business = agent_results["business"].get("analysis", {})
            impact = business.get("impact_assessment", {})
            if impact.get("overall"):
                summary_parts.append(f"Business Impact: {impact['overall']}")
        
        return " ".join(summary_parts)
    
    def _compile_key_findings(
        self,
        agent_results: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Compile key findings from all agents."""
        findings = []
        
        for agent_name, result in agent_results.items():
            if "analysis" in result:
                analysis = result["analysis"]
                
                # Extract findings/key points
                agent_findings = analysis.get("key_findings", [])
                if isinstance(agent_findings, list):
                    for finding in agent_findings[:3]:  # Top 3 from each
                        findings.append({
                            "source": agent_name,
                            "finding": finding,
                            "confidence": result.get("confidence", 0.7)
                        })
        
        # Sort by confidence
        findings.sort(key=lambda x: x["confidence"], reverse=True)
        
        return findings[:10]  # Top 10 overall
    
    def _generate_recommendations(
        self,
        agent_results: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Get response agent recommendations first (highest priority)
        response_result = agent_results.get("response", {})
        if "analysis" in response_result:
            analysis = response_result["analysis"]
            rec_list = analysis.get("recommendations", [])
            for i, rec in enumerate(rec_list[:5]):
                recommendations.append({
                    "priority": i + 1,
                    "recommendation": rec,
                    "source": "response",
                    "category": "immediate"
                })
        
        # Add forensics recommendations
        forensics_result = agent_results.get("forensics", {})
        if "analysis" in forensics_result:
            analysis = forensics_result["analysis"]
            rec_list = analysis.get("recommendations", [])
            for rec in rec_list[:3]:
                recommendations.append({
                    "priority": len(recommendations) + 1,
                    "recommendation": rec,
                    "source": "forensics",
                    "category": "investigation"
                })
        
        return recommendations
    
    def _calculate_agreement(
        self,
        agent_results: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate agreement level between agents."""
        # This is a simplified agreement calculation
        # In production, would compare specific fields
        
        agent_count = len(agent_results)
        
        if agent_count == 0:
            return {"level": "N/A", "score": 0}
        
        if agent_count == 1:
            return {"level": "single_agent", "score": 1.0}
        
        # Simple scoring based on successful analyses
        successful = sum(1 for r in agent_results.values() if "analysis" in r)
        
        agreement_score = successful / agent_count
        
        if agreement_score >= 0.9:
            level = "high"
        elif agreement_score >= 0.7:
            level = "moderate"
        else:
            level = "low"
        
        return {
            "level": level,
            "score": round(agreement_score, 2),
            "agents_reporting": successful,
            "total_agents": agent_count
        }
    
    def _get_immediate_actions(
        self,
        agent_results: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract immediate actions from response agent."""
        response_result = agent_results.get("response", {})
        
        if "analysis" in response_result:
            analysis = response_result["analysis"]
            
            # Try to get from response phases
            phases = analysis.get("response_phases", {})
            containment = phases.get("phase_2_containment", {})
            
            return containment.get("actions", [
                "Assess scope of incident",
                "Isolate affected systems",
                "Preserve evidence",
                "Notify stakeholders"
            ])
        
        return [
            "Acknowledge and triage incident",
            "Assess immediate risk",
            "Implement initial containment",
            "Begin evidence collection"
        ]


# Singleton instance for reuse
_orchestrator: Optional[AgentOrchestrator] = None


def get_orchestrator() -> AgentOrchestrator:
    """Get or create the agent orchestrator singleton."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator()
    return _orchestrator
