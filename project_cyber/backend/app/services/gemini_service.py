"""
Contexta Backend - Gemini AI Service

This module provides integration with Google Gemini API for AI-powered
threat analysis, context extraction, and relevance scoring.
"""

import json
import asyncio
from typing import Optional, Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import google.generativeai as genai
import structlog

from app.config import settings

logger = structlog.get_logger()


class GeminiServiceError(Exception):
    """Custom exception for Gemini service errors."""
    pass


class GeminiService:
    """
    Service for interacting with Google Gemini API.
    
    Provides methods for:
    - Parsing threat descriptions
    - Extracting CVE context
    - Calculating AI relevance scores
    - Multi-agent analysis prompts
    """
    
    def __init__(self):
        """Initialize Gemini service with API key."""
        if not settings.gemini_api_key:
            logger.warning("Gemini API key not configured")
            self._model = None
        else:
            genai.configure(api_key=settings.gemini_api_key)
            self._model = genai.GenerativeModel(settings.gemini_model)
        
        self._rate_limit_delay = 1.0  # seconds between requests
        self._last_request_time = 0
    
    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        current_time = asyncio.get_event_loop().time()
        elapsed = current_time - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = asyncio.get_event_loop().time()
    
    def _check_model(self) -> None:
        """Check if model is initialized."""
        if self._model is None:
            raise GeminiServiceError("Gemini API key not configured")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((Exception,)),
        reraise=True
    )
    async def _generate_content(self, prompt: str) -> str:
        """
        Generate content using Gemini with retry logic.
        
        Args:
            prompt: The prompt to send to Gemini
            
        Returns:
            Generated text response
        """
        self._check_model()
        await self._rate_limit()
        
        try:
            response = await asyncio.to_thread(
                self._model.generate_content,
                prompt
            )
            return response.text
        except Exception as e:
            logger.error("Gemini API error", error=str(e))
            raise GeminiServiceError(f"Gemini API error: {str(e)}")
    
    async def extract_threat_context(self, description: str) -> Dict[str, Any]:
        """
        Extract structured threat context from a threat description.
        
        Args:
            description: Raw threat/CVE description
            
        Returns:
            Structured JSON with extracted context:
            - cve_id: CVE identifier if found
            - target_software: List of affected software
            - attack_vector: Attack vector type
            - industry: Targeted industries
            - region: Targeted regions
            - severity_assessment: AI assessment of severity
            - key_indicators: IOCs and indicators
        """
        prompt = f"""Analyze the following threat/vulnerability description and extract structured information.
Return ONLY valid JSON with the following structure:
{{
    "cve_id": "CVE-XXXX-XXXXX or null if not found",
    "target_software": ["list", "of", "affected", "software"],
    "attack_vector": "NETWORK|ADJACENT|LOCAL|PHYSICAL or null",
    "attack_complexity": "LOW|HIGH or null",
    "privileges_required": "NONE|LOW|HIGH or null",
    "user_interaction": "NONE|REQUIRED or null",
    "industry": ["list", "of", "targeted", "industries"],
    "region": ["list", "of", "targeted", "regions"],
    "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW",
    "key_indicators": {{
        "ips": [],
        "domains": [],
        "file_hashes": [],
        "file_names": [],
        "registry_keys": []
    }},
    "exploitation_likelihood": "HIGH|MEDIUM|LOW",
    "summary": "Brief summary of the threat"
}}

Threat Description:
{description}

Return ONLY the JSON, no additional text."""

        try:
            response = await self._generate_content(prompt)
            # Clean response and parse JSON
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            
            return json.loads(response.strip())
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Gemini response as JSON", error=str(e))
            return {
                "cve_id": None,
                "target_software": [],
                "attack_vector": None,
                "industry": [],
                "region": [],
                "severity_assessment": "MEDIUM",
                "key_indicators": {},
                "exploitation_likelihood": "MEDIUM",
                "summary": description[:200],
                "parse_error": True
            }
        except GeminiServiceError:
            # Return fallback if Gemini is unavailable
            return {
                "cve_id": None,
                "target_software": [],
                "attack_vector": None,
                "industry": [],
                "region": [],
                "severity_assessment": "MEDIUM",
                "key_indicators": {},
                "exploitation_likelihood": "MEDIUM",
                "summary": description[:200],
                "api_unavailable": True
            }
    
    async def calculate_relevance_score(
        self,
        cve_description: str,
        asset_info: Dict[str, Any],
        organization_context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate AI relevance score for a CVE against organizational context.
        
        Args:
            cve_description: CVE description
            asset_info: Information about the affected asset
            organization_context: Optional organizational context
            
        Returns:
            Dict with relevance_percentage (0-100) and reasoning
        """
        org_context = organization_context or {
            "industry": "technology",
            "region": "global",
            "size": "medium"
        }
        
        prompt = f"""Analyze how relevant this vulnerability is to the given organization and asset.

CVE Description:
{cve_description}

Asset Information:
{json.dumps(asset_info, indent=2)}

Organization Context:
{json.dumps(org_context, indent=2)}

Return ONLY valid JSON with the following structure:
{{
    "relevance_percentage": <number 0-100>,
    "confidence": <number 0-100>,
    "reasoning": "explanation of relevance assessment",
    "risk_factors": ["list", "of", "relevant", "risk", "factors"],
    "mitigating_factors": ["list", "of", "mitigating", "factors"],
    "recommended_priority": "CRITICAL|HIGH|MEDIUM|LOW"
}}

Return ONLY the JSON, no additional text."""

    async def generate_agent_discussion(
        self,
        risk_title: str,
        agents: Optional[List[str]] = None,
        max_messages: int = 8
    ) -> List[Dict[str, Any]]:
        """
        Generate a sequential multi-agent discussion following the SOC pipeline.
        
        Pipeline Flow (as per flowchart):
        1. Analyst + Intel (parallel) - Initial analysis and threat intelligence
        2. Forensics - Deep dive based on Analyst+Intel findings
        3. Business - Business impact based on Forensics findings
        4. Response - Action plan based on all previous findings

        Args:
            risk_title: Short title of the risk/incident
            agents: Optional list of agent types to include
            max_messages: Maximum number of messages to generate

        Returns:
            List of discussion messages with agent, message, and timestamp_offset_seconds
        """
        allowed_agents = ["analyst", "intel", "forensics", "business", "response"]
        selected_agents = [a for a in (agents or allowed_agents) if a in allowed_agents]
        if not selected_agents:
            selected_agents = allowed_agents

        prompt = f"""You are generating a realistic SOC agent discussion for a security operations center UI.

Risk Title: {risk_title}

CRITICAL: Follow this EXACT sequential pipeline flow:

**Stage 1 - Initial Analysis (Analyst + Intel work in parallel):**
- ANALYST speaks first: Provides initial technical assessment, identifies attack patterns, affected systems
- INTEL speaks next: Adds threat intelligence context, known threat actors, campaign attribution, IOCs

**Stage 2 - Forensics (builds on Analyst + Intel findings):**
- FORENSICS agent: References what Analyst and Intel found, digs deeper into evidence, artifacts, timeline

**Stage 3 - Business Impact (builds on Forensics findings):**
- BUSINESS agent: References forensics findings to assess business impact, affected operations, financial risk

**Stage 4 - Response Planning (synthesizes all previous findings):**
- RESPONSE agent: Creates action plan based on ALL previous agents' findings, prioritizes containment and remediation

Agents to include: {selected_agents}

RULES:
1. Each agent MUST reference findings from previous agents in their stage
2. Messages should show progressive understanding and escalation
3. Use realistic SOC terminology and be specific to the risk title
4. Return ONLY valid JSON
5. Create {max_messages} messages total following the pipeline order
6. timestamp_offset_seconds should increase progressively (0, 15, 30, 45, 60, 90, 120, 150)

Example flow for ransomware:
- Analyst: "Detecting encryption patterns on file servers..."
- Intel: "This matches LockBit 3.0 TTPs, associated with RaaS group..."
- Forensics: "Based on Intel's attribution, found lateral movement via PSExec, initial access was phishing..."
- Business: "Per Forensics timeline, 3 critical systems affected, estimated 4-hour recovery..."
- Response: "Given Business impact assessment, immediate actions: 1) Isolate affected hosts 2) Block C2 IPs from Intel..."

Return ONLY JSON in this exact shape:
{{
  "discussion": [
    {{"agent": "analyst", "message": "...", "timestamp_offset_seconds": 0}},
    {{"agent": "intel", "message": "...", "timestamp_offset_seconds": 15}},
    {{"agent": "forensics", "message": "...", "timestamp_offset_seconds": 45}},
    {{"agent": "business", "message": "...", "timestamp_offset_seconds": 90}},
    {{"agent": "response", "message": "...", "timestamp_offset_seconds": 120}}
  ]
}}
"""

        try:
            response = await self._generate_content(prompt)
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]

            parsed = json.loads(response.strip())
            discussion = parsed.get("discussion", [])
            if not isinstance(discussion, list) or not discussion:
                raise GeminiServiceError("Gemini returned empty discussion")

            sanitized = []
            for item in discussion:
                agent = item.get("agent")
                if agent not in allowed_agents:
                    continue
                message = str(item.get("message", "")).strip()
                if not message:
                    continue
                offset = item.get("timestamp_offset_seconds", 0)
                try:
                    offset = int(offset)
                except (TypeError, ValueError):
                    offset = 0
                sanitized.append(
                    {
                        "agent": agent,
                        "message": message,
                        "timestamp_offset_seconds": max(0, offset)
                    }
                )

            if not sanitized:
                raise GeminiServiceError("Gemini discussion contained no valid messages")

            return sanitized[:max_messages]
        except (json.JSONDecodeError, GeminiServiceError) as e:
            logger.error("Failed to generate Gemini discussion", error=str(e))
            raise GeminiServiceError("Failed to generate Gemini discussion")

        try:
            response = await self._generate_content(prompt)
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            
            result = json.loads(response.strip())
            # Ensure relevance_percentage is in valid range
            result["relevance_percentage"] = max(0, min(100, result.get("relevance_percentage", 50)))
            return result
        except (json.JSONDecodeError, GeminiServiceError) as e:
            logger.error("Failed to calculate relevance score", error=str(e))
            return {
                "relevance_percentage": 50,
                "confidence": 0,
                "reasoning": "Unable to calculate AI relevance - using default score",
                "risk_factors": [],
                "mitigating_factors": [],
                "recommended_priority": "MEDIUM",
                "error": True
            }
    
    async def analyze_for_agent(
        self,
        agent_type: str,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate analysis for a specific SOC agent.
        
        Args:
            agent_type: Type of agent (analyst, intel, forensics, business, response)
            incident_data: Incident details
            context: Additional context
            
        Returns:
            Agent-specific analysis
        """
        agent_prompts = {
            "analyst": self._get_analyst_prompt,
            "intel": self._get_intel_prompt,
            "forensics": self._get_forensics_prompt,
            "business": self._get_business_prompt,
            "response": self._get_response_prompt,
        }
        
        if agent_type not in agent_prompts:
            raise GeminiServiceError(f"Unknown agent type: {agent_type}")
        
        prompt = agent_prompts[agent_type](incident_data, context or {})
        
        try:
            response = await self._generate_content(prompt)
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            
            return json.loads(response.strip())
        except (json.JSONDecodeError, GeminiServiceError) as e:
            logger.error(f"Agent {agent_type} analysis failed", error=str(e))
            return {
                "agent_type": agent_type,
                "analysis": "Analysis unavailable",
                "confidence": 0,
                "recommendations": [],
                "error": True
            }
    
    def _get_analyst_prompt(self, incident: Dict, context: Dict) -> str:
        """Generate prompt for Security Analyst agent."""
        return f"""You are a Senior Security Analyst investigating a security incident.

Incident Data:
{json.dumps(incident, indent=2)}

Additional Context:
{json.dumps(context, indent=2)}

Analyze this incident and provide your assessment. Return ONLY valid JSON:
{{
    "agent_type": "analyst",
    "threat_classification": "classification of the threat",
    "attack_stage": "reconnaissance|weaponization|delivery|exploitation|installation|command_control|actions",
    "confidence": <number 0-100>,
    "key_findings": ["list", "of", "key", "findings"],
    "indicators_of_compromise": {{
        "ips": [],
        "domains": [],
        "hashes": [],
        "other": []
    }},
    "affected_systems": ["list", "of", "systems"],
    "timeline_analysis": "analysis of attack timeline",
    "recommendations": ["list", "of", "recommendations"],
    "escalation_required": true|false,
    "summary": "executive summary"
}}"""

    def _get_intel_prompt(self, incident: Dict, context: Dict) -> str:
        """Generate prompt for Threat Intelligence agent."""
        return f"""You are a Threat Intelligence Analyst researching a security incident.

Incident Data:
{json.dumps(incident, indent=2)}

Additional Context:
{json.dumps(context, indent=2)}

Research this incident and provide threat intelligence. Return ONLY valid JSON:
{{
    "agent_type": "intel",
    "threat_actor": {{
        "name": "known threat actor name or Unknown",
        "type": "APT|cybercrime|hacktivist|insider|unknown",
        "motivation": "financial|espionage|disruption|unknown",
        "confidence": <number 0-100>
    }},
    "campaign_analysis": "analysis of potential campaign",
    "related_threats": ["list", "of", "related", "threats"],
    "ttps": {{
        "tactics": [],
        "techniques": [],
        "procedures": []
    }},
    "historical_context": "relevant historical context",
    "industry_targeting": ["targeted", "industries"],
    "geographic_targeting": ["targeted", "regions"],
    "recommendations": ["list", "of", "recommendations"],
    "confidence": <number 0-100>,
    "summary": "intelligence summary"
}}"""

    def _get_forensics_prompt(self, incident: Dict, context: Dict) -> str:
        """Generate prompt for Digital Forensics agent."""
        return f"""You are a Digital Forensics Investigator analyzing a security incident.

Incident Data:
{json.dumps(incident, indent=2)}

Additional Context:
{json.dumps(context, indent=2)}

Conduct forensic analysis and provide findings. Return ONLY valid JSON:
{{
    "agent_type": "forensics",
    "evidence_analysis": {{
        "artifacts_found": [],
        "persistence_mechanisms": [],
        "lateral_movement": [],
        "data_exfiltration": []
    }},
    "attack_reconstruction": "step by step attack reconstruction",
    "root_cause": "identified root cause",
    "entry_point": "initial entry point",
    "dwell_time_estimate": "estimated time attacker was in environment",
    "scope_assessment": {{
        "systems_compromised": [],
        "data_accessed": [],
        "data_exfiltrated": "description"
    }},
    "preservation_steps": ["evidence", "preservation", "steps"],
    "recommendations": ["list", "of", "recommendations"],
    "confidence": <number 0-100>,
    "summary": "forensics summary"
}}"""

    def _get_business_prompt(self, incident: Dict, context: Dict) -> str:
        """Generate prompt for Business Impact agent."""
        return f"""You are a Business Impact Analyst assessing a security incident.

Incident Data:
{json.dumps(incident, indent=2)}

Additional Context:
{json.dumps(context, indent=2)}

Assess the business impact. Return ONLY valid JSON:
{{
    "agent_type": "business",
    "impact_assessment": {{
        "financial": {{
            "estimated_loss": "estimated financial loss",
            "recovery_cost": "estimated recovery cost",
            "confidence": <number 0-100>
        }},
        "operational": {{
            "affected_processes": [],
            "downtime_estimate": "estimated downtime",
            "productivity_impact": "description"
        }},
        "reputational": {{
            "risk_level": "HIGH|MEDIUM|LOW",
            "stakeholders_affected": [],
            "media_exposure_risk": "HIGH|MEDIUM|LOW"
        }},
        "regulatory": {{
            "compliance_implications": [],
            "reporting_requirements": [],
            "potential_fines": "description"
        }}
    }},
    "business_continuity": {{
        "critical_functions_affected": [],
        "workarounds_available": true|false,
        "recovery_priority": []
    }},
    "stakeholder_communication": ["communication", "recommendations"],
    "recommendations": ["list", "of", "recommendations"],
    "confidence": <number 0-100>,
    "summary": "business impact summary"
}}"""

    def _get_response_prompt(self, incident: Dict, context: Dict) -> str:
        """Generate prompt for Incident Response agent."""
        return f"""You are an Incident Response Lead coordinating response to a security incident.

Incident Data:
{json.dumps(incident, indent=2)}

Additional Context:
{json.dumps(context, indent=2)}

Develop a response plan. Return ONLY valid JSON:
{{
    "agent_type": "response",
    "response_priority": "CRITICAL|HIGH|MEDIUM|LOW",
    "immediate_actions": [
        {{
            "action": "description",
            "owner": "role responsible",
            "timeline": "timeframe"
        }}
    ],
    "containment_strategy": {{
        "short_term": ["immediate", "containment", "steps"],
        "long_term": ["long", "term", "containment"]
    }},
    "eradication_plan": ["steps", "to", "remove", "threat"],
    "recovery_plan": {{
        "steps": [],
        "timeline": "estimated timeline",
        "validation": ["validation", "steps"]
    }},
    "communication_plan": {{
        "internal": ["internal", "notifications"],
        "external": ["external", "notifications"],
        "regulatory": ["regulatory", "notifications"]
    }},
    "lessons_learned": ["preliminary", "lessons"],
    "prevention_measures": ["future", "prevention", "measures"],
    "recommendations": ["list", "of", "recommendations"],
    "confidence": <number 0-100>,
    "summary": "response plan summary"
}}"""

    async def generate_consensus_report(
        self,
        agent_analyses: List[Dict[str, Any]],
        incident_data: Dict[str, Any]
    ) -> str:
        """
        Generate a consensus report from multiple agent analyses.
        
        Args:
            agent_analyses: List of analyses from different agents
            incident_data: Original incident data
            
        Returns:
            Consensus report as markdown text
        """
        prompt = f"""You are a Security Operations Center (SOC) Manager synthesizing analyses from your team.

Incident Overview:
{json.dumps(incident_data, indent=2)}

Agent Analyses:
{json.dumps(agent_analyses, indent=2)}

Create a comprehensive consensus report that:
1. Synthesizes findings from all agents
2. Highlights areas of agreement and disagreement
3. Provides a unified risk assessment
4. Delivers actionable recommendations prioritized by urgency
5. Includes an executive summary

Format the report in clear markdown with sections for:
- Executive Summary
- Threat Assessment
- Business Impact
- Technical Findings
- Recommended Actions (prioritized)
- Timeline
- Appendix (IOCs, affected systems)

Generate the full report now:"""

        try:
            response = await self._generate_content(prompt)
            return response
        except GeminiServiceError as e:
            logger.error("Failed to generate consensus report", error=str(e))
            return f"""# Consensus Report - Generation Failed

Unable to generate AI consensus report due to service unavailability.

## Manual Review Required

Please review individual agent analyses and compile findings manually.

Error: {str(e)}
"""


# Singleton instance
gemini_service = GeminiService()
