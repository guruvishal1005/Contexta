"""
Contexta Backend - AI Agents Routes

Provides endpoints for multi-agent analysis and orchestration.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.agents.orchestrator import get_orchestrator
from app.services.incident_service import IncidentService
from app.auth.jwt import get_current_active_user, get_current_user_optional, TokenData
from app.ledger.chain import get_ledger, LedgerEventTypes
from app.services.gemini_service import GeminiService, GeminiServiceError

logger = structlog.get_logger()
router = APIRouter()


@router.post("/analyze/{incident_id}")
async def analyze_incident(
    incident_id: str,
    risk_title: Optional[str] = Query(None),
    agents: Optional[List[str]] = Query(
        None,
        description="Specific agents to use (analyst, intel, forensics, business, response). Uses all if not specified."
    ),
    current_user: Optional[TokenData] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    Run AI agent analysis on an incident.
    """
    
    # DEMO MODE: Bypass auth and logic if incident_id is 'demo'
    if incident_id == "demo":
        import asyncio
        from datetime import datetime, timedelta
        import random
        
        # Simulate processing time
        await asyncio.sleep(1.5)
        
        current_time_obj = datetime.now()
        
        def get_time(offset_seconds):
            return (current_time_obj + timedelta(seconds=offset_seconds)).strftime("%H:%M:%S")

        # Dynamic discussion generation based on risk_title
        title = risk_title or "Detected Security Event"
        title_lower = title.lower()
        
        discussion = []

        # Try Gemini for real AI-generated discussion
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
        except GeminiServiceError as e:
            logger.error("Gemini API failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"AI service unavailable: {str(e)}. Please check your Gemini API key configuration."
            )

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
