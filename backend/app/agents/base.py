"""
Contexta Backend - Base Agent

This module defines the base class for all SOC agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import structlog

from app.services.gemini_service import gemini_service

logger = structlog.get_logger()


class BaseAgent(ABC):
    """
    Abstract base class for SOC agents.
    
    All specialized agents inherit from this class and implement
    their own analysis logic using the Gemini AI service.
    """
    
    def __init__(self, name: str, agent_type: str):
        """
        Initialize base agent.
        
        Args:
            name: Human-readable agent name
            agent_type: Agent type identifier
        """
        self.name = name
        self.agent_type = agent_type
        self._gemini = gemini_service
    
    @abstractmethod
    async def analyze(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Perform agent-specific analysis on an incident.
        
        Args:
            incident_data: Incident details
            context: Additional context
            
        Returns:
            Analysis result dictionary
        """
        pass
    
    async def _call_gemini(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Call Gemini service for analysis.
        
        Args:
            incident_data: Incident details
            context: Additional context
            
        Returns:
            Gemini analysis result
        """
        try:
            result = await self._gemini.analyze_for_agent(
                self.agent_type,
                incident_data,
                context
            )
            return result
        except Exception as e:
            logger.error(
                f"{self.name} analysis failed",
                agent=self.agent_type,
                error=str(e)
            )
            return {
                "agent_type": self.agent_type,
                "analysis": f"Analysis failed: {str(e)}",
                "confidence": 0,
                "recommendations": [],
                "error": True
            }
    
    def _format_result(
        self,
        analysis: Dict[str, Any],
        confidence: float = None,
        recommendations: list = None
    ) -> Dict[str, Any]:
        """
        Format analysis result with standard fields.
        
        Args:
            analysis: Raw analysis result
            confidence: Override confidence score
            recommendations: Override recommendations
            
        Returns:
            Formatted result
        """
        return {
            "agent_type": self.agent_type,
            "agent_name": self.name,
            "analysis_result": analysis,
            "confidence_score": confidence or analysis.get("confidence", 0),
            "recommendations": recommendations or analysis.get("recommendations", []),
            "timestamp": datetime.utcnow().isoformat()
        }
