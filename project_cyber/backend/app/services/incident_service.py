"""
Contexta Backend - Incident Service

This module provides incident management capabilities.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.models.incident import Incident, IncidentAnalysis, IncidentStatus, IncidentSeverity
from app.models.risk import Risk
from app.services.ledger_service import LedgerService

logger = structlog.get_logger()


class IncidentService:
    """
    Service for managing security incidents.
    
    Provides methods for:
    - Incident CRUD operations
    - Timeline management
    - Analysis tracking
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize service with database session."""
        self.db = db
    
    async def create_incident(
        self,
        title: str,
        description: str = None,
        risk_id: UUID = None,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        created_by: UUID = None,
        assigned_to: str = None,
        affected_assets: List[UUID] = None,
        iocs: Dict[str, Any] = None
    ) -> Incident:
        """
        Create a new incident.
        
        Args:
            title: Incident title
            description: Incident description
            risk_id: Source risk UUID
            severity: Incident severity
            created_by: User ID who created
            assigned_to: Assigned analyst
            affected_assets: List of affected asset IDs
            iocs: Indicators of Compromise
            
        Returns:
            Created Incident model
        """
        incident = Incident(
            title=title,
            description=description,
            risk_id=risk_id,
            severity=severity,
            created_by=created_by,
            assigned_to=assigned_to,
            affected_assets=affected_assets or [],
            iocs=iocs or {},
            timeline=[{
                "timestamp": datetime.utcnow().isoformat(),
                "event": "Incident created",
                "details": f"Incident created with severity: {severity.value}"
            }]
        )
        self.db.add(incident)
        await self.db.flush()
        
        # Log to ledger
        ledger_service = LedgerService(self.db)
        await ledger_service.record_action(
            action_type="incident_created",
            actor=str(created_by) if created_by else "system",
            resource_type="incident",
            resource_id=str(incident.id),
            data={
                "title": title,
                "severity": severity.value,
                "risk_id": str(risk_id) if risk_id else None
            }
        )
        
        logger.info("Created incident", id=str(incident.id), title=title)
        return incident
    
    async def get_by_id(self, id: UUID) -> Optional[Incident]:
        """Get incident by ID with related data."""
        result = await self.db.execute(
            select(Incident)
            .options(
                selectinload(Incident.risk),
                selectinload(Incident.analyses)
            )
            .where(Incident.id == id)
        )
        return result.scalar_one_or_none()
    
    async def update_incident(
        self,
        incident: Incident,
        update_data: Dict[str, Any],
        updated_by: UUID = None
    ) -> Incident:
        """
        Update an existing incident.
        
        Args:
            incident: Incident to update
            update_data: Fields to update
            updated_by: User who made the update
            
        Returns:
            Updated Incident model
        """
        old_status = incident.status
        
        for key, value in update_data.items():
            if hasattr(incident, key) and value is not None:
                setattr(incident, key, value)
        
        incident.updated_at = datetime.utcnow()
        
        # Add timeline event if status changed
        if "status" in update_data and update_data["status"] != old_status:
            incident.add_timeline_event(
                f"Status changed to {update_data['status'].value}",
                f"Changed by user {updated_by}" if updated_by else None
            )
        
        await self.db.flush()
        
        # Log to ledger
        ledger_service = LedgerService(self.db)
        await ledger_service.record_action(
            action_type="incident_updated",
            actor=str(updated_by) if updated_by else "system",
            resource_type="incident",
            resource_id=str(incident.id),
            data={"updates": list(update_data.keys())}
        )
        
        return incident
    
    async def add_timeline_event(
        self,
        incident: Incident,
        event: str,
        details: str = None
    ) -> Incident:
        """
        Add an event to incident timeline.
        
        Args:
            incident: Incident to update
            event: Event description
            details: Additional details
            
        Returns:
            Updated Incident
        """
        incident.add_timeline_event(event, details)
        incident.updated_at = datetime.utcnow()
        await self.db.flush()
        return incident
    
    async def save_analysis(
        self,
        incident_id: UUID,
        agent_type: str,
        analysis_result: Dict[str, Any],
        confidence_score: float = 0.0,
        recommendations: List[str] = None,
        raw_response: str = None,
        consensus_report: str = None
    ) -> IncidentAnalysis:
        """
        Save agent analysis result.
        
        Args:
            incident_id: Incident UUID
            agent_type: Type of agent
            analysis_result: Analysis JSON
            confidence_score: Confidence percentage
            recommendations: List of recommendations
            raw_response: Raw API response
            consensus_report: Consensus report (for orchestrator)
            
        Returns:
            Created IncidentAnalysis
        """
        analysis = IncidentAnalysis(
            incident_id=incident_id,
            agent_type=agent_type,
            analysis_result=analysis_result,
            confidence_score=confidence_score,
            recommendations=recommendations or [],
            raw_response=raw_response,
            consensus_report=consensus_report
        )
        self.db.add(analysis)
        await self.db.flush()
        
        logger.info("Saved analysis", incident_id=str(incident_id), agent=agent_type)
        return analysis
    
    async def get_analyses(self, incident_id: UUID) -> List[IncidentAnalysis]:
        """Get all analyses for an incident."""
        result = await self.db.execute(
            select(IncidentAnalysis)
            .where(IncidentAnalysis.incident_id == incident_id)
            .order_by(IncidentAnalysis.created_at)
        )
        return list(result.scalars().all())
    
    async def list_incidents(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None
    ) -> tuple[List[Incident], int]:
        """
        List incidents with pagination.
        
        Args:
            page: Page number
            page_size: Items per page
            status: Filter by status
            severity: Filter by severity
            
        Returns:
            Tuple of (Incident list, total count)
        """
        query = select(Incident).options(selectinload(Incident.risk))
        count_query = select(func.count(Incident.id))
        
        if status:
            query = query.where(Incident.status == status)
            count_query = count_query.where(Incident.status == status)
        
        if severity:
            query = query.where(Incident.severity == severity)
            count_query = count_query.where(Incident.severity == severity)
        
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        offset = (page - 1) * page_size
        query = query.order_by(Incident.created_at.desc()).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        incidents = result.scalars().all()
        
        return list(incidents), total
    
    async def create_from_risk(
        self,
        risk_id: UUID,
        created_by: UUID = None
    ) -> Optional[Incident]:
        """
        Create an incident from a risk.
        
        Args:
            risk_id: Risk UUID
            created_by: User ID
            
        Returns:
            Created Incident or None
        """
        # Get the risk
        risk_result = await self.db.execute(
            select(Risk)
            .options(selectinload(Risk.cve), selectinload(Risk.asset))
            .where(Risk.id == risk_id)
        )
        risk = risk_result.scalar_one_or_none()
        
        if not risk:
            logger.warning("Risk not found", risk_id=str(risk_id))
            return None
        
        # Determine severity based on BWVS
        if risk.bwvs_score >= 80:
            severity = IncidentSeverity.CRITICAL
        elif risk.bwvs_score >= 60:
            severity = IncidentSeverity.HIGH
        elif risk.bwvs_score >= 40:
            severity = IncidentSeverity.MEDIUM
        else:
            severity = IncidentSeverity.LOW
        
        # Get affected assets
        affected_assets = [risk.asset_id] if risk.asset_id else []
        
        # Get IOCs from CVE if available
        iocs = {}
        if risk.cve and risk.cve.ai_extracted_data:
            iocs = risk.cve.ai_extracted_data.get("key_indicators", {})
        
        incident = await self.create_incident(
            title=f"Incident: {risk.title}",
            description=risk.description,
            risk_id=risk_id,
            severity=severity,
            created_by=created_by,
            affected_assets=affected_assets,
            iocs=iocs
        )
        
        # Update risk status
        risk.status = "investigating"
        
        return incident
    
    async def resolve_incident(
        self,
        incident: Incident,
        resolution: str,
        resolved_by: UUID = None
    ) -> Incident:
        """
        Resolve an incident.
        
        Args:
            incident: Incident to resolve
            resolution: Resolution summary
            resolved_by: User who resolved
            
        Returns:
            Updated Incident
        """
        incident.status = IncidentStatus.RESOLVED
        incident.resolution = resolution
        incident.resolved_at = datetime.utcnow()
        incident.add_timeline_event(
            "Incident resolved",
            resolution
        )
        
        await self.db.flush()
        
        # Log to ledger
        ledger_service = LedgerService(self.db)
        await ledger_service.record_action(
            action_type="incident_resolved",
            actor=str(resolved_by) if resolved_by else "system",
            resource_type="incident",
            resource_id=str(incident.id),
            data={"resolution": resolution}
        )
        
        logger.info("Resolved incident", id=str(incident.id))
        return incident
