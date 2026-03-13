"""
Contexta Backend - Playbook Service

This module provides playbook management and execution capabilities.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog
import asyncio

from app.models.playbook import Playbook, PlaybookExecution, PlaybookStatus
from app.services.ledger_service import LedgerService

logger = structlog.get_logger()


class PlaybookService:
    """
    Service for managing and executing playbooks.
    
    Provides methods for:
    - Playbook CRUD operations
    - Playbook execution
    - Execution history tracking
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize service with database session."""
        self.db = db
    
    async def create_playbook(self, playbook_data: Dict[str, Any]) -> Playbook:
        """
        Create a new playbook.
        
        Args:
            playbook_data: Playbook configuration
            
        Returns:
            Created Playbook model
        """
        playbook = Playbook(**playbook_data)
        self.db.add(playbook)
        await self.db.flush()
        logger.info("Created playbook", name=playbook.name)
        return playbook
    
    async def get_by_id(self, id: UUID) -> Optional[Playbook]:
        """Get playbook by ID."""
        result = await self.db.execute(
            select(Playbook).where(Playbook.id == id)
        )
        return result.scalar_one_or_none()
    
    async def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get playbook by ID string."""
        try:
            uuid_id = UUID(playbook_id)
            return await self.get_by_id(uuid_id)
        except ValueError:
            return None
    
    async def get_by_name(self, name: str) -> Optional[Playbook]:
        """Get playbook by name."""
        result = await self.db.execute(
            select(Playbook).where(Playbook.name == name)
        )
        return result.scalar_one_or_none()
    
    async def update_playbook(
        self,
        playbook: Playbook,
        update_data: Dict[str, Any]
    ) -> Playbook:
        """Update an existing playbook."""
        for key, value in update_data.items():
            if hasattr(playbook, key) and value is not None:
                setattr(playbook, key, value)
        playbook.updated_at = datetime.utcnow()
        await self.db.flush()
        return playbook
    
    async def list_playbooks(
        self,
        page: int = 1,
        page_size: int = 20,
        category: str = None,
        is_active: bool = True
    ) -> tuple[List[Playbook], int]:
        """List playbooks with pagination."""
        query = select(Playbook).where(Playbook.is_active == is_active)
        count_query = select(func.count(Playbook.id)).where(Playbook.is_active == is_active)
        
        if category:
            query = query.where(Playbook.category == category)
            count_query = count_query.where(Playbook.category == category)
        
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        offset = (page - 1) * page_size
        query = query.order_by(Playbook.name).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        playbooks = result.scalars().all()
        
        return list(playbooks), total
    
    async def execute_playbook(
        self,
        playbook_id: UUID,
        incident_id: UUID = None,
        executed_by: UUID = None,
        parameters: Dict[str, Any] = None
    ) -> PlaybookExecution:
        """
        Execute a playbook.
        
        Args:
            playbook_id: Playbook to execute
            incident_id: Related incident
            executed_by: User executing
            parameters: Execution parameters
            
        Returns:
            PlaybookExecution record
        """
        playbook = await self.get_by_id(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        if not playbook.is_active:
            raise ValueError(f"Playbook {playbook.name} is not active")
        
        # Create execution record
        execution = PlaybookExecution(
            playbook_id=playbook_id,
            incident_id=incident_id,
            executed_by=executed_by,
            status=PlaybookStatus.PENDING,
            step_results=[]
        )
        self.db.add(execution)
        await self.db.flush()
        
        # Start execution
        execution.start()
        
        # Log to ledger
        ledger_service = LedgerService(self.db)
        await ledger_service.record_action(
            action_type="playbook_executed",
            actor=str(executed_by) if executed_by else "system",
            resource_type="playbook",
            resource_id=str(playbook_id),
            data={
                "playbook_name": playbook.name,
                "incident_id": str(incident_id) if incident_id else None,
                "execution_id": str(execution.id)
            }
        )
        
        # Execute steps
        step_results = []
        try:
            for step in playbook.steps:
                step_start = datetime.utcnow()
                step_result = await self._execute_step(step, parameters or {})
                step_duration = (datetime.utcnow() - step_start).total_seconds()
                
                step_results.append({
                    "step_order": step.get("order", 0),
                    "step_name": step.get("name", "Unknown"),
                    "status": step_result.get("status", "completed"),
                    "output": step_result.get("output"),
                    "error": step_result.get("error"),
                    "duration_seconds": step_duration
                })
                
                # Check if we should stop on failure
                if step_result.get("status") == "failed":
                    if step.get("on_failure", "stop") == "stop":
                        break
            
            execution.step_results = step_results
            execution.complete({
                "steps_completed": len(step_results),
                "total_steps": len(playbook.steps)
            })
            
        except Exception as e:
            logger.error("Playbook execution failed", error=str(e))
            execution.step_results = step_results
            execution.fail(str(e))
        
        await self.db.flush()
        return execution
    
    async def _execute_step(
        self,
        step: Dict[str, Any],
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a single playbook step.
        
        This is a simulation - in production, this would integrate with
        actual security tools and systems.
        
        Args:
            step: Step configuration
            parameters: Execution parameters
            
        Returns:
            Step execution result
        """
        action = step.get("action", "")
        step_params = step.get("parameters", {})
        
        # Merge with execution parameters
        merged_params = {**step_params, **parameters}
        
        logger.info("Executing step", step=step.get("name"), action=action)
        
        # Simulate step execution based on action type
        # In production, these would integrate with real systems
        
        if action == "isolate_host":
            # Simulate host isolation
            await asyncio.sleep(0.5)
            return {
                "status": "completed",
                "output": {
                    "isolated": True,
                    "host": merged_params.get("host", "unknown"),
                    "method": "network_acl"
                }
            }
        
        elif action == "block_ip":
            await asyncio.sleep(0.3)
            return {
                "status": "completed",
                "output": {
                    "blocked": True,
                    "ip": merged_params.get("ip", "unknown"),
                    "firewall_rule_id": "FW-12345"
                }
            }
        
        elif action == "disable_user":
            await asyncio.sleep(0.2)
            return {
                "status": "completed",
                "output": {
                    "disabled": True,
                    "user": merged_params.get("user", "unknown")
                }
            }
        
        elif action == "collect_forensics":
            await asyncio.sleep(1.0)
            return {
                "status": "completed",
                "output": {
                    "collected": True,
                    "artifacts": ["memory_dump", "disk_image", "logs"],
                    "storage_location": "/forensics/case_001/"
                }
            }
        
        elif action == "notify":
            await asyncio.sleep(0.1)
            return {
                "status": "completed",
                "output": {
                    "notified": True,
                    "channels": merged_params.get("channels", ["email"]),
                    "recipients": merged_params.get("recipients", [])
                }
            }
        
        elif action == "scan_vulnerability":
            await asyncio.sleep(2.0)
            return {
                "status": "completed",
                "output": {
                    "scanned": True,
                    "vulnerabilities_found": 0,
                    "scan_id": "SCAN-67890"
                }
            }
        
        else:
            # Generic action simulation
            await asyncio.sleep(0.5)
            return {
                "status": "completed",
                "output": {
                    "action": action,
                    "result": "simulated",
                    "parameters": merged_params
                }
            }
    
    async def get_execution(self, execution_id: UUID) -> Optional[PlaybookExecution]:
        """Get playbook execution by ID."""
        result = await self.db.execute(
            select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
        )
        return result.scalar_one_or_none()
    
    async def list_executions(
        self,
        playbook_id: UUID = None,
        incident_id: UUID = None,
        page: int = 1,
        page_size: int = 20
    ) -> tuple[List[PlaybookExecution], int]:
        """List playbook executions with filters."""
        query = select(PlaybookExecution)
        count_query = select(func.count(PlaybookExecution.id))
        
        if playbook_id:
            query = query.where(PlaybookExecution.playbook_id == playbook_id)
            count_query = count_query.where(PlaybookExecution.playbook_id == playbook_id)
        
        if incident_id:
            query = query.where(PlaybookExecution.incident_id == incident_id)
            count_query = count_query.where(PlaybookExecution.incident_id == incident_id)
        
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        offset = (page - 1) * page_size
        query = query.order_by(PlaybookExecution.created_at.desc()).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        executions = result.scalars().all()
        
        return list(executions), total
    
    async def create_default_playbooks(self) -> List[Playbook]:
        """
        Create default playbooks for common scenarios.
        
        Returns:
            List of created playbooks
        """
        default_playbooks = [
            {
                "name": "Malware Containment",
                "description": "Isolate infected host and collect forensic evidence",
                "category": "incident_response",
                "steps": [
                    {
                        "order": 1,
                        "name": "Isolate Host",
                        "action": "isolate_host",
                        "parameters": {},
                        "on_failure": "stop",
                        "timeout_seconds": 60
                    },
                    {
                        "order": 2,
                        "name": "Collect Forensics",
                        "action": "collect_forensics",
                        "parameters": {"include_memory": True},
                        "on_failure": "continue",
                        "timeout_seconds": 300
                    },
                    {
                        "order": 3,
                        "name": "Notify Security Team",
                        "action": "notify",
                        "parameters": {
                            "channels": ["email", "slack"],
                            "template": "malware_alert"
                        },
                        "on_failure": "continue",
                        "timeout_seconds": 30
                    }
                ],
                "is_active": True,
                "is_automated": False,
                "estimated_duration": 10
            },
            {
                "name": "Compromised Account Response",
                "description": "Disable compromised user account and reset credentials",
                "category": "incident_response",
                "steps": [
                    {
                        "order": 1,
                        "name": "Disable User Account",
                        "action": "disable_user",
                        "parameters": {},
                        "on_failure": "stop",
                        "timeout_seconds": 30
                    },
                    {
                        "order": 2,
                        "name": "Revoke Active Sessions",
                        "action": "revoke_sessions",
                        "parameters": {},
                        "on_failure": "continue",
                        "timeout_seconds": 30
                    },
                    {
                        "order": 3,
                        "name": "Notify User Manager",
                        "action": "notify",
                        "parameters": {
                            "channels": ["email"],
                            "template": "account_compromised"
                        },
                        "on_failure": "continue",
                        "timeout_seconds": 30
                    }
                ],
                "is_active": True,
                "is_automated": False,
                "estimated_duration": 5
            },
            {
                "name": "Critical Vulnerability Remediation",
                "description": "Patch critical vulnerability and verify remediation",
                "category": "remediation",
                "steps": [
                    {
                        "order": 1,
                        "name": "Create Change Request",
                        "action": "create_change_request",
                        "parameters": {"priority": "critical"},
                        "on_failure": "stop",
                        "timeout_seconds": 60
                    },
                    {
                        "order": 2,
                        "name": "Apply Patch",
                        "action": "apply_patch",
                        "parameters": {},
                        "on_failure": "stop",
                        "timeout_seconds": 600
                    },
                    {
                        "order": 3,
                        "name": "Verify Remediation",
                        "action": "scan_vulnerability",
                        "parameters": {},
                        "on_failure": "continue",
                        "timeout_seconds": 300
                    },
                    {
                        "order": 4,
                        "name": "Update Risk Status",
                        "action": "update_risk",
                        "parameters": {"status": "mitigated"},
                        "on_failure": "continue",
                        "timeout_seconds": 30
                    }
                ],
                "is_active": True,
                "is_automated": False,
                "estimated_duration": 20
            },
            {
                "name": "Block Malicious IP",
                "description": "Block malicious IP address at firewall",
                "category": "containment",
                "steps": [
                    {
                        "order": 1,
                        "name": "Block IP at Firewall",
                        "action": "block_ip",
                        "parameters": {},
                        "on_failure": "stop",
                        "timeout_seconds": 30
                    },
                    {
                        "order": 2,
                        "name": "Add to Threat Intel",
                        "action": "add_to_blocklist",
                        "parameters": {"list": "malicious_ips"},
                        "on_failure": "continue",
                        "timeout_seconds": 30
                    },
                    {
                        "order": 3,
                        "name": "Log Action",
                        "action": "notify",
                        "parameters": {
                            "channels": ["log"],
                            "template": "ip_blocked"
                        },
                        "on_failure": "continue",
                        "timeout_seconds": 10
                    }
                ],
                "is_active": True,
                "is_automated": True,
                "estimated_duration": 2
            }
        ]
        
        created_playbooks = []
        for pb_data in default_playbooks:
            existing = await self.get_by_name(pb_data["name"])
            if not existing:
                playbook = await self.create_playbook(pb_data)
                created_playbooks.append(playbook)
            else:
                created_playbooks.append(existing)
        
        logger.info("Created default playbooks", count=len(created_playbooks))
        return created_playbooks
