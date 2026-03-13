"""
Contexta Backend - Response Service

Automatically selects and executes the appropriate playbook
when an incident is created or updated, based on its type.
"""

from typing import Any, Dict, Optional
import structlog

from app.playbooks.engine import PlaybookEngine

logger = structlog.get_logger()

# Built-in playbook definitions keyed by incident type.
# These are intentionally self-contained so no external files need to change.
_PLAYBOOK_REGISTRY: Dict[str, Dict[str, Any]] = {
    "DDoS": {
        "id": "ddos_mitigation",
        "name": "DDoS Mitigation Playbook",
        "description": "Mitigate an active DDoS attack",
        "version": "1.0",
        "category": "network",
        "severity_threshold": "high",
        "steps": [
            {
                "order": 1,
                "name": "Enable Rate Limiting",
                "description": "Apply rate-limiting rules on edge routers",
                "action_type": "automated",
                "automation_script": "block_iocs.py",
                "timeout_minutes": 5,
                "required": True,
            },
            {
                "order": 2,
                "name": "Block Malicious IPs",
                "description": "Block source IPs identified in the attack",
                "action_type": "automated",
                "automation_script": "block_iocs.py",
                "timeout_minutes": 10,
                "required": True,
            },
            {
                "order": 3,
                "name": "Notify SOC Team",
                "description": "Alert the SOC team about the ongoing DDoS",
                "action_type": "automated",
                "automation_script": "notify_ir_team.py",
                "timeout_minutes": 5,
                "required": True,
            },
            {
                "order": 4,
                "name": "Log Mitigation Actions",
                "description": "Record all mitigation steps taken",
                "action_type": "automated",
                "automation_script": "preserve_evidence.py",
                "timeout_minutes": 5,
                "required": True,
            },
            {
                "order": 5,
                "name": "Verify Service Restoration",
                "description": "Confirm services have recovered",
                "action_type": "manual",
                "timeout_minutes": 30,
                "required": True,
            },
        ],
    },
    "BruteForce": {
        "id": "bruteforce_response",
        "name": "Brute-Force Response Playbook",
        "description": "Respond to brute-force login attempts",
        "version": "1.0",
        "category": "authentication",
        "severity_threshold": "medium",
        "steps": [
            {
                "order": 1,
                "name": "Block Attacker IPs",
                "description": "Block IPs performing brute-force attempts",
                "action_type": "automated",
                "automation_script": "block_iocs.py",
                "timeout_minutes": 5,
                "required": True,
            },
            {
                "order": 2,
                "name": "Isolate Targeted Host",
                "description": "Temporarily isolate the targeted authentication service",
                "action_type": "automated",
                "automation_script": "isolate_host.py",
                "timeout_minutes": 10,
                "required": True,
            },
            {
                "order": 3,
                "name": "Notify Security Team",
                "description": "Alert the security team about the brute-force campaign",
                "action_type": "automated",
                "automation_script": "notify_ir_team.py",
                "timeout_minutes": 5,
                "required": True,
            },
            {
                "order": 4,
                "name": "Log Incident Details",
                "description": "Record attack details for audit and forensics",
                "action_type": "automated",
                "automation_script": "preserve_evidence.py",
                "timeout_minutes": 5,
                "required": True,
            },
            {
                "order": 5,
                "name": "Review Account Integrity",
                "description": "Verify no accounts were compromised",
                "action_type": "manual",
                "timeout_minutes": 60,
                "required": True,
            },
        ],
    },
}


class ResponseService:
    """
    Orchestrates automatic playbook execution for incidents.

    Call :meth:`handle_incident` with an incident dict.  If the
    incident type matches a registered playbook the engine runs it
    and returns the execution summary.
    """

    def __init__(self) -> None:
        self.engine = PlaybookEngine()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handle_incident(self, incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Determine the incident type and run the matching playbook.

        The incident type is detected from an explicit ``type`` field
        first; if absent it is inferred from the ``title`` /
        ``description`` text.

        Args:
            incident: Incident data dict (id, title, description,
                      iocs, affected_assets, …).

        Returns:
            Playbook execution summary dict, or ``None`` if no
            playbook matched.
        """
        incident_type = self._detect_type(incident)

        if incident_type is None:
            logger.info(
                "No matching playbook for incident",
                incident_id=str(incident.get("id", "unknown")),
            )
            return None

        playbook = _PLAYBOOK_REGISTRY[incident_type]

        logger.info(
            "Auto-executing playbook",
            incident_id=str(incident.get("id", "unknown")),
            incident_type=incident_type,
            playbook=playbook["id"],
        )

        result = self.engine.execute(playbook, incident)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_type(incident: Dict[str, Any]) -> Optional[str]:
        """Return the registry key if the incident matches, else None."""
        # 1. Explicit type field
        explicit = incident.get("type", "")
        if explicit in _PLAYBOOK_REGISTRY:
            return explicit

        # 2. Keyword match against title + description
        text = (
            f"{incident.get('title', '')} {incident.get('description', '')}"
        ).lower()

        keyword_map = {
            "DDoS": ["ddos", "distributed denial", "denial of service", "denial-of-service"],
            "BruteForce": ["brute force", "brute-force", "bruteforce", "credential stuffing", "login attempts"],
        }

        for type_key, keywords in keyword_map.items():
            if any(kw in text for kw in keywords):
                return type_key

        return None
