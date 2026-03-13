"""
Contexta Backend - Attack Simulator

Generates mock incidents for the three supported attack types and
feeds them through the normal SOC pipeline (ResponseService →
PlaybookEngine → Ledger).

Usage::

    from app.services.attack_simulator import simulate_attack

    result = simulate_attack("DDoS")
    result = simulate_attack("BruteForce")
    result = simulate_attack("PortScan")
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
import structlog

from app.services.response_service import ResponseService

logger = structlog.get_logger()

# Pre-built mock incident templates per attack type.
_ATTACK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "PortScan": {
        "title": "Port Scan detected on perimeter firewall",
        "description": (
            "Sequential port scan observed from external IP targeting "
            "ports 22, 80, 443, 3306, 5432, 8080. Likely reconnaissance activity."
        ),
        "severity": "medium",
        "type": "PortScan",
        "iocs": {
            "ips": ["198.51.100.23"],
            "domains": [],
            "hashes": [],
        },
        "affected_assets": ["Firewall", "Web-01"],
    },
    "DDoS": {
        "title": "Volumetric DDoS attack on public API gateway",
        "description": (
            "Sustained flood of UDP and SYN packets detected at 12 Gbps, "
            "originating from a botnet of ~2,000 IPs. Service degradation observed."
        ),
        "severity": "critical",
        "type": "DDoS",
        "iocs": {
            "ips": ["203.0.113.50", "203.0.113.51", "203.0.113.52"],
            "domains": ["bad-c2.example.com"],
            "hashes": [],
        },
        "affected_assets": ["LoadBalancer", "Web-01", "Web-02"],
    },
    "BruteForce": {
        "title": "Brute-force login campaign against admin portal",
        "description": (
            "Over 15,000 failed SSH login attempts in the last 20 minutes "
            "from a single source IP. Credential stuffing suspected."
        ),
        "severity": "high",
        "type": "BruteForce",
        "iocs": {
            "ips": ["192.0.2.99"],
            "domains": [],
            "hashes": [],
        },
        "affected_assets": ["Admin Host"],
    },
}


def simulate_attack(attack_type: str) -> Dict[str, Any]:
    """
    Create a mock incident for *attack_type* and run it through the
    SOC response pipeline.

    Supported types: ``PortScan``, ``DDoS``, ``BruteForce``.

    Args:
        attack_type: One of the supported attack type strings.

    Returns:
        A dict with ``incident`` (the mock data) and ``playbook_result``
        (the playbook execution summary, or ``None`` if no playbook matched).

    Raises:
        ValueError: If *attack_type* is not recognised.
    """
    template = _ATTACK_TEMPLATES.get(attack_type)
    if template is None:
        supported = ", ".join(sorted(_ATTACK_TEMPLATES))
        raise ValueError(
            f"Unknown attack type '{attack_type}'. Supported: {supported}"
        )

    # Build a concrete incident from the template
    incident: Dict[str, Any] = {
        "id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        **template,
    }

    logger.info(
        "Attack simulation started",
        attack_type=attack_type,
        incident_id=incident["id"],
    )

    # Feed through the response pipeline
    response_service = ResponseService()
    playbook_result = response_service.handle_incident(incident)

    logger.info(
        "Attack simulation completed",
        attack_type=attack_type,
        incident_id=incident["id"],
        playbook_matched=playbook_result is not None,
    )

    return {
        "incident": incident,
        "playbook_result": playbook_result,
    }
