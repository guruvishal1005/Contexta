"""
Contexta Backend - Playbook Execution Engine

Executes response playbooks against incidents, running each step
in order and dispatching supported actions (block_ip, isolate_host,
notify_team, log_action).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import structlog

from app.ledger.chain import get_ledger, LedgerEventTypes

logger = structlog.get_logger()


class PlaybookEngine:
    """
    Executes a response playbook's steps against an incident context.

    Supported automated actions:
        block_ip      – simulates blocking an IP address
        isolate_host  – simulates isolating a host from the network
        notify_team   – simulates sending a notification to a team
        log_action    – logs an arbitrary action for audit purposes
    """

    # Maps action name → handler method name
    _ACTION_HANDLERS = {
        "block_ip": "_action_block_ip",
        "isolate_host": "_action_isolate_host",
        "notify_team": "_action_notify_team",
        "log_action": "_action_log_action",
    }

    def execute(
        self,
        playbook: Dict[str, Any],
        incident: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute every step in *playbook* using the *incident* as context.

        Args:
            playbook: Parsed playbook JSON (must contain ``steps``).
            incident: Incident data dict with fields like ``id``,
                      ``title``, ``iocs``, ``affected_assets``, etc.

        Returns:
            A summary dict::

                {
                    "playbook_id": str,
                    "incident_id": str,
                    "started_at": str,
                    "completed_at": str,
                    "steps_total": int,
                    "steps_executed": int,
                    "steps_skipped": int,
                    "results": [ { step‑level detail … }, … ]
                }
        """
        playbook_id = playbook.get("id", "unknown")
        incident_id = str(incident.get("id", "unknown"))

        logger.info(
            "Playbook execution started",
            playbook=playbook_id,
            incident=incident_id,
        )

        started_at = datetime.now(timezone.utc).isoformat()
        results: List[Dict[str, Any]] = []
        steps_executed = 0
        steps_skipped = 0

        steps = sorted(playbook.get("steps", []), key=lambda s: s.get("order", 0))

        for step in steps:
            step_name = step.get("name", "unnamed")
            action_type = step.get("action_type", "manual")

            if action_type != "automated":
                # Manual steps are recorded but not executed by the engine
                results.append(self._skip_result(step, reason="manual step"))
                steps_skipped += 1
                logger.info("Skipping manual step", step=step_name)
                continue

            # Derive the action key from the automation_script field
            action_key = self._resolve_action(step)
            handler_name = self._ACTION_HANDLERS.get(action_key)

            if handler_name is None:
                results.append(
                    self._skip_result(step, reason=f"unsupported action: {action_key}")
                )
                steps_skipped += 1
                logger.warning("Unsupported action", step=step_name, action=action_key)
                continue

            handler = getattr(self, handler_name)
            step_result = handler(step, incident)
            self._record_to_ledger(action_key, step_result, incident)
            results.append(step_result)
            steps_executed += 1

        completed_at = datetime.now(timezone.utc).isoformat()

        summary = {
            "playbook_id": playbook_id,
            "incident_id": incident_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "steps_total": len(steps),
            "steps_executed": steps_executed,
            "steps_skipped": steps_skipped,
            "results": results,
        }

        logger.info(
            "Playbook execution completed",
            playbook=playbook_id,
            incident=incident_id,
            executed=steps_executed,
            skipped=steps_skipped,
        )

        return summary

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _action_block_ip(
        self, step: Dict[str, Any], incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        iocs = incident.get("iocs", {})
        ips: List[str] = iocs.get("ips", [])
        for ip in ips:
            logger.info(f"Blocking IP {ip}")
        return self._step_result(
            step, status="executed", detail=f"Blocked {len(ips)} IP(s): {ips}"
        )

    def _action_isolate_host(
        self, step: Dict[str, Any], incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        targets = incident.get("affected_assets", [])
        for target in targets:
            logger.info(f"Isolating host {target}")
        return self._step_result(
            step,
            status="executed",
            detail=f"Isolated {len(targets)} host(s): {targets}",
        )

    def _action_notify_team(
        self, step: Dict[str, Any], incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        team = step.get("notify_targets") or ["soc_team"]
        incident_title = incident.get("title", "N/A")
        for t in team:
            logger.info(f"Notifying team {t} about incident: {incident_title}")
        return self._step_result(
            step, status="executed", detail=f"Notified teams: {team}"
        )

    def _action_log_action(
        self, step: Dict[str, Any], incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        msg = step.get("description", step.get("name", "action"))
        logger.info(f"Log action: {msg} [incident={incident.get('id')}]")
        return self._step_result(step, status="executed", detail=f"Logged: {msg}")

    # ------------------------------------------------------------------
    # Ledger integration
    # ------------------------------------------------------------------

    @staticmethod
    def _record_to_ledger(
        action_key: str,
        step_result: Dict[str, Any],
        incident: Dict[str, Any],
    ) -> None:
        """Record an executed action to the audit ledger."""
        action_labels = {
            "block_ip": "IP_BLOCKED",
            "isolate_host": "HOST_ISOLATED",
            "notify_team": "TEAM_NOTIFIED",
            "log_action": "ACTION_LOGGED",
        }
        try:
            ledger = get_ledger()
            ledger.add_block(
                event_type=LedgerEventTypes.ACTION_TAKEN,
                data={
                    "action": action_labels.get(action_key, action_key.upper()),
                    "target": step_result.get("detail", ""),
                    "step": step_result.get("name"),
                    "incident_id": str(incident.get("id", "unknown")),
                    "timestamp": step_result.get("timestamp"),
                },
                actor="playbook_engine",
            )
        except Exception as exc:
            logger.error("Failed to record action to ledger", error=str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_action(step: Dict[str, Any]) -> str:
        """Derive an action key from the step's automation_script field."""
        script: str = step.get("automation_script", "")
        # Strip path and extension: "block_iocs.py" -> "block_iocs"
        key = script.rsplit("/", 1)[-1].replace(".py", "")

        # Map known script names to supported action keys
        script_map = {
            "block_iocs": "block_ip",
            "notify_ir_team": "notify_team",
            "send_breach_notifications": "notify_team",
            "preserve_evidence": "log_action",
            "analyze_malware": "log_action",
            "network_scan": "log_action",
        }
        return script_map.get(key, key)

    @staticmethod
    def _step_result(
        step: Dict[str, Any],
        status: str,
        detail: str = "",
    ) -> Dict[str, Any]:
        return {
            "order": step.get("order"),
            "name": step.get("name"),
            "status": status,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _skip_result(
        step: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        return {
            "order": step.get("order"),
            "name": step.get("name"),
            "status": "skipped",
            "detail": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
