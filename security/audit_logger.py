"""
HAZARUS Audit Logger
Comprehensive logging for security auditing and compliance.
"""

from typing import Dict, Any, Optional
from datetime import datetime
import logging
import json
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class AuditEvent:
    """An audit event."""
    event_type: str
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    assessment_id: Optional[str] = None
    operator_id: Optional[str] = None
    severity: str = "info"  # info, warning, error, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "assessment_id": self.assessment_id,
            "operator_id": self.operator_id,
            "severity": self.severity
        }


class AuditLogger:
    """
    Comprehensive audit logging for security assessments.
    All operations are logged for compliance and accountability.
    """

    def __init__(self, assessment_id: str, log_dir: Optional[Path] = None):
        self.assessment_id = assessment_id
        self.logger = logging.getLogger("hazarus.audit_logger")

        if log_dir is None:
            log_dir = Path.home() / ".hazarus" / "audit_logs"

        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_file = self.log_dir / f"{assessment_id}.jsonl"
        self._events: list[AuditEvent] = []
        self._closed = False

    async def log_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "info",
        operator_id: Optional[str] = None
    ) -> None:
        """Log an audit event."""
        if self._closed:
            self.logger.warning("Attempted to log event after audit logger closed")
            return

        event = AuditEvent(
            event_type=event_type,
            details=details,
            assessment_id=self.assessment_id,
            operator_id=operator_id,
            severity=severity
        )

        self._events.append(event)

        # Write to file immediately
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")

        # Also log to standard logger
        log_msg = f"[{event_type}] {json.dumps(details)}"
        if severity == "critical":
            self.logger.critical(log_msg)
        elif severity == "error":
            self.logger.error(log_msg)
        elif severity == "warning":
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)

    async def log_scope_change(self, old_scope: Dict, new_scope: Dict, operator_id: str) -> None:
        """Log a scope change."""
        await self.log_event(
            event_type="scope_change",
            details={
                "old_scope": old_scope,
                "new_scope": new_scope
            },
            severity="warning",
            operator_id=operator_id
        )

    async def log_exploitation(
        self,
        exploit_id: str,
        target: str,
        result: str,
        operator_id: str
    ) -> None:
        """Log an exploitation attempt."""
        await self.log_event(
            event_type="exploitation",
            details={
                "exploit_id": exploit_id,
                "target": target,
                "result": result
            },
            severity="critical",
            operator_id=operator_id
        )

    async def log_privilege_escalation(
        self,
        target: str,
        method: str,
        success: bool,
        operator_id: str
    ) -> None:
        """Log a privilege escalation attempt."""
        await self.log_event(
            event_type="privilege_escalation",
            details={
                "target": target,
                "method": method,
                "success": success
            },
            severity="critical" if success else "warning",
            operator_id=operator_id
        )

    async def log_data_access(
        self,
        target: str,
        data_type: str,
        count: int,
        operator_id: str
    ) -> None:
        """Log data access."""
        await self.log_event(
            event_type="data_access",
            details={
                "target": target,
                "data_type": data_type,
                "count": count
            },
            severity="warning",
            operator_id=operator_id
        )

    async def log_emergency_stop(self, reason: str, operator_id: str) -> None:
        """Log an emergency stop."""
        await self.log_event(
            event_type="emergency_stop",
            details={"reason": reason},
            severity="critical",
            operator_id=operator_id
        )

    def get_events(self, event_type: Optional[str] = None) -> list[AuditEvent]:
        """Get logged events, optionally filtered by type."""
        if event_type:
            return [e for e in self._events if e.event_type == event_type]
        return self._events.copy()

    def get_critical_events(self) -> list[AuditEvent]:
        """Get all critical events."""
        return [e for e in self._events if e.severity == "critical"]

    def get_events_by_operator(self, operator_id: str) -> list[AuditEvent]:
        """Get events by operator."""
        return [e for e in self._events if e.operator_id == operator_id]

    async def finalize(self) -> None:
        """Finalize the audit log."""
        self._closed = True

        # Write summary
        summary = {
            "assessment_id": self.assessment_id,
            "total_events": len(self._events),
            "critical_events": len(self.get_critical_events()),
            "finalized_at": datetime.utcnow().isoformat()
        }

        summary_file = self.log_dir / f"{self.assessment_id}_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        self.logger.info(f"Audit log finalized: {len(self._events)} events")
