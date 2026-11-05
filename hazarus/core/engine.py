"""
HAZARUS Core Engine
Central orchestration engine for the security assessment framework.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, UTC
import asyncio
import logging
from dataclasses import dataclass, field

try:
    from security.scope import ScopeManager
    from security.authorization import AuthorizationManager
    from security.safety_gate import SafetyGate
    from security.audit_logger import AuditLogger
    from anonymity.anonsurf import AnonsurfManager
    from anonymity.privacy_report import PrivacyReport
    from core.event_bus import EventBus
    from core.task_manager import TaskManager
    from core.state_manager import StateManager
except ImportError:
    # Relative imports for package structure
    from ..security.scope import ScopeManager
    from ..security.authorization import AuthorizationManager
    from ..security.safety_gate import SafetyGate
    from ..security.audit_logger import AuditLogger
    from ..anonymity.anonsurf import AnonsurfManager
    from ..anonymity.privacy_report import PrivacyReport
    from .event_bus import EventBus
    from .task_manager import TaskManager
    from .state_manager import StateManager


@dataclass
class AssessmentConfig:
    """Configuration for a security assessment."""
    assessment_id: str
    targets: List[str]
    scope_file: str
    intensity: str = "normal"  # low, normal, high
    privacy_mode: str = "strict"  # strict, balanced, permissive
    max_threads: int = 10
    timeout: int = 300
    log_level: str = "INFO"


class HazarusEngine:
    """
    Core engine for HAZARUS Security Assessment Framework.
    Orchestrates all assessment components and enforces security policies.
    """

    def __init__(self, config: AssessmentConfig):
        self.config = config
        self.logger = logging.getLogger("hazarus.engine")
        self.logger.setLevel(config.log_level)

        # Initialize core components
        self.event_bus = EventBus()
        self.task_manager = TaskManager(self.event_bus)
        self.state_manager = StateManager(config.assessment_id)

        # Initialize security components
        self.scope_manager = ScopeManager(config.scope_file)
        self.authorization_manager = AuthorizationManager()
        self.safety_gate = SafetyGate(self.scope_manager, self.authorization_manager)
        self.audit_logger = AuditLogger(config.assessment_id)

        # Initialize anonymity components
        self.anonsurf_manager = AnonsurfManager()

        # Assessment state
        self._running = False
        self._paused = False
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None

    async def initialize(self) -> bool:
        """Initialize the engine and validate prerequisites."""
        self.logger.info(f"Initializing HAZARUS engine for assessment {self.config.assessment_id}")

        # Load scope
        if not await self.scope_manager.load_scope():
            self.logger.error("Failed to load scope configuration")
            return False

        # Validate scope
        if not self.scope_manager.validate_targets(self.config.targets):
            self.logger.error("Target validation failed")
            return False

        # Initialize state manager
        await self.state_manager.initialize()

        # Log initialization
        await self.audit_logger.log_event(
            event_type="engine_init",
            details={
                "assessment_id": self.config.assessment_id,
                "targets": self.config.targets,
                "intensity": self.config.intensity,
                "privacy_mode": self.config.privacy_mode
            }
        )

        self.logger.info("Engine initialization complete")
        return True

    async def verify_privacy(self) -> PrivacyReport:
        """
        Verify privacy/anonymity configuration before assessment.
        Returns a detailed privacy report.
        """
        self.logger.info("Verifying privacy configuration")

        report = PrivacyReport(assessment_id=self.config.assessment_id)

        # Check Anonsurf status
        report.anonsurf_installed = await self.anonsurf_manager.check_installed()
        report.anonsurf_running = await self.anonsurf_manager.check_running()

        # Check Tor connectivity
        report.tor_available = await self.anonsurf_manager.check_tor_connectivity()

        # Check for DNS leaks
        report.dns_leak_detected = await self.anonsurf_manager.check_dns_leak()

        # Check IPv6 exposure
        report.ipv6_exposed = await self.anonsurf_manager.check_ipv6_exposure()

        # Generate overall privacy status
        report.privacy_status = self._evaluate_privacy_status(report)

        # Log privacy check
        await self.audit_logger.log_event(
            event_type="privacy_check",
            details=report.to_dict()
        )

        return report

    def _evaluate_privacy_status(self, report: PrivacyReport) -> str:
        """Evaluate overall privacy status based on checks."""
        if report.privacy_mode == "strict":
            if not report.anonsurf_running or not report.tor_available:
                return "failed"
            if report.dns_leak_detected or report.ipv6_exposed:
                return "failed"
            return "pass"
        elif report.privacy_mode == "balanced":
            if report.anonsurf_running and report.tor_available:
                return "pass"
            return "warning"
        else:  # permissive
            return "pass"

    async def run_assessment(self) -> Dict[str, Any]:
        """
        Execute the full security assessment.
        This is the main entry point for assessment execution.
        """
        self.logger.info(f"Starting assessment {self.config.assessment_id}")
        self._running = True
        self._start_time = datetime.now(UTC)

        # Verify privacy before starting
        privacy_report = await self.verify_privacy()
        if privacy_report.privacy_status == "failed":
            error_msg = "Privacy verification failed. Assessment cannot proceed."
            self.logger.error(error_msg)
            await self.audit_logger.log_event(
                event_type="assessment_blocked",
                details={"reason": "privacy_failed", "report": privacy_report.to_dict()}
            )
            raise RuntimeError(error_msg)

        # Execute assessment phases
        results = {
            "assessment_id": self.config.assessment_id,
            "targets": self.config.targets,
            "start_time": self._start_time.isoformat(),
            "phases": {}
        }

        try:
            # Phase 1: Reconnaissance
            self.logger.info("Starting reconnaissance phase")
            results["phases"]["reconnaissance"] = await self._run_reconnaissance()

            # Phase 2: Scanning
            self.logger.info("Starting scanning phase")
            results["phases"]["scanning"] = await self._run_scanning()

            # Phase 3: Vulnerability Assessment
            self.logger.info("Starting vulnerability assessment phase")
            results["phases"]["vulnerability"] = await self._run_vulnerability_assessment()

            # Phase 4: Post-assessment
            self.logger.info("Starting post-assessment phase")
            results["phases"]["post_assessment"] = await self._run_post_assessment()

        except Exception as e:
            self.logger.error(f"Assessment failed: {e}")
            await self.audit_logger.log_event(
                event_type="assessment_error",
                details={"error": str(e)}
            )
            raise
        finally:
            self._running = False
            self._end_time = datetime.now(UTC)
            results["end_time"] = self._end_time.isoformat()
            results["duration_seconds"] = (self._end_time - self._start_time).total_seconds()

            await self.audit_logger.log_event(
                event_type="assessment_complete",
                details={"duration": results["duration_seconds"]}
            )

        return results

    async def _run_reconnaissance(self) -> Dict[str, Any]:
        """Execute reconnaissance phase."""
        # Placeholder - will be implemented in Stage 4
        await self.audit_logger.log_event(event_type="phase_start", details={"phase": "reconnaissance"})
        return {"status": "pending", "message": "Reconnaissance module to be implemented"}

    async def _run_scanning(self) -> Dict[str, Any]:
        """Execute scanning phase."""
        # Placeholder - will be implemented in Stage 4
        await self.audit_logger.log_event(event_type="phase_start", details={"phase": "scanning"})
        return {"status": "pending", "message": "Scanning module to be implemented"}

    async def _run_vulnerability_assessment(self) -> Dict[str, Any]:
        """Execute vulnerability assessment phase."""
        # Placeholder - will be implemented in Stage 5-6
        await self.audit_logger.log_event(event_type="phase_start", details={"phase": "vulnerability"})
        return {"status": "pending", "message": "Vulnerability assessment module to be implemented"}

    async def _run_post_assessment(self) -> Dict[str, Any]:
        """Execute post-assessment phase."""
        # Placeholder - will be implemented in Stage 9
        await self.audit_logger.log_event(event_type="phase_start", details={"phase": "post_assessment"})
        return {"status": "pending", "message": "Post-assessment module to be implemented"}

    async def pause(self) -> None:
        """Pause the assessment."""
        self._paused = True
        await self.task_manager.pause_all()
        await self.audit_logger.log_event(event_type="assessment_paused", details={})
        self.logger.info("Assessment paused")

    async def resume(self) -> None:
        """Resume the assessment."""
        self._paused = False
        await self.task_manager.resume_all()
        await self.audit_logger.log_event(event_type="assessment_resumed", details={})
        self.logger.info("Assessment resumed")

    async def stop(self) -> None:
        """Stop the assessment gracefully."""
        self._running = False
        await self.task_manager.stop_all()
        await self.audit_logger.log_event(event_type="assessment_stopped", details={})
        self.logger.info("Assessment stopped")

    async def emergency_stop(self) -> None:
        """Emergency stop - terminate all operations immediately."""
        self._running = False
        await self.task_manager.kill_all()
        await self.audit_logger.log_event(event_type="emergency_stop", details={})
        self.logger.warning("Emergency stop executed")

    def is_running(self) -> bool:
        """Check if the assessment is currently running."""
        return self._running

    def is_paused(self) -> bool:
        """Check if the assessment is paused."""
        return self._paused

    async def cleanup(self) -> None:
        """Cleanup resources and finalize assessment."""
        self.logger.info("Cleaning up engine resources")
        await self.state_manager.save_state()
        await self.audit_logger.finalize()
        self.logger.info("Cleanup complete")
