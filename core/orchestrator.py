"""
HAZARUS Orchestrator
Coordinates assessment phases and module execution.
"""

from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import asyncio
import logging
from dataclasses import dataclass
from enum import Enum

from .event_bus import EventBus
from .task_manager import TaskManager


class Phase(Enum):
    """Assessment phases."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_ASSESSMENT = "post_assessment"
    CODE_ANALYSIS = "code_analysis"
    REPORTING = "reporting"


@dataclass
class PhaseResult:
    """Result of an assessment phase."""
    phase: Phase
    status: str  # pending, running, completed, failed, skipped
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    data: Dict[str, Any] = None
    error: Optional[str] = None


class Orchestrator:
    """
    Orchestrates assessment phases and module execution.
    Manages the flow of assessment operations.
    """

    def __init__(self, event_bus: EventBus, task_manager: TaskManager):
        self.event_bus = event_bus
        self.task_manager = task_manager
        self.logger = logging.getLogger("hazarus.orchestrator")

        self._phase_handlers: Dict[Phase, Callable] = {}
        self._phase_results: Dict[Phase, PhaseResult] = {}
        self._current_phase: Optional[Phase] = None

    def register_phase_handler(self, phase: Phase, handler: Callable) -> None:
        """Register a handler for a specific phase."""
        self._phase_handlers[phase] = handler
        self.logger.debug(f"Registered handler for phase: {phase.value}")

    async def execute_phase(self, phase: Phase, **kwargs) -> PhaseResult:
        """
        Execute a single assessment phase.
        """
        self.logger.info(f"Executing phase: {phase.value}")
        self._current_phase = phase

        result = PhaseResult(phase=phase, status="running", start_time=datetime.utcnow())

        # Emit phase start event
        await self.event_bus.emit("phase_start", {"phase": phase.value})

        try:
            if phase not in self._phase_handlers:
                raise ValueError(f"No handler registered for phase: {phase.value}")

            # Execute the phase handler
            phase_data = await self._phase_handlers[phase](**kwargs)
            result.data = phase_data
            result.status = "completed"

            # Emit phase complete event
            await self.event_bus.emit("phase_complete", {
                "phase": phase.value,
                "data": phase_data
            })

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            self.logger.error(f"Phase {phase.value} failed: {e}")

            # Emit phase failed event
            await self.event_bus.emit("phase_failed", {
                "phase": phase.value,
                "error": str(e)
            })

        finally:
            result.end_time = datetime.utcnow()
            self._phase_results[phase] = result
            self._current_phase = None

        return result

    async def execute_sequence(
        self,
        phases: List[Phase],
        stop_on_failure: bool = True,
        **kwargs
    ) -> Dict[Phase, PhaseResult]:
        """
        Execute a sequence of phases.
        """
        self.logger.info(f"Executing phase sequence: {[p.value for p in phases]}")
        results = {}

        for phase in phases:
            result = await self.execute_phase(phase, **kwargs)
            results[phase] = result

            if result.status == "failed" and stop_on_failure:
                self.logger.warning(f"Stopping sequence due to failure in phase: {phase.value}")
                break

        return results

    async def execute_parallel(
        self,
        phases: List[Phase],
        **kwargs
    ) -> Dict[Phase, PhaseResult]:
        """
        Execute multiple phases in parallel.
        """
        self.logger.info(f"Executing phases in parallel: {[p.value for p in phases]}")

        tasks = [self.execute_phase(phase, **kwargs) for phase in phases]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for phase, result in zip(phases, results_list):
            if isinstance(result, Exception):
                results[phase] = PhaseResult(
                    phase=phase,
                    status="failed",
                    error=str(result)
                )
            else:
                results[phase] = result

        return results

    def get_phase_result(self, phase: Phase) -> Optional[PhaseResult]:
        """Get the result of a specific phase."""
        return self._phase_results.get(phase)

    def get_all_results(self) -> Dict[Phase, PhaseResult]:
        """Get all phase results."""
        return self._phase_results.copy()

    def get_current_phase(self) -> Optional[Phase]:
        """Get the currently executing phase."""
        return self._current_phase

    def reset(self) -> None:
        """Reset orchestrator state."""
        self._phase_results.clear()
        self._current_phase = None
        self.logger.debug("Orchestrator reset")
