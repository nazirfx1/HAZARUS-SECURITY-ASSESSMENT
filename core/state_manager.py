"""
HAZARUS State Manager
Manages persistent state for assessments.
"""

from typing import Dict, Any, Optional
import json
import logging
from pathlib import Path
from datetime import datetime, UTC
from dataclasses import dataclass, asdict


@dataclass
class AssessmentState:
    """Persistent state for an assessment."""
    assessment_id: str
    status: str = "initialized"
    current_phase: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    metadata: Dict[str, Any] = None
    results: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.results is None:
            self.results = {}

    def update_status(self, status: str) -> None:
        """Update assessment status."""
        self.status = status

    def update_phase(self, phase: str) -> None:
        """Update current phase."""
        self.current_phase = phase

    def update_metadata(self, key: str, value: Any) -> None:
        """Update metadata."""
        self.metadata[key] = value

    def update_results(self, key: str, value: Any) -> None:
        """Update results."""
        self.results[key] = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AssessmentState":
        """Create from dictionary."""
        return cls(**data)


class StateManager:
    """
    Manages persistent state for assessments.
    Saves state to JSON files for resumption capability.
    """

    def __init__(self, assessment_id: str, state_dir: Optional[Path] = None):
        self.assessment_id = assessment_id
        self.logger = logging.getLogger("hazarus.state_manager")

        if state_dir is None:
            state_dir = Path.home() / ".hazarus" / "state"

        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.state_file = self.state_dir / f"{assessment_id}.json"
        self.state: Optional[AssessmentState] = None

    async def initialize(self) -> None:
        """Initialize the state manager."""
        # Try to load existing state
        if self.state_file.exists():
            self.state = await self.load_state()
            self.logger.info(f"Loaded existing state for assessment {self.assessment_id}")
        else:
            self.state = AssessmentState(assessment_id=self.assessment_id)
            await self.save_state()
            self.logger.info(f"Created new state for assessment {self.assessment_id}")

    async def load_state(self) -> Optional[AssessmentState]:
        """Load state from disk."""
        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)
            return AssessmentState.from_dict(data)
        except Exception as e:
            self.logger.error(f"Failed to load state: {e}")
            return None

    async def save_state(self) -> bool:
        """Save state to disk."""
        if not self.state:
            return False

        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state.to_dict(), f, indent=2, default=str)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
            return False

    def get_state(self) -> Optional[AssessmentState]:
        """Get current state."""
        return self.state

    def update_status(self, status: str) -> None:
        """Update assessment status."""
        if self.state:
            self.state.status = status

    def update_phase(self, phase: str) -> None:
        """Update current phase."""
        if self.state:
            self.state.current_phase = phase

    def update_metadata(self, key: str, value: Any) -> None:
        """Update metadata."""
        if self.state:
            self.state.metadata[key] = value

    def update_results(self, key: str, value: Any) -> None:
        """Update results."""
        if self.state:
            self.state.results[key] = value

    def set_start_time(self, timestamp: Optional[datetime] = None) -> None:
        """Set assessment start time."""
        if self.state:
            self.state.start_time = (timestamp or datetime.now(UTC)).isoformat()

    def set_end_time(self, timestamp: Optional[datetime] = None) -> None:
        """Set assessment end time."""
        if self.state:
            self.state.end_time = (timestamp or datetime.now(UTC)).isoformat()

    async def cleanup(self) -> None:
        """Clean up state file."""
        if self.state_file.exists():
            try:
                self.state_file.unlink()
                self.logger.info(f"Cleaned up state file: {self.state_file}")
            except Exception as e:
                self.logger.error(f"Failed to cleanup state file: {e}")
