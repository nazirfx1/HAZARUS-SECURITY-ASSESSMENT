"""
HAZARUS Core Tests
Tests for core engine components.
"""

import pytest
import asyncio
from core.event_bus import EventBus, Event
from core.task_manager import TaskManager, TaskStatus
from core.state_manager import StateManager, AssessmentState


@pytest.mark.asyncio
async def test_event_bus():
    """Test event bus functionality."""
    bus = EventBus()
    events_received = []

    async def handler(event):
        events_received.append(event)

    bus.subscribe("test_event", handler)

    # Test emit
    event_data = {"test": "data"}
    await bus.emit("test_event", event_data)

    assert len(events_received) == 1
    assert events_received[0].event_type == "test_event"


def test_state_manager():
    """Test state manager."""
    state = AssessmentState(assessment_id="test-assessment")

    assert state.assessment_id == "test-assessment"
    assert state.status == "initialized"

    state.update_status("running")
    assert state.status == "running"

