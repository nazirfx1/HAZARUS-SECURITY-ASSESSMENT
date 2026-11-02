"""
HAZARUS Core Modules Tests
Tests for core architecture components - simplified to match actual interfaces.
"""

import pytest
import asyncio
from datetime import datetime, UTC
from core.engine import AssessmentConfig
from core.scheduler import Scheduler
from core.state_manager import AssessmentState
from core.event_bus import EventBus, Event


@pytest.mark.asyncio
async def test_scheduler_initialization():
    """Test scheduler initialization."""
    scheduler = Scheduler()

    assert scheduler is not None
    assert scheduler._running is False


@pytest.mark.asyncio
async def test_scheduler_start_stop():
    """Test starting and stopping scheduler."""
    scheduler = Scheduler()

    await scheduler.start()
    assert scheduler._running is True

    await scheduler.stop()
    assert scheduler._running is False


def test_event_bus_initialization():
    """Test event bus initialization."""
    event_bus = EventBus()

    assert event_bus is not None
    assert len(event_bus._subscribers) == 0


def test_event_bus_subscribe():
    """Test subscribing to events."""
    event_bus = EventBus()

    def handler(event):
        pass

    event_bus.subscribe("assessment_started", handler)

    assert "assessment_started" in event_bus._subscribers
    assert handler in event_bus._subscribers["assessment_started"]


def test_assessment_config():
    """Test assessment config dataclass."""
    config = AssessmentConfig(
        assessment_id="test-001",
        targets=["192.168.1.100"],
        scope_file="config/scope.yaml"
    )

    assert config.assessment_id == "test-001"
    assert len(config.targets) == 1
    assert config.intensity == "normal"


def test_assessment_state_initialization():
    """Test assessment state dataclass."""
    state = AssessmentState(assessment_id="test-001")

    assert state.assessment_id == "test-001"
    assert state.status == "initialized"


def test_assessment_state_to_dict():
    """Test assessment state serialization."""
    state = AssessmentState(assessment_id="test-001")

    data = state.to_dict()

    assert data["assessment_id"] == "test-001"
    assert data["status"] == "initialized"


def test_event_initialization():
    """Test event dataclass."""
    event = Event(
        event_type="test_event",
        data={"key": "value"}
    )

    assert event.event_type == "test_event"
    assert event.data["key"] == "value"
    assert event.timestamp is not None
