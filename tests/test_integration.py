"""
HAZARUS Integration Tests
Test core framework functionality.
"""

import pytest
import asyncio
from datetime import datetime, UTC


@pytest.mark.asyncio
async def test_event_bus():
    """Test event bus functionality."""
    from core.event_bus import EventBus

    bus = EventBus()
    events_received = []

    async def handler(event):
        events_received.append(event)

    bus.subscribe("test_event", handler)
    await bus.emit("test_event", {"test": "data"})

    assert len(events_received) == 1
    assert events_received[0].event_type == "test_event"


def test_state_manager():
    """Test state manager."""
    from core.state_manager import AssessmentState

    state = AssessmentState(assessment_id="test-assessment")
    assert state.assessment_id == "test-assessment"
    assert state.status == "initialized"

    state.update_status("running")
    assert state.status == "running"


def test_scope_validation():
    """Test scope validation."""
    from security.scope import ScopeManager, ScopeConfig

    config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        allowed_domains=["example.com"],
        allowed_cidrs=["192.168.1.0/24"]
    )

    assert "192.168.1.100" in config.allowed_targets
    assert "example.com" in config.allowed_domains


def test_privacy_report():
    """Test privacy report generation."""
    from anonymity.privacy_report import PrivacyReport

    report = PrivacyReport(assessment_id="test")
    report.anonsurf_installed = True
    report.anonsurf_running = True
    report.tor_available = True
    report.privacy_status = "pass"

    assert report.assessment_id == "test"
    assert report.privacy_status == "pass"


def test_exploit_engine():
    """Test exploit engine initialization."""
    from exploitation.exploit_engine import ExploitEngine

    engine = ExploitEngine()
    assert engine is not None
    assert len(engine._lab_ranges) > 0


def test_report_config():
    """Test report configuration."""
    from reporting.report_engine import ReportConfig

    config = ReportConfig(
        assessment_id="test-123",
        format="html"
    )

    assert config.assessment_id == "test-123"
    assert config.format == "html"
