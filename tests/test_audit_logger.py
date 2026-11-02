"""
HAZARUS Audit Logger Tests
Tests for audit logging functionality.
"""

import pytest
from datetime import datetime, UTC
from pathlib import Path
import tempfile
import shutil
import json

from security.audit_logger import AuditLogger, AuditEvent


@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for audit log tests."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_audit_logger_initialization(temp_log_dir):
    """Test audit logger initialization."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    assert logger.assessment_id == "test-001"
    assert logger.log_dir == temp_log_dir
    assert logger.log_dir.exists()
    assert logger._closed is False


@pytest.mark.asyncio
async def test_audit_logger_log_event(temp_log_dir):
    """Test logging a generic event."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_event(
        event_type="test_event",
        details={"key": "value"},
        severity="info",
        operator_id="operator@example.com"
    )

    # Check log file was created
    log_files = list(temp_log_dir.glob("*.jsonl"))
    assert len(log_files) == 1

    # Check log content
    with open(log_files[0], "r") as f:
        log_entry = json.loads(f.read())

    assert log_entry["event_type"] == "test_event"
    assert log_entry["assessment_id"] == "test-001"
    assert log_entry["operator_id"] == "operator@example.com"
    assert log_entry["details"]["key"] == "value"


@pytest.mark.asyncio
async def test_audit_logger_log_scope_change(temp_log_dir):
    """Test logging scope changes."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    old_scope = {"allowed_targets": ["192.168.1.100"]}
    new_scope = {"allowed_targets": ["192.168.1.100", "192.168.1.200"]}

    await logger.log_scope_change(
        old_scope=old_scope,
        new_scope=new_scope,
        operator_id="operator@example.com"
    )

    log_files = list(temp_log_dir.glob("*.jsonl"))
    with open(log_files[0], "r") as f:
        log_entry = json.loads(f.read())

    assert log_entry["event_type"] == "scope_change"
    assert log_entry["severity"] == "warning"
    assert log_entry["details"]["old_scope"] == old_scope
    assert log_entry["details"]["new_scope"] == new_scope


@pytest.mark.asyncio
async def test_audit_logger_log_exploitation(temp_log_dir):
    """Test logging exploitation attempts."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_exploitation(
        exploit_id="CVE-2021-44228",
        target="192.168.1.100",
        result="success",
        operator_id="operator@example.com"
    )

    log_files = list(temp_log_dir.glob("*.jsonl"))
    with open(log_files[0], "r") as f:
        log_entry = json.loads(f.read())

    assert log_entry["event_type"] == "exploitation"
    assert log_entry["severity"] == "critical"
    assert log_entry["details"]["exploit_id"] == "CVE-2021-44228"
    assert log_entry["details"]["target"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_audit_logger_log_privilege_escalation(temp_log_dir):
    """Test logging privilege escalation attempts."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_privilege_escalation(
        target="192.168.1.100",
        method="sudo exploitation",
        success=True,
        operator_id="operator@example.com"
    )

    log_files = list(temp_log_dir.glob("*.jsonl"))
    with open(log_files[0], "r") as f:
        log_entry = json.loads(f.read())

    assert log_entry["event_type"] == "privilege_escalation"
    assert log_entry["severity"] == "critical"
    assert log_entry["details"]["method"] == "sudo exploitation"
    assert log_entry["details"]["success"] is True


@pytest.mark.asyncio
async def test_audit_logger_log_data_access(temp_log_dir):
    """Test logging data access."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_data_access(
        target="192.168.1.100",
        data_type="user_records",
        count=100,
        operator_id="operator@example.com"
    )

    log_files = list(temp_log_dir.glob("*.jsonl"))
    with open(log_files[0], "r") as f:
        log_entry = json.loads(f.read())

    assert log_entry["event_type"] == "data_access"
    assert log_entry["severity"] == "warning"
    assert log_entry["details"]["data_type"] == "user_records"
    assert log_entry["details"]["count"] == 100


@pytest.mark.asyncio
async def test_audit_logger_log_emergency_stop(temp_log_dir):
    """Test logging emergency stop."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_emergency_stop(
        reason="Unauthorized access attempt",
        operator_id="operator@example.com"
    )

    log_files = list(temp_log_dir.glob("*.jsonl"))
    with open(log_files[0], "r") as f:
        log_entry = json.loads(f.read())

    assert log_entry["event_type"] == "emergency_stop"
    assert log_entry["severity"] == "critical"
    assert log_entry["details"]["reason"] == "Unauthorized access attempt"


@pytest.mark.asyncio
async def test_audit_logger_get_events(temp_log_dir):
    """Test retrieving logged events."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_event(event_type="event1", details={})
    await logger.log_event(event_type="event2", details={})
    await logger.log_event(event_type="event1", details={})

    # Get all events
    all_events = logger.get_events()
    assert len(all_events) == 3

    # Get filtered events
    event1_events = logger.get_events(event_type="event1")
    assert len(event1_events) == 2


@pytest.mark.asyncio
async def test_audit_logger_get_critical_events(temp_log_dir):
    """Test retrieving critical events."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_event(event_type="info", details={}, severity="info")
    await logger.log_event(event_type="critical", details={}, severity="critical")
    await logger.log_event(event_type="warning", details={}, severity="warning")

    critical_events = logger.get_critical_events()
    assert len(critical_events) == 1
    assert critical_events[0].event_type == "critical"


@pytest.mark.asyncio
async def test_audit_logger_get_events_by_operator(temp_log_dir):
    """Test retrieving events by operator."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_event(event_type="event1", details={}, operator_id="operator1@example.com")
    await logger.log_event(event_type="event2", details={}, operator_id="operator2@example.com")
    await logger.log_event(event_type="event3", details={}, operator_id="operator1@example.com")

    operator1_events = logger.get_events_by_operator("operator1@example.com")
    assert len(operator1_events) == 2


@pytest.mark.asyncio
async def test_audit_logger_finalize(temp_log_dir):
    """Test finalizing audit log."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.log_event(event_type="event1", details={})
    await logger.log_event(event_type="critical", details={}, severity="critical")

    await logger.finalize()

    # Check logger is closed
    assert logger._closed is True

    # Check summary file was created
    summary_files = list(temp_log_dir.glob("*_summary.json"))
    assert len(summary_files) == 1

    with open(summary_files[0], "r") as f:
        summary = json.load(f)

    assert summary["assessment_id"] == "test-001"
    assert summary["total_events"] == 2
    assert summary["critical_events"] == 1


@pytest.mark.asyncio
async def test_audit_logger_closed_logging(temp_log_dir):
    """Test that logging after finalize is prevented."""
    logger = AuditLogger(assessment_id="test-001", log_dir=temp_log_dir)

    await logger.finalize()

    # This should not add an event
    await logger.log_event(event_type="event1", details={})

    events = logger.get_events()
    assert len(events) == 0


def test_audit_event_to_dict():
    """Test AuditEvent serialization."""
    event = AuditEvent(
        event_type="test",
        details={"key": "value"},
        assessment_id="test-001",
        operator_id="operator@example.com",
        severity="info"
    )

    data = event.to_dict()

    assert data["event_type"] == "test"
    assert data["details"]["key"] == "value"
    assert data["assessment_id"] == "test-001"
    assert data["operator_id"] == "operator@example.com"
    assert data["severity"] == "info"
    assert "timestamp" in data
