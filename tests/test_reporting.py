"""
HAZARUS Reporting Module Tests
Tests for report generation and evidence management.
"""

import pytest
from reporting.report_engine import ReportEngine
from reporting.evidence_manager import EvidenceManager
from reporting.executive_summary import ExecutiveSummary
from reporting.html_report import HTMLReport
from reporting.json_report import JSONReport


def test_report_engine_initialization():
    """Test report engine initialization."""
    engine = ReportEngine()

    assert engine is not None
    assert engine.logger is not None


def test_evidence_manager_initialization():
    """Test evidence manager initialization."""
    manager = EvidenceManager(assessment_id="test-001")

    assert manager is not None
    assert manager.assessment_id == "test-001"


def test_executive_summary_initialization():
    """Test executive summary initialization."""
    summary = ExecutiveSummary()

    assert summary is not None


def test_html_report_initialization():
    """Test HTML report initialization."""
    report = HTMLReport()

    assert report is not None


def test_json_report_initialization():
    """Test JSON report initialization."""
    report = JSONReport()

    assert report is not None


def test_evidence_initialization():
    """Test evidence dataclass."""
    from reporting.evidence_manager import Evidence
    from datetime import datetime, UTC

    evidence = Evidence(
        evidence_id="ev-001",
        collected_at=datetime.now(UTC),
        type="screenshot",
        file_path="/tmp/screenshot.png",
        description="Test evidence"
    )

    assert evidence.evidence_id == "ev-001"
    assert evidence.type == "screenshot"
