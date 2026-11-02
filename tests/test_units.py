"""
HAZARUS Unit Tests
Test individual modules.
"""

import pytest
from datetime import datetime


def test_cvss_calculation():
    """Test CVSS score calculation."""
    from vulnerability.cvss import CVSSCalculator

    calculator = CVSSCalculator()

    # Test critical vulnerability
    metrics = {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "C",
        "C": "H",
        "I": "H",
        "A": "H"
    }

    import asyncio
    score = asyncio.run(calculator.calculate(metrics))

    assert score.base_score >= 9.0
    assert score.severity == "Critical"


def test_dns_recon():
    """Test DNS reconnaissance initialization."""
    from reconnaissance.dns import DNSRecon

    recon = DNSRecon(timeout=5)
    assert recon is not None
    assert recon.timeout == 5


def test_nmap_scanner():
    """Test Nmap scanner initialization."""
    from scanning.nmap import NmapScanner

    scanner = NmapScanner()
    assert scanner is not None


def test_exploit_registry():
    """Test exploit registry."""
    from exploitation.exploit_registry import ExploitRegistry, ExploitMetadata
    from datetime import datetime

    registry = ExploitRegistry()

    exploit = ExploitMetadata(
        exploit_id="TEST-001",
        name="Test Exploit",
        description="A test exploit",
        author="HAZARUS",
        category="test",
        risk_level="low"
    )

    registry.register(exploit)

    retrieved = registry.get("TEST-001")
    assert retrieved is not None
    assert retrieved.name == "Test Exploit"


def test_privilege_audit():
    """Test privilege audit initialization."""
    from post_assessment.privilege_audit import PrivilegeAudit

    audit = PrivilegeAudit()
    assert audit is not None


def test_secret_analysis():
    """Test secret analysis initialization."""
    from code_analysis.secret_analysis import SecretAnalysis

    analyzer = SecretAnalysis()
    assert analyzer is not None
    assert len(analyzer.patterns) > 0
