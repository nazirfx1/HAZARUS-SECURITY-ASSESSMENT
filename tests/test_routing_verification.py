"""
HAZARUS Network Routing Verification Tests
Tests for evidence-based routing verification service.
"""

import pytest
from datetime import datetime, UTC
from anonymity.routing_verification import (
    RoutingMode,
    RoutingStatus,
    RoutingReport,
    RoutingVerificationService
)


def test_routing_mode_enum():
    """Test routing mode enumeration."""
    assert RoutingMode.NORMAL.value == "normal"
    assert RoutingMode.PROXY.value == "proxy"
    assert RoutingMode.TOR.value == "tor"


def test_routing_status_enum():
    """Test routing status enumeration."""
    assert RoutingStatus.VERIFIED.value == "verified"
    assert RoutingStatus.UNVERIFIED.value == "unverified"
    assert RoutingStatus.FAILED.value == "failed"
    assert RoutingStatus.BLOCKED.value == "blocked"


def test_routing_report_dataclass():
    """Test routing report dataclass."""
    report = RoutingReport(
        mode=RoutingMode.NORMAL,
        status=RoutingStatus.VERIFIED,
        anonsurf_installed=False,
        anonsurf_active=False,
        tor_connected=False,
        external_ip="192.168.1.1",
        dns_leaking=False,
        ipv6_enabled=False,
        proxy_configured=False,
        tool_compatibility={},
        timestamp=datetime.now(UTC),
        details={}
    )
    
    assert report.mode == RoutingMode.NORMAL
    assert report.status == RoutingStatus.VERIFIED
    assert report.anonsurf_installed == False


def test_routing_verification_service_initialization():
    """Test routing verification service initialization."""
    service = RoutingVerificationService()
    
    assert service is not None
    assert service.logger is not None
    assert service.anonsurf is not None
    assert service.tor_checker is not None


def test_evaluate_mode_normal():
    """Test evaluating normal routing mode."""
    service = RoutingVerificationService()
    
    # Normal mode with no DNS leak - should be verified
    status = service._evaluate_mode(
        RoutingMode.NORMAL,
        anonsurf_status={"installed": False, "active": False},
        tor_status={"connected": False},
        dns_status={"leaking": False},
        ipv6_status={"ipv6_enabled": False},
        proxy_status={"configured": False},
        tool_compatibility={}
    )
    
    assert status == RoutingStatus.VERIFIED


def test_evaluate_mode_normal_dns_leak():
    """Test normal mode with DNS leak - should be blocked."""
    service = RoutingVerificationService()
    
    status = service._evaluate_mode(
        RoutingMode.NORMAL,
        anonsurf_status={"installed": False, "active": False},
        tor_status={"connected": False},
        dns_status={"leaking": True},
        ipv6_status={"ipv6_enabled": False},
        proxy_status={"configured": False},
        tool_compatibility={}
    )
    
    assert status == RoutingStatus.BLOCKED


def test_evaluate_mode_proxy():
    """Test evaluating proxy routing mode."""
    service = RoutingVerificationService()
    
    # Proxy mode with proxy configured
    status = service._evaluate_mode(
        RoutingMode.PROXY,
        anonsurf_status={"installed": False, "active": False},
        tor_status={"connected": False},
        dns_status={"leaking": False},
        ipv6_status={"ipv6_enabled": False},
        proxy_status={"configured": True},
        tool_compatibility={"curl": True}
    )
    
    assert status == RoutingStatus.VERIFIED


def test_evaluate_mode_proxy_not_configured():
    """Test proxy mode without proxy - should be blocked."""
    service = RoutingVerificationService()
    
    status = service._evaluate_mode(
        RoutingMode.PROXY,
        anonsurf_status={"installed": False, "active": False},
        tor_status={"connected": False},
        dns_status={"leaking": False},
        ipv6_status={"ipv6_enabled": False},
        proxy_status={"configured": False},
        tool_compatibility={}
    )
    
    assert status == RoutingStatus.BLOCKED


def test_evaluate_mode_tor():
    """Test evaluating Tor routing mode."""
    service = RoutingVerificationService()
    
    # Tor mode with all requirements met
    status = service._evaluate_mode(
        RoutingMode.TOR,
        anonsurf_status={"installed": True, "active": True},
        tor_status={"connected": True},
        dns_status={"leaking": False},
        ipv6_status={"ipv6_enabled": False},
        proxy_status={"configured": False},
        tool_compatibility={}
    )
    
    assert status == RoutingStatus.VERIFIED


def test_evaluate_mode_tor_not_installed():
    """Test Tor mode without Anonsurf - should be blocked."""
    service = RoutingVerificationService()
    
    status = service._evaluate_mode(
        RoutingMode.TOR,
        anonsurf_status={"installed": False, "active": False},
        tor_status={"connected": False},
        dns_status={"leaking": False},
        ipv6_status={"ipv6_enabled": False},
        proxy_status={"configured": False},
        tool_compatibility={}
    )
    
    assert status == RoutingStatus.BLOCKED


def test_get_routing_recommendation_verified():
    """Test routing recommendation for verified status."""
    service = RoutingVerificationService()
    
    report = RoutingReport(
        mode=RoutingMode.NORMAL,
        status=RoutingStatus.VERIFIED,
        anonsurf_installed=False,
        anonsurf_active=False,
        tor_connected=False,
        external_ip=None,
        dns_leaking=False,
        ipv6_enabled=False,
        proxy_configured=False,
        tool_compatibility={},
        timestamp=datetime.now(UTC),
        details={}
    )
    
    recommendation = service.get_routing_recommendation(report)
    assert "verified" in recommendation.lower()


def test_get_routing_recommendation_blocked():
    """Test routing recommendation for blocked status."""
    service = RoutingVerificationService()
    
    report = RoutingReport(
        mode=RoutingMode.TOR,
        status=RoutingStatus.BLOCKED,
        anonsurf_installed=False,
        anonsurf_active=False,
        tor_connected=False,
        external_ip=None,
        dns_leaking=False,
        ipv6_enabled=False,
        proxy_configured=False,
        tool_compatibility={},
        timestamp=datetime.now(UTC),
        details={}
    )
    
    recommendation = service.get_routing_recommendation(report)
    assert "install" in recommendation.lower() or "cannot" in recommendation.lower()


def test_get_routing_recommendation_dns_leak():
    """Test routing recommendation for DNS leak."""
    service = RoutingVerificationService()
    
    report = RoutingReport(
        mode=RoutingMode.PROXY,
        status=RoutingStatus.FAILED,
        anonsurf_installed=False,
        anonsurf_active=False,
        tor_connected=False,
        external_ip=None,
        dns_leaking=True,
        ipv6_enabled=False,
        proxy_configured=True,
        tool_compatibility={},
        timestamp=datetime.now(UTC),
        details={}
    )
    
    recommendation = service.get_routing_recommendation(report)
    assert "dns" in recommendation.lower()


def test_get_env_var():
    """Test environment variable retrieval."""
    service = RoutingVerificationService()
    
    # Test non-existent variable
    result = service._get_env_var("NONEXISTENT_VAR_HAZARUS_TEST")
    assert result is None
    
    # Test setting and getting a variable
    import os
    os.environ["HAZARUS_TEST_VAR"] = "test_value"
    result = service._get_env_var("HAZARUS_TEST_VAR")
    assert result == "test_value"
    
    # Cleanup
    del os.environ["HAZARUS_TEST_VAR"]
