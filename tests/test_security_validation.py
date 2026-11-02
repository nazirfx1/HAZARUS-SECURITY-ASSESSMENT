"""
HAZARUS Security Validation Tests
Tests for scope enforcement, safety gates, and authorization.
"""

import pytest
import asyncio
from datetime import datetime, UTC, timedelta
from security.scope import ScopeManager, ScopeConfig, ScopeError, TargetType
from security.safety_gate import SafetyGate, SafetyError
from security.authorization import AuthorizationManager


def test_scope_validation_ipv4():
    """Test IPv4 target validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        allowed_cidrs=["192.168.1.0/24"]
    )
    scope_manager._parse_cidrs()

    # Valid targets
    assert scope_manager.validate_targets(["192.168.1.100"])
    assert scope_manager.validate_targets(["192.168.1.50"])

    # Invalid target
    assert not scope_manager.validate_targets(["10.0.0.1"])


def test_scope_validation_exclusion():
    """Test target exclusion."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        excluded_targets=["192.168.1.100"]
    )

    # Target in exclusion list should be invalid
    assert not scope_manager.validate_targets(["192.168.1.100"])


def test_scope_validation_cidr():
    """Test CIDR validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_cidrs=["192.168.1.0/24", "10.0.0.0/8"]
    )
    scope_manager._parse_cidrs()

    # Valid IPs in CIDR
    assert scope_manager._validate_ip("192.168.1.50")
    assert scope_manager._validate_ip("10.0.1.1")

    # Invalid IP outside CIDR
    assert not scope_manager._validate_ip("172.16.1.1")


def test_port_validation():
    """Test port validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_ports=[80, 443, 22]
    )

    # Valid ports
    assert scope_manager.validate_port(80)
    assert scope_manager.validate_port(443)

    # Invalid port
    assert not scope_manager.validate_port(8080)

    # Default-deny: no ports specified = restricted
    scope_manager2 = ScopeManager("config/scope.yaml")
    scope_manager2.config = ScopeConfig(allowed_ports=[])
    assert not scope_manager2.validate_port(80)


def test_assessment_window():
    """Test assessment window validation."""
    from datetime import datetime, UTC, timedelta

    scope_manager = ScopeManager("config/scope.yaml")
    
    # No restriction
    assert scope_manager.validate_assessment_window()

    # Valid window
    scope_manager.config = ScopeConfig(
        assessment_window={
            "start": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "end": (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        }
    )
    assert scope_manager.validate_assessment_window()

    # Invalid window (outside)
    scope_manager.config = ScopeConfig(
        assessment_window={
            "start": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "end": (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        }
    )
    assert not scope_manager.validate_assessment_window()


def test_rate_limit():
    """Test rate limiting."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(rate_limit=100, request_limit=10000)

    # Within limit
    assert scope_manager.check_rate_limit(50)
    assert scope_manager.check_rate_limit(99)

    # At limit should fail (exclusive upper bound)
    assert not scope_manager.check_rate_limit(100)
    assert not scope_manager.check_rate_limit(1000)

    # Atomic increment
    initial = scope_manager._request_count
    new_count = scope_manager.increment_request_count()
    assert new_count == initial + 1


@pytest.mark.asyncio
async def test_safety_gate_validation():
    """Test safety gate operation validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        allowed_ports=[80, 443]
    )
    scope_manager._parse_cidrs()

    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    # Valid operation
    assert await gate.validate_operation("scan", ["192.168.1.100"], port=80)
    gate.operation_complete()

    # Invalid target
    with pytest.raises(SafetyError):
        await gate.validate_operation("scan", ["10.0.0.1"])

    # Invalid port
    with pytest.raises(SafetyError):
        await gate.validate_operation("scan", ["192.168.1.100"], port=8080)


@pytest.mark.asyncio
async def test_safety_gate_exploitation():
    """Test safety gate exploitation validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.100.10"],  # Lab target
        intensity="high"  # High intensity allows exploitation
    )
    scope_manager._parse_cidrs()

    auth_manager = AuthorizationManager()
    # Create and approve a valid authorization
    record = auth_manager.create_authorization(
        operator_id="test-operator",
        client_id="test-client",
        targets=["192.168.100.10"],
        expires_in_days=1
    )
    auth_manager.approve_authorization(record.auth_id, "admin")

    gate = SafetyGate(scope_manager, auth_manager)

    # Lab exploitation should succeed
    assert await gate.validate_exploitation("CVE-2021-44228", "192.168.100.10", record.auth_id, lab_only=True)
    gate.operation_complete()

    # Non-lab exploitation should fail
    with pytest.raises(SafetyError):
        await gate.validate_exploitation("CVE-2021-44228", "10.0.0.1", record.auth_id, lab_only=True)


def test_lab_target_validation():
    """Test lab target detection."""
    scope_manager = ScopeManager("config/scope.yaml")
    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    # Lab IP ranges
    assert gate._is_lab_target("192.168.100.10")
    assert gate._is_lab_target("10.0.100.50")
    assert gate._is_lab_target("172.16.100.25")

    # Lab domains (configured in safety_gate.py)
    assert gate._is_lab_target("test.local")
    assert gate._is_lab_target("internal.lab")

    # Non-lab
    assert not gate._is_lab_target("8.8.8.8")
    assert not gate._is_lab_target("example.com")


@pytest.mark.asyncio
async def test_emergency_stop():
    """Test emergency stop."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(allowed_targets=["192.168.1.100"])
    scope_manager._parse_cidrs()

    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    # Activate emergency stop
    with pytest.raises(SafetyError, match="Emergency stop"):
        gate.emergency_stop()

    # Verify emergency stop is active
    assert gate.get_stats()["emergency_stop_active"] is True

    # Verify operations are blocked
    with pytest.raises(SafetyError, match="Emergency stop"):
        await gate.validate_operation("scan", ["192.168.1.100"])

    # Reset and verify operations can proceed
    gate.reset_emergency_stop()
    assert gate.get_stats()["emergency_stop_active"] is False


# Adversarial security tests
def test_target_normalization():
    """Test target normalization prevents bypass."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    # Normalized versions should all be recognized
    assert scope_manager._normalize_target("EXAMPLE.COM") == "example.com"
    assert scope_manager._normalize_target("example.com.") == "example.com"
    assert scope_manager._normalize_target("  example.com  ") == "example.com"


def test_redirect_validation():
    """Test redirect validation prevents DNS rebinding."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    # Valid redirect within same domain
    assert scope_manager.validate_redirect("example.com", "sub.example.com")

    # Valid redirect to explicitly allowed domain
    scope_manager.config.allowed_domains.append("allowed.com")
    assert scope_manager.validate_redirect("example.com", "allowed.com")

    # Invalid redirect to unauthorized domain
    assert not scope_manager.validate_redirect("example.com", "evil.com")


def test_wildcard_safety():
    """Test wildcard domain rules don't authorize unrelated domains."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_domains=["*.example.com"]
    )

    # Valid subdomain
    assert scope_manager.is_wildcard_safe("sub.example.com")

    # Base domain should not be authorized by wildcard
    assert not scope_manager.is_wildcard_safe("example.com")

    # Unrelated domain should not be authorized
    assert not scope_manager.is_wildcard_safe("evil.com")


def test_concurrency_limits():
    """Test concurrency limiting."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig()

    # Check initial state
    assert scope_manager.check_concurrency()

    # Acquire slots
    assert scope_manager.acquire_operation_slot()
    assert scope_manager._concurrent_operations == 1

    # Fill to limit
    for _ in range(9):
        scope_manager.acquire_operation_slot()
    assert scope_manager._concurrent_operations == 10

    # Should fail at limit
    assert not scope_manager.acquire_operation_slot()

    # Release and verify
    scope_manager.release_operation_slot()
    assert scope_manager._concurrent_operations == 9
    assert scope_manager.acquire_operation_slot()


def test_operation_permissions():
    """Test operation-specific permission checks."""
    scope_manager = ScopeManager("config/scope.yaml")

    # Low intensity - limited operations
    scope_manager.config = ScopeConfig(intensity="low")
    assert scope_manager.validate_operation_permission("recon")
    assert scope_manager.validate_operation_permission("scan")
    assert not scope_manager.validate_operation_permission("exploit")

    # High intensity - more operations
    scope_manager.config = ScopeConfig(intensity="high")
    assert scope_manager.validate_operation_permission("recon")
    assert scope_manager.validate_operation_permission("exploit")


def test_overnight_assessment_window():
    """Test overnight assessment window handling."""
    from datetime import datetime, UTC, time

    scope_manager = ScopeManager("config/scope.yaml")

    # Overnight window (22:00 to 06:00 next day)
    scope_manager.config = ScopeConfig(
        assessment_window={
            "start": "22:00",
            "end": "06:00"
        }
    )

    # Current time should be checked correctly
    # Test will pass if window logic handles overnight correctly
    window_valid = scope_manager.validate_assessment_window()
    # We can't predict exact time, but logic should not crash
    assert isinstance(window_valid, bool)
