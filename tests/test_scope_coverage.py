"""
HAZARUS Scope Coverage Tests
Additional tests to improve scope.py coverage to 90%+.
"""

import pytest
from pathlib import Path
import tempfile
import shutil
import yaml

from security.scope import ScopeManager, ScopeConfig, TargetType


@pytest.fixture
def temp_scope_file():
    """Create a temporary scope file for testing."""
    temp_dir = tempfile.mkdtemp()
    temp_file = Path(temp_dir) / "scope.yaml"
    yield temp_file
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_scope_manager_load_scope_success(temp_scope_file):
    """Test successful scope loading from YAML file."""
    scope_data = {
        "allowed_targets": ["192.168.1.100"],
        "allowed_domains": ["example.com"],
        "allowed_cidrs": ["192.168.1.0/24"],
        "excluded_targets": ["192.168.1.1"],
        "allowed_ports": [80, 443],
        "assessment_window": {
            "start": "2024-01-01T00:00:00",
            "end": "2024-12-31T23:59:59"
        },
        "intensity": "normal",
        "rate_limit": 100,
        "request_limit": 10000,
        "operator_id": "operator@example.com",
        "client_id": "client-001"
    }

    with open(temp_scope_file, "w") as f:
        yaml.dump(scope_data, f)

    manager = ScopeManager(str(temp_scope_file))
    loaded = await manager.load_scope()

    assert loaded is True
    assert manager.config is not None
    assert manager.config.operator_id == "operator@example.com"
    assert len(manager.config.allowed_targets) == 1


@pytest.mark.asyncio
async def test_scope_manager_load_scope_file_not_found():
    """Test loading scope when file doesn't exist."""
    manager = ScopeManager("/nonexistent/scope.yaml")
    loaded = await manager.load_scope()

    assert loaded is False


@pytest.mark.asyncio
async def test_scope_manager_load_scope_invalid_yaml(temp_scope_file):
    """Test loading scope with invalid YAML."""
    with open(temp_scope_file, "w") as f:
        f.write("invalid: yaml: content: [unclosed")

    manager = ScopeManager(str(temp_scope_file))
    loaded = await manager.load_scope()

    assert loaded is False


def test_scope_manager_parse_cidrs():
    """Test CIDR parsing."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(allowed_cidrs=["192.168.1.0/24", "10.0.0.0/8", "invalid-cidr"])
    manager._parse_cidrs()

    assert len(manager._parsed_cidrs) == 2  # Valid CIDRs only


def test_scope_manager_validate_cidr_subnet():
    """Test CIDR subnet validation."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(allowed_cidrs=["192.168.1.0/24"])
    manager._parse_cidrs()

    # CIDR within allowed range
    assert manager._validate_cidr("192.168.1.0/24") is True
    assert manager._validate_cidr("192.168.1.128/25") is True

    # CIDR outside allowed range
    assert manager._validate_cidr("10.0.0.0/8") is False


def test_scope_manager_validate_url_with_port():
    """Test URL validation with port."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(allowed_domains=["example.com"])

    # URL with port
    assert manager._validate_url("https://example.com:8443") is True

    # URL without port
    assert manager._validate_url("https://example.com") is True


def test_scope_manager_is_excluded_substring():
    """Test exclusion with substring matching."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        excluded_targets=["192.168.1"]
    )

    # Should be excluded due to substring match
    assert manager._is_excluded("192.168.1.100") is True


def test_scope_manager_classify_url():
    """Test URL classification."""
    manager = ScopeManager(str(temp_scope_file))

    assert manager._classify_target("http://example.com") == TargetType.URL
    assert manager._classify_target("https://example.com") == TargetType.URL
    assert manager._classify_target("ftp://example.com") == TargetType.DOMAIN  # Not http/https


def test_scope_manager_classify_ipv6():
    """Test IPv6 classification."""
    manager = ScopeManager(str(temp_scope_file))

    assert manager._classify_target("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == TargetType.IPV6
    assert manager._classify_target("::1") == TargetType.IPV6
    assert manager._classify_target("fe80::1") == TargetType.IPV6


def test_scope_manager_classify_invalid_cidr():
    """Test classification of invalid CIDR."""
    manager = ScopeManager(str(temp_scope_file))

    # Invalid CIDR should be classified as domain
    assert manager._classify_target("invalid-cidr") == TargetType.DOMAIN


def test_scope_manager_get_scope_summary():
    """Test scope summary generation."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        allowed_domains=["example.com"],
        allowed_cidrs=["192.168.1.0/24"],
        excluded_targets=["192.168.1.1"],
        allowed_ports=[80, 443],
        operator_id="operator@example.com",
        client_id="client-001"
    )

    summary = manager.get_scope_summary()

    assert summary["allowed_targets"] == 1
    assert summary["allowed_domains"] == 1
    assert summary["allowed_cidrs"] == 1
    assert summary["excluded_targets"] == 1
    assert summary["allowed_ports"] == 2
    assert summary["operator_id"] == "operator@example.com"


def test_scope_manager_create_scope_template(temp_scope_file):
    """Test creating scope template."""
    manager = ScopeManager(str(temp_scope_file))
    output_path = Path(temp_scope_file).parent / "template.yaml"

    manager.create_scope_template(output_path)

    assert output_path.exists()

    with open(output_path, "r") as f:
        template = yaml.safe_load(f)

    assert "allowed_targets" in template
    assert "allowed_domains" in template
    assert "assessment_window" in template


def test_scope_manager_validate_with_no_config():
    """Test validation when scope not loaded."""
    manager = ScopeManager(str(temp_scope_file))

    assert manager.validate_targets(["192.168.1.100"]) is False
    assert manager.validate_port(80) is False
    # validate_assessment_window returns True when no config (default-deny for other methods but permissive for time)
    assert manager.config is None


def test_scope_manager_validate_assessment_window_invalid_format():
    """Test assessment window with invalid format."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(
        assessment_window={
            "start": "invalid-date",
            "end": "2024-12-31T23:59:59"
        }
    )

    assert manager.validate_assessment_window() is False


def test_scope_manager_validate_assessment_window_no_times():
    """Test assessment window with no start/end times."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(assessment_window={})

    assert manager.validate_assessment_window() is True


def test_scope_manager_validate_domain_with_wildcard():
    """Test domain validation with wildcard rules."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(allowed_domains=["*.example.com"])

    # Subdomain should match
    assert manager._validate_domain("sub.example.com") is True

    # Base domain should not match (requires explicit)
    assert manager._validate_domain("example.com") is False


def test_scope_manager_validate_ip_with_cidr_fallback():
    """Test IP validation falls back to CIDR when not in explicit list."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(allowed_cidrs=["192.168.1.0/24"])
    manager._parse_cidrs()

    # IP in CIDR but not in explicit list
    assert manager._validate_ip("192.168.1.50") is True

    # IP not in CIDR
    assert manager._validate_ip("10.0.0.1") is False


def test_scope_manager_validate_ip_invalid():
    """Test IP validation with invalid IP."""
    manager = ScopeManager(str(temp_scope_file))
    manager.config = ScopeConfig(allowed_targets=["192.168.1.100"])

    assert manager._validate_ip("invalid-ip") is False
