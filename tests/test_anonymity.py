"""
HAZARUS Anonymity Module Tests
Tests for privacy and anonymity verification components.
"""

import pytest
from anonymity.anonsurf import AnonsurfManager
from anonymity.tor_check import TorChecker
from anonymity.dns_leak import DNSLeakChecker
from anonymity.ipv6_check import IPv6Checker
from anonymity.proxy_validation import ProxyValidator
from anonymity.privacy_report import PrivacyReport


def test_anonsurf_manager_initialization():
    """Test Anonsurf manager initialization."""
    manager = AnonsurfManager()

    assert manager is not None
    assert manager.logger is not None


def test_tor_checker_initialization():
    """Test Tor checker initialization."""
    checker = TorChecker()

    assert checker is not None
    assert checker.logger is not None


def test_dns_leak_checker_initialization():
    """Test DNS leak checker initialization."""
    checker = DNSLeakChecker()

    assert checker is not None
    assert checker.logger is not None


def test_ipv6_checker_initialization():
    """Test IPv6 checker initialization."""
    checker = IPv6Checker()

    assert checker is not None
    assert checker.logger is not None


def test_proxy_validator_initialization():
    """Test proxy validator initialization."""
    validator = ProxyValidator()

    assert validator is not None
    assert validator.logger is not None


def test_privacy_report_initialization():
    """Test privacy report initialization."""
    report = PrivacyReport(assessment_id="test-001")

    assert report is not None
    assert report.assessment_id == "test-001"
