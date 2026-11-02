"""
HAZARUS TLS Analysis
TLS/SSL configuration analysis.
"""

import asyncio
import logging
import ssl
import socket
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class TLSCertificate:
    """TLS certificate information."""
    subject: str
    issuer: str
    serial_number: str
    version: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    key_size: int
    extensions: List[str] = field(default_factory=list)


@dataclass
class TLSConfiguration:
    """TLS configuration analysis."""
    protocol_version: str
    cipher_suite: str
    certificate: Optional[TLSCertificate] = None
    has_hsts: bool = False
    has_ocsp_stapling: bool = False
    weak_protocols: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    grade: str = "F"  # A, B, C, D, F


@dataclass
class TLSAnalysisResult:
    """TLS analysis result."""
    target: str
    port: int
    configurations: List[TLSConfiguration] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: datetime = None

    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class TLSAnalysis:
    """TLS analysis module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.tls_analysis")

        # Weak protocols
        self.weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

        # Weak ciphers
        self.weak_ciphers = [
            "RC4", "DES", "3DES", "MD5", "SHA1", "NULL", "EXPORT", "anon"
        ]

    async def analyze(self, target: str, port: int = 443) -> TLSAnalysisResult:
        """Analyze TLS configuration."""
        self.logger.info(f"Analyzing TLS for {target}:{port}")

        result = TLSAnalysisResult(target=target, port=port)

        try:
            # Test TLS configuration
            config = await self._test_tls_configuration(target, port)
            result.configurations.append(config)

            # Analyze certificate
            if config.certificate:
                await self._analyze_certificate(config.certificate, result)

            # Check for vulnerabilities
            self._check_vulnerabilities(config, result)

            # Generate recommendations
            self._generate_recommendations(config, result)

            # Calculate grade
            config.grade = self._calculate_grade(config)

        except Exception as e:
            self.logger.error(f"TLS analysis failed: {e}")
            result.vulnerabilities.append(f"Analysis failed: {str(e)}")

        return result

    async def _test_tls_configuration(self, target: str, port: int) -> TLSConfiguration:
        """Test TLS configuration."""
        config = TLSConfiguration(protocol_version="unknown", cipher_suite="unknown")

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=context),
                timeout=self.timeout
            )

            # Get TLS info
            tls_object = writer.transport.get_extra_info("ssl_object")
            if tls_object:
                config.protocol_version = tls_object.version()
                config.cipher_suite = tls_object.cipher()[0] if tls_object.cipher() else "unknown"

                # Get certificate
                cert_der = tls_object.getpeercert(binary_form=True)
                if cert_der:
                    config.certificate = self._parse_certificate(cert_der)

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            self.logger.error(f"TLS connection failed: {e}")

        return config

    def _parse_certificate(self, cert_der: bytes) -> TLSCertificate:
        """Parse TLS certificate."""
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        extensions = []
        for ext in cert.extensions:
            extensions.append(ext.oid._name)

        return TLSCertificate(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=str(cert.serial_number),
            version=cert.version.name,
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            signature_algorithm=cert.signature_hash_algorithm.name,
            key_size=cert.public_key().key_size,
            extensions=extensions
        )

    async def _analyze_certificate(self, cert: TLSCertificate, result: TLSAnalysisResult) -> None:
        """Analyze certificate for issues."""
        now = datetime.utcnow()

        # Check expiration
        if cert.not_after < now:
            result.vulnerabilities.append("Certificate has expired")
        elif (cert.not_after - now).days < 30:
            result.vulnerabilities.append("Certificate expires soon")

        # Check key size
        if cert.key_size < 2048:
            result.vulnerabilities.append(f"Weak key size: {cert.key_size} bits")

        # Check for common extensions
        if "subjectAltName" not in cert.extensions:
            result.vulnerabilities.append("Missing subjectAltName extension")

    def _check_vulnerabilities(self, config: TLSConfiguration, result: TLSAnalysisResult) -> None:
        """Check for TLS vulnerabilities."""
        # Check for weak protocols
        for protocol in self.weak_protocols:
            if protocol in config.protocol_version:
                config.weak_protocols.append(protocol)
                result.vulnerabilities.append(f"Weak protocol: {protocol}")

        # Check for weak ciphers
        for weak in self.weak_ciphers:
            if weak.lower() in config.cipher_suite.lower():
                config.weak_ciphers.append(weak)
                result.vulnerabilities.append(f"Weak cipher: {weak}")

    def _generate_recommendations(self, config: TLSConfiguration, result: TLSAnalysisResult) -> None:
        """Generate security recommendations."""
        if config.weak_protocols:
            result.recommendations.append("Disable weak SSL/TLS protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)")

        if config.weak_ciphers:
            result.recommendations.append("Disable weak cipher suites")

        if config.certificate and config.certificate.key_size < 2048:
            result.recommendations.append("Use certificates with at least 2048-bit keys")

        if not config.has_hsts:
            result.recommendations.append("Enable HTTP Strict Transport Security (HSTS)")

        if not config.has_ocsp_stapling:
            result.recommendations.append("Enable OCSP stapling for certificate validation")

    def _calculate_grade(self, config: TLSConfiguration) -> str:
        """Calculate TLS configuration grade."""
        score = 100

        # Deduct for weak protocols
        score -= len(config.weak_protocols) * 20

        # Deduct for weak ciphers
        score -= len(config.weak_ciphers) * 10

        # Deduct for missing HSTS
        if not config.has_hsts:
            score -= 5

        # Deduct for missing OCSP stapling
        if not config.has_ocsp_stapling:
            score -= 5

        # Convert to letter grade
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def to_dict(self, result: TLSAnalysisResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "port": result.port,
            "configurations": [
                {
                    "protocol_version": c.protocol_version,
                    "cipher_suite": c.cipher_suite,
                    "certificate": {
                        "subject": c.certificate.subject if c.certificate else None,
                        "issuer": c.certificate.issuer if c.certificate else None,
                        "not_before": c.certificate.not_before.isoformat() if c.certificate else None,
                        "not_after": c.certificate.not_after.isoformat() if c.certificate else None,
                        "key_size": c.certificate.key_size if c.certificate else None,
                    } if c.certificate else None,
                    "grade": c.grade,
                    "weak_protocols": c.weak_protocols,
                    "weak_ciphers": c.weak_ciphers
                }
                for c in result.configurations
            ],
            "vulnerabilities": result.vulnerabilities,
            "recommendations": result.recommendations,
            "analyzed_at": result.analyzed_at.isoformat()
        }
