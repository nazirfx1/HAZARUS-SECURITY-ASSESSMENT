"""
HAZARUS Service Detection
Service detection and version identification.
"""

import asyncio
import logging
import socket
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ServiceInfo:
    """Service information."""
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0


@dataclass
class ServiceDetectionResult:
    """Service detection result."""
    target: str
    port: int
    services: List[ServiceInfo] = None
    detected_at: datetime = None

    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.detected_at is None:
            self.detected_at = datetime.utcnow()


class ServiceDetection:
    """Service detection module."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.service_detection")

        # Common service fingerprints
        self.service_fingerprints = {
            21: {"service": "FTP", "banner_pattern": "220"},
            22: {"service": "SSH", "banner_pattern": "SSH"},
            23: {"service": "Telnet", "banner_pattern": None},
            25: {"service": "SMTP", "banner_pattern": "220|ESMTP"},
            53: {"service": "DNS", "banner_pattern": None},
            80: {"service": "HTTP", "banner_pattern": "HTTP"},
            110: {"service": "POP3", "banner_pattern": "POP3"},
            143: {"service": "IMAP", "banner_pattern": "IMAP"},
            443: {"service": "HTTPS", "banner_pattern": "HTTP"},
            445: {"service": "SMB", "banner_pattern": None},
            3306: {"service": "MySQL", "banner_pattern": "mysql"},
            3389: {"service": "RDP", "banner_pattern": None},
            5432: {"service": "PostgreSQL", "banner_pattern": "postgre"},
            5900: {"service": "VNC", "banner_pattern": "RFB"},
            6379: {"service": "Redis", "banner_pattern": "redis"},
            8080: {"service": "HTTP-Alt", "banner_pattern": "HTTP"},
            8443: {"service": "HTTPS-Alt", "banner_pattern": "HTTP"},
            27017: {"service": "MongoDB", "banner_pattern": None},
        }

    async def detect(self, target: str, port: int) -> ServiceDetectionResult:
        """Detect service on target:port."""
        self.logger.info(f"Detecting service on {target}:{port}")

        result = ServiceDetectionResult(target=target, port=port)

        try:
            # Grab banner
            banner = await self._grab_banner(target, port)

            if banner:
                service_info = self._analyze_banner(banner, port)
                service_info.banner = banner
                result.services.append(service_info)

            # Port-based detection
            if port in self.service_fingerprints:
                port_info = self.service_fingerprints[port]
                service_info = ServiceInfo(
                    service=port_info["service"],
                    confidence=0.5
                )
                result.services.append(service_info)

            # Refine confidence
            if len(result.services) > 1:
                # If we have both banner and port-based info, increase confidence
                for service in result.services:
                    service.confidence = min(1.0, service.confidence + 0.3)

        except Exception as e:
            self.logger.error(f"Service detection failed: {e}")

        return result

    async def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab service banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )

            # Send a simple probe for some services
            if port in [80, 8080, 443, 8443]:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            elif port == 110:
                pass  # POP3 sends banner automatically
            elif port == 143:
                pass  # IMAP sends banner automatically

            await writer.drain()

            # Read banner
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.timeout
            )

            writer.close()
            await writer.wait_closed()

            return banner.decode(errors="ignore").strip()

        except Exception as e:
            self.logger.debug(f"Banner grab failed: {e}")
            return None

    def _analyze_banner(self, banner: str, port: int) -> ServiceInfo:
        """Analyze banner to identify service."""
        banner_lower = banner.lower()

        # SSH
        if "ssh" in banner_lower:
            version = banner_lower.split("ssh-")[-1].split()[0] if "ssh-" in banner_lower else None
            return ServiceInfo(service="SSH", version=version, confidence=0.9)

        # HTTP
        if "http" in banner_lower:
            version = banner_lower.split("/")[-1].split()[0] if "/" in banner_lower else None
            return ServiceInfo(service="HTTP", version=version, confidence=0.9)

        # FTP
        if "ftp" in banner_lower or "220" in banner:
            return ServiceInfo(service="FTP", confidence=0.8)

        # SMTP
        if "smtp" in banner_lower or "esmtp" in banner_lower:
            return ServiceInfo(service="SMTP", confidence=0.8)

        # MySQL
        if "mysql" in banner_lower:
            version = banner_lower.split()[-1] if banner_lower.split() else None
            return ServiceInfo(service="MySQL", version=version, confidence=0.9)

        # PostgreSQL
        if "postgre" in banner_lower:
            return ServiceInfo(service="PostgreSQL", confidence=0.9)

        # Redis
        if "redis" in banner_lower:
            version = banner_lower.split("=")[-1] if "=" in banner_lower else None
            return ServiceInfo(service="Redis", version=version, confidence=0.9)

        # Generic fallback
        return ServiceInfo(service="Unknown", confidence=0.3)

    async def detect_multiple(self, target: str, ports: List[int]) -> Dict[int, ServiceDetectionResult]:
        """Detect services on multiple ports."""
        self.logger.info(f"Detecting services on {len(ports)} ports for {target}")

        results = {}
        tasks = [self.detect(target, port) for port in ports]
        detected = await asyncio.gather(*tasks, return_exceptions=True)

        for port, result in zip(ports, detected):
            if isinstance(result, Exception):
                self.logger.error(f"Detection failed for port {port}: {result}")
            else:
                results[port] = result

        return results

    def to_dict(self, result: ServiceDetectionResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "port": result.port,
            "services": [
                {
                    "service": s.service,
                    "version": s.version,
                    "banner": s.banner,
                    "confidence": s.confidence
                }
                for s in result.services
            ],
            "detected_at": result.detected_at.isoformat()
        }
