"""
HAZARUS Origin IP Discovery
Find origin server IPs behind WAF/CDN protection.
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class OriginIPFinding:
    """Origin IP finding."""
    ip: str
    source: str
    confidence: str  # high, medium, low
    timestamp: datetime = None
    evidence: str = ""

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(UTC)


@dataclass
class OriginIPResult:
    """Origin IP discovery result."""
    target: str
    origin_ips: List[OriginIPFinding] = field(default_factory=list)
    historical_dns: List[str] = field(default_factory=list)
    subdomain_ips: Dict[str, List[str]] = field(default_factory=dict)
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


class OriginIPDiscovery:
    """Origin IP discovery module for WAF/CDN bypass."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.origin_ip")

    async def discover(self, target: str) -> OriginIPResult:
        """Discover origin IPs behind WAF/CDN."""
        self.logger.info(f"Discovering origin IPs for {target}")

        result = OriginIPResult(target=target)

        try:
            # Check historical DNS records
            await self._check_historical_dns(result)

            # Check certificate transparency for origin IPs
            await self._check_certificate_transparency(result)

            # Check subdomain IP variations
            await self._check_subdomain_ips(result)

            # Check DNS cache records
            await self._check_dns_cache(result)

            self.logger.info(f"Found {len(result.origin_ips)} potential origin IPs")

        except Exception as e:
            self.logger.error(f"Origin IP discovery failed: {e}")

        return result

    async def _check_historical_dns(self, result: OriginIPResult) -> None:
        """Check historical DNS records for origin IPs."""
        try:
            import subprocess

            # Use dig to check DNS records
            cmd = ["dig", "+short", result.target, "A", "+norecurse"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                ips = stdout.decode().strip().split("\n")
                for ip in ips:
                    if ip and self._is_valid_ip(ip):
                        result.historical_dns.append(ip)
                        result.origin_ips.append(OriginIPFinding(
                            ip=ip,
                            source="historical_dns",
                            confidence="medium",
                            evidence=f"DNS A record for {result.target}"
                        ))

            self.logger.info(f"Historical DNS: {len(result.historical_dns)} IPs")

        except Exception as e:
            self.logger.warning(f"Historical DNS check failed: {e}")

    async def _check_certificate_transparency(self, result: OriginIPResult) -> None:
        """Check certificate transparency logs for origin IPs."""
        try:
            import httpx

            # Query crt.sh for certificate details
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q={result.target}&output=json"
                )

                if response.status_code == 200:
                    import json
                    data = response.json()

                    # Extract IPs from certificate issuer info
                    for cert in data:
                        issuer = cert.get('issuer_name', '')
                        # Look for IP patterns in issuer info
                        ip_matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', issuer)
                        for ip in ip_matches:
                            if self._is_valid_ip(ip) and ip not in [f.ip for f in result.origin_ips]:
                                result.origin_ips.append(OriginIPFinding(
                                    ip=ip,
                                    source="certificate_transparency",
                                    confidence="low",
                                    evidence=f"Found in certificate issuer for {result.target}"
                                ))

            self.logger.info(f"Certificate transparency: {len(result.origin_ips)} potential IPs")

        except Exception as e:
            self.logger.warning(f"Certificate transparency check failed: {e}")

    async def _check_subdomain_ips(self, result: OriginIPResult) -> None:
        """Check subdomains for origin IPs that bypass WAF."""
        try:
            import subprocess

            # Common subdomains to check
            subdomains = [
                f"www.{result.target}",
                f"mail.{result.target}",
                f"ftp.{result.target}",
                f"direct.{result.target}",
                f"origin.{result.target}",
                f"real.{result.target}",
                f"dev.{result.target}",
                f"staging.{result.target}"
            ]

            for subdomain in subdomains:
                cmd = ["dig", "+short", subdomain, "A"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    ips = stdout.decode().strip().split("\n")
                    valid_ips = [ip for ip in ips if ip and self._is_valid_ip(ip)]
                    if valid_ips:
                        result.subdomain_ips[subdomain] = valid_ips
                        for ip in valid_ips:
                            if ip not in [f.ip for f in result.origin_ips]:
                                result.origin_ips.append(OriginIPFinding(
                                    ip=ip,
                                    source="subdomain_dns",
                                    confidence="medium",
                                    evidence=f"Subdomain {subdomain} resolves to {ip}"
                                ))

            self.logger.info(f"Subdomain IPs: {len(result.subdomain_ips)} subdomains with IPs")

        except Exception as e:
            self.logger.warning(f"Subdomain IP check failed: {e}")

    async def _check_dns_cache(self, result: OriginIPResult) -> None:
        """Check DNS cache services for historical IPs."""
        try:
            import httpx

            # Try Google DNS over HTTPS
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://dns.google/resolve?name={result.target}&type=A"
                )

                if response.status_code == 200:
                    data = response.json()
                    answers = data.get('Answer', [])

                    for answer in answers:
                        if answer.get('type') == 1:  # A record
                            ip = answer.get('data')
                            if ip and self._is_valid_ip(ip):
                                if ip not in [f.ip for f in result.origin_ips]:
                                    result.origin_ips.append(OriginIPFinding(
                                        ip=ip,
                                        source="google_doh",
                                        confidence="high",
                                        evidence=f"Google DNS A record for {result.target}"
                                    ))

            self.logger.info(f"DNS cache: {len(result.origin_ips)} total IPs")

        except Exception as e:
            self.logger.warning(f"DNS cache check failed: {e}")

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(pattern, ip):
            return False

        # Check each octet
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False

        return True
