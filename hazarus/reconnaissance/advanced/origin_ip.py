"""
HAZARUS Enhanced Origin IP Discovery
Censys, Shodan, SSL analysis, HTTP headers, ASN, and BGP route analysis.
"""

import asyncio
import logging
import httpx
import subprocess
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class ASNInfo:
    """ASN information."""
    asn: str
    org: str
    country: str
    prefix: str


@dataclass
class EnhancedOriginIPFinding:
    """Enhanced origin IP finding."""
    ip: str
    source: str
    confidence: str
    asn_info: Optional[ASNInfo] = None
    port_scan: List[int] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


@dataclass
class EnhancedOriginIPResult:
    """Enhanced origin IP discovery result."""
    target: str
    origin_ips: List[EnhancedOriginIPFinding] = field(default_factory=list)
    cloudflare_bypassed: bool = False
    total_ips: int = 0
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


class EnhancedOriginIPDiscovery:
    """Enhanced origin IP discovery capabilities."""

    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        """
        Initialize enhanced origin IP discovery.

        Args:
            api_keys: Dictionary of API keys (shodan, censys)
        """
        self.logger = logging.getLogger("hazarus.enhanced_origin_ip")
        self.api_keys = api_keys or {}

    async def ssl_certificate_analysis(self, domain: str) -> List[str]:
        """
        Analyze SSL certificates for origin IPs.

        Args:
            domain: Target domain

        Returns:
            List of potential origin IPs from certificates
        """
        ips = []

        try:
            # Use openssl to get certificate
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", f"{domain}:443",
                "-servername", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=30
            )

            if proc.returncode == 0:
                output = stdout.decode()
                # Parse certificate for IPs
                import re
                ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                ips = re.findall(ip_pattern, output)

                self.logger.info(f"SSL analysis: {len(ips)} IPs found in certificate")

        except Exception as e:
            self.logger.warning(f"SSL certificate analysis failed: {e}")

        return ips

    async def http_header_analysis(self, url: str) -> List[str]:
        """
        Analyze HTTP headers for origin hints.

        Args:
            url: Target URL

        Returns:
            List of potential origin IPs from headers
        """
        ips = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)

                # Check headers for origin hints
                headers_str = str(response.headers).lower()

                # Look for IPs in headers
                import re
                ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                ips = re.findall(ip_pattern, headers_str)

                # Check for Cloudflare-specific headers
                if "cf-ray" in headers_str:
                    self.logger.debug("Cloudflare detected in headers")

                self.logger.info(f"HTTP header analysis: {len(ips)} IPs found")

        except Exception as e:
            self.logger.warning(f"HTTP header analysis failed: {e}")

        return ips

    async def asn_discovery(self, ip: str) -> Optional[ASNInfo]:
        """
        Discover ASN information for IP.

        Args:
            ip: IP address

        Returns:
            ASNInfo object or None
        """
        try:
            # Use whois for ASN info
            proc = await asyncio.create_subprocess_exec(
                "whois", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=30
            )

            if proc.returncode == 0:
                output = stdout.decode()
                import re

                # Parse ASN info
                asn_match = re.search(r'OriginAS:\s*AS(\d+)', output)
                org_match = re.search(r'OrgName:\s*(.+)', output)
                country_match = re.search(r'Country:\s*(\w{2})', output)

                if asn_match:
                    return ASNInfo(
                        asn=asn_match.group(1),
                        org=org_match.group(1) if org_match else "Unknown",
                        country=country_match.group(1) if country_match else "Unknown",
                        prefix=""
                    )

        except Exception as e:
            self.logger.warning(f"ASN discovery failed: {e}")

        return None

    async def bgp_route_analysis(self, ip: str) -> List[str]:
        """
        Analyze BGP routes for origin detection.

        Args:
            ip: IP address

        Returns:
            List of ASNs in BGP path
        """
        asns = []

        try:
            # Use bgphe.net or similar
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(f"https://bgp.he.net/ip/{ip}")

                if response.status_code == 200:
                    import re
                    asn_pattern = r'AS(\d+)'
                    asns = re.findall(asn_pattern, response.text)

                    self.logger.info(f"BGP analysis: {len(asns)} ASNs found")

        except Exception as e:
            self.logger.warning(f"BGP route analysis failed: {e}")

        return asns

    async def censys_infrastructure(self, domain: str) -> List[str]:
        """
        Use Censys to discover infrastructure.

        Args:
            domain: Target domain

        Returns:
            List of discovered IPs
        """
        ips = []

        try:
            api_key = self.api_keys.get("censys")
            if not api_key:
                self.logger.warning("Censys API key not available")
                return ips

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://search.censys.io/api/v2/certificates?q={domain}",
                    headers={"Authorization": f"Bearer {api_key}"}
                )

                if response.status_code == 200:
                    data = response.json()
                    # Parse results for IPs
                    # (Simplified - full parsing would require more work)
                    self.logger.info("Censys infrastructure queried")

        except Exception as e:
            self.logger.warning(f"Censys infrastructure failed: {e}")

        return ips

    async def shodan_infrastructure(self, domain: str) -> List[str]:
        """
        Use Shodan to discover infrastructure.

        Args:
            domain: Target domain

        Returns:
            List of discovered IPs
        """
        ips = []

        try:
            api_key = self.api_keys.get("shodan")
            if not api_key:
                self.logger.warning("Shodan API key not available")
                return ips

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/search?query=hostname:{domain}&key={api_key}"
                )

                if response.status_code == 200:
                    data = response.json()
                    for match in data.get("matches", []):
                        ip = match.get("ip_str")
                        if ip:
                            ips.append(ip)

                    self.logger.info(f"Shodan infrastructure: {len(ips)} IPs found")

        except Exception as e:
            self.logger.warning(f"Shodan infrastructure failed: {e}")

        return ips

    async def discover_enhanced(
        self,
        target: str,
        methods: List[str] = None
    ) -> EnhancedOriginIPResult:
        """
        Run enhanced origin IP discovery with multiple methods.

        Args:
            target: Target domain
            methods: List of methods (ssl, http, asn, bgp, censys, shodan)

        Returns:
            EnhancedOriginIPResult with all findings
        """
        if methods is None:
            methods = ["ssl", "http", "asn"]

        result = EnhancedOriginIPResult(target=target)
        self.logger.info(f"Enhanced origin IP discovery for {target}")

        all_ips = set()

        # SSL certificate analysis
        if "ssl" in methods:
            ssl_ips = await self.ssl_certificate_analysis(target)
            all_ips.update(ssl_ips)
            for ip in ssl_ips:
                result.origin_ips.append(EnhancedOriginIPFinding(
                    ip=ip,
                    source="ssl_certificate",
                    confidence="medium",
                    evidence="Found in SSL certificate"
                ))

        # HTTP header analysis
        if "http" in methods:
            url = f"https://{target}"
            http_ips = await self.http_header_analysis(url)
            all_ips.update(http_ips)
            for ip in http_ips:
                result.origin_ips.append(EnhancedOriginIPFinding(
                    ip=ip,
                    source="http_headers",
                    confidence="low",
                    evidence="Found in HTTP headers"
                ))

        # ASN discovery for each IP
        if "asn" in methods:
            for ip in list(all_ips)[:10]:  # Limit to 10 IPs
                asn_info = await self.asn_discovery(ip)
                for finding in result.origin_ips:
                    if finding.ip == ip:
                        finding.asn_info = asn_info

        # BGP route analysis
        if "bgp" in methods:
            for ip in list(all_ips)[:5]:  # Limit to 5 IPs
                bgp_asns = await self.bgp_route_analysis(ip)
                if bgp_asns:
                    self.logger.debug(f"BGP path for {ip}: {bgp_asns}")

        # Censys infrastructure
        if "censys" in methods:
            censys_ips = await self.censys_infrastructure(target)
            all_ips.update(censys_ips)
            for ip in censys_ips:
                result.origin_ips.append(EnhancedOriginIPFinding(
                    ip=ip,
                    source="censys",
                    confidence="high",
                    evidence="Discovered via Censys"
                ))

        # Shodan infrastructure
        if "shodan" in methods:
            shodan_ips = await self.shodan_infrastructure(target)
            all_ips.update(shodan_ips)
            for ip in shodan_ips:
                result.origin_ips.append(EnhancedOriginIPFinding(
                    ip=ip,
                    source="shodan",
                    confidence="high",
                    evidence="Discovered via Shodan"
                ))

        result.total_ips = len(all_ips)
        result.cloudflare_bypassed = len(all_ips) > 0

        self.logger.info(
            f"Enhanced origin IP discovery complete: "
            f"{result.total_ips} potential origin IPs found"
        )

        return result
