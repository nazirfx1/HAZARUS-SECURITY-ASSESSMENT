"""
HAZARUS API Intelligence Sources
Integration with commercial and free APIs for enhanced reconnaissance.
"""

import asyncio
import logging
import httpx
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC
import os


@dataclass
class APIQueryResult:
    """Result from an API query."""
    source: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(UTC)


class APIIntelligence:
    """Integration with intelligence APIs."""

    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        """
        Initialize API intelligence.

        Args:
            api_keys: Dictionary of API keys (securitytrails, shodan, censys, virustotal, etc.)
        """
        self.logger = logging.getLogger("hazarus.api_intelligence")
        self.api_keys = api_keys or {}

        # Load from environment if not provided
        if not self.api_keys.get("securitytrails"):
            self.api_keys["securitytrails"] = os.environ.get("SECURITYTRAILS_API_KEY")
        if not self.api_keys.get("shodan"):
            self.api_keys["shodan"] = os.environ.get("SHODAN_API_KEY")
        if not self.api_keys.get("censys"):
            self.api_keys["censys"] = os.environ.get("CENSYS_API_KEY")
        if not self.api_keys.get("virustotal"):
            self.api_keys["virustotal"] = os.environ.get("VIRUSTOTAL_API_KEY")

    async def securitytrails_query(self, domain: str) -> APIQueryResult:
        """
        Query SecurityTrails API for historical DNS and subdomains.

        Args:
            domain: Target domain

        Returns:
            APIQueryResult with subdomains and historical data
        """
        result = APIQueryResult(source="securitytrails")
        start_time = asyncio.get_event_loop().time()

        try:
            api_key = self.api_keys.get("securitytrails")
            if not api_key:
                result.success = False
                result.error = "SecurityTrails API key not configured"
                self.logger.warning("SecurityTrails API key not available")
                return result

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Query subdomains
                response = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers={"apikey": api_key}
                )

                if response.status_code == 200:
                    data = response.json()
                    result.data = {
                        "subdomains": data.get("subdomains", []),
                        "record_count": data.get("record_count", 0)
                    }
                    result.success = True
                    self.logger.info(f"SecurityTrails: {len(result.data['subdomains'])} subdomains")
                else:
                    result.success = False
                    result.error = f"HTTP {response.status_code}: {response.text}"
                    self.logger.warning(f"SecurityTrails failed: {result.error}")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"SecurityTrails error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def shodan_query(self, ip: str) -> APIQueryResult:
        """
        Query Shodan API for host intelligence.

        Args:
            ip: Target IP address

        Returns:
            APIQueryResult with host information
        """
        result = APIQueryResult(source="shodan")
        start_time = asyncio.get_event_loop().time()

        try:
            api_key = self.api_keys.get("shodan")
            if not api_key:
                result.success = False
                result.error = "Shodan API key not configured"
                self.logger.warning("Shodan API key not available")
                return result

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                )

                if response.status_code == 200:
                    data = response.json()
                    result.data = {
                        "ip": data.get("ip_str"),
                        "hostnames": data.get("hostnames", []),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "os": data.get("os"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("asn")
                    }
                    result.success = True
                    self.logger.info(f"Shodan: {len(result.data['ports'])} ports, {len(result.data['vulns'])} vulns")
                else:
                    result.success = False
                    result.error = f"HTTP {response.status_code}: {response.text}"
                    self.logger.warning(f"Shodan failed: {result.error}")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"Shodan error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def censys_query(self, ip: str) -> APIQueryResult:
        """
        Query Censys API for certificate and infrastructure discovery.

        Args:
            ip: Target IP address

        Returns:
            APIQueryResult with infrastructure data
        """
        result = APIQueryResult(source="censys")
        start_time = asyncio.get_event_loop().time()

        try:
            api_key = self.api_keys.get("censys")
            if not api_key:
                result.success = False
                result.error = "Censys API key not configured"
                self.logger.warning("Censys API key not available")
                return result

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Censys API v2
                response = await client.get(
                    f"https://search.censys.io/api/v2/hosts/{ip}",
                    headers={"accept": "application/json", "Authorization": f"Bearer {api_key}"}
                )

                if response.status_code == 200:
                    data = response.json()
                    result.data = {
                        "ip": data.get("result", {}).get("ip"),
                        "services": data.get("result", {}).get("services", []),
                        "location": data.get("result", {}).get("location", {}),
                        "autonomous_system": data.get("result", {}).get("autonomous_system", {})
                    }
                    result.success = True
                    self.logger.info(f"Censys: {len(result.data['services'])} services")
                else:
                    result.success = False
                    result.error = f"HTTP {response.status_code}: {response.text}"
                    self.logger.warning(f"Censys failed: {result.error}")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"Censys error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def virustotal_query(self, domain: str) -> APIQueryResult:
        """
        Query VirusTotal API for domain reputation and relationships.

        Args:
            domain: Target domain

        Returns:
            APIQueryResult with reputation data
        """
        result = APIQueryResult(source="virustotal")
        start_time = asyncio.get_event_loop().time()

        try:
            api_key = self.api_keys.get("virustotal")
            if not api_key:
                result.success = False
                result.error = "VirusTotal API key not configured"
                self.logger.warning("VirusTotal API key not available")
                return result

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": api_key}
                )

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    result.data = {
                        "reputation": attributes.get("reputation"),
                        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                        "categories": attributes.get("categories", {}),
                        "whois": attributes.get("whois", ""),
                        "last_dns_records": attributes.get("last_dns_records", [])
                    }
                    result.success = True
                    self.logger.info(f"VirusTotal: reputation {result.data['reputation']}")
                else:
                    result.success = False
                    result.error = f"HTTP {response.status_code}: {response.text}"
                    self.logger.warning(f"VirusTotal failed: {result.error}")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"VirusTotal error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def wayback_machine_query(self, domain: str) -> APIQueryResult:
        """
        Query Wayback Machine for historical URLs and subdomains.

        Args:
            domain: Target domain

        Returns:
            APIQueryResult with historical data
        """
        result = APIQueryResult(source="wayback_machine")
        start_time = asyncio.get_event_loop().time()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Wayback Machine CDX API
                response = await client.get(
                    f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=url&collapse=urlkey"
                )

                if response.status_code == 200:
                    data = response.json()
                    if len(data) > 0:
                        # Skip header row
                        urls = [row[0] for row in data[1:]]

                        # Extract subdomains from URLs
                        subdomains = set()
                        for url in urls:
                            # Extract subdomain from URL
                            if f".{domain}" in url:
                                start = url.find("://") + 3
                                end = url.find("/", start)
                                if end == -1:
                                    end = len(url)
                                hostname = url[start:end]
                                if hostname.endswith(f".{domain}"):
                                    subdomain = hostname[:-(len(domain) + 1)]
                                    if subdomain:
                                        subdomains.add(subdomain)

                        result.data = {
                            "urls": urls[:100],  # Limit to 100 URLs
                            "subdomains": list(subdomains),
                            "total_urls": len(urls)
                        }
                        result.success = True
                        self.logger.info(f"Wayback Machine: {len(result.data['subdomains'])} subdomains")
                    else:
                        result.success = False
                        result.error = "No historical data found"
                else:
                    result.success = False
                    result.error = f"HTTP {response.status_code}"
                    self.logger.warning(f"Wayback Machine failed: {result.error}")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"Wayback Machine error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def query_all(
        self,
        target: str,
        target_type: str = "domain"
    ) -> Dict[str, APIQueryResult]:
        """
        Query all available APIs for the target.

        Args:
            target: Target (domain or IP)
            target_type: Type of target (domain or ip)

        Returns:
            Dictionary of API name -> APIQueryResult
        """
        results = {}
        self.logger.info(f"Querying all APIs for {target} ({target_type})")

        if target_type == "domain":
            # Domain-specific queries
            tasks = [
                self.securitytrails_query(target),
                self.virustotal_query(target),
                self.wayback_machine_query(target)
            ]
        else:
            # IP-specific queries
            tasks = [
                self.shodan_query(target),
                self.censys_query(target)
            ]

        # Run all queries in parallel
        api_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Map results back to API names
        if target_type == "domain":
            api_names = ["securitytrails", "virustotal", "wayback_machine"]
        else:
            api_names = ["shodan", "censys"]

        for name, result in zip(api_names, api_results):
            if isinstance(result, Exception):
                self.logger.error(f"{name} error: {result}")
                results[name] = APIQueryResult(
                    source=name,
                    success=False,
                    error=str(result)
                )
            else:
                results[name] = result

        successful = sum(1 for r in results.values() if r.success)
        self.logger.info(f"API queries complete: {successful}/{len(results)} successful")

        return results
