"""
HAZARUS Advanced DNS Features
DNS over HTTPS, DNS over TLS, NSEC walk, and advanced DNS capabilities.
"""

import asyncio
import logging
import httpx
import dns.resolver
import dns.query
import dns.message
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class DNSRecord:
    """DNS record."""
    record_type: str
    name: str
    value: str
    ttl: int


@dataclass
class DoHResult:
    """DNS over HTTPS result."""
    provider: str
    records: List[DNSRecord] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class NSECWalkResult:
    """NSEC/NSEC3 zone walk result."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    walk_type: str = "NSEC"  # NSEC or NSEC3
    success: bool = True
    error: Optional[str] = None


class AdvancedDNS:
    """Advanced DNS capabilities."""

    # DoH providers
    DOH_PROVIDERS = {
        "google": "https://dns.google/resolve",
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "quad9": "https://dns.quad9.net/dns-query"
    }

    def __init__(self):
        self.logger = logging.getLogger("hazarus.advanced_dns")

    async def query_doh(
        self,
        domain: str,
        record_type: str = "A",
        provider: str = "google"
    ) -> DoHResult:
        """
        Query DNS over HTTPS.

        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            provider: DoH provider (google, cloudflare, quad9)

        Returns:
            DoHResult with DNS records
        """
        result = DoHResult(provider=provider)
        start_time = asyncio.get_event_loop().time()

        try:
            provider_url = self.DOH_PROVIDERS.get(provider)
            if not provider_url:
                result.success = False
                result.error = f"Unknown provider: {provider}"
                return result

            # Record type mapping
            type_map = {
                "A": 1, "AAAA": 28, "MX": 15, "TXT": 16,
                "NS": 2, "CNAME": 5, "SOA": 6, "SRV": 33
            }
            qtype = type_map.get(record_type.upper(), 1)

            async with httpx.AsyncClient(timeout=30.0) as client:
                params = {
                    "name": domain,
                    "type": qtype
                }

                if provider == "cloudflare":
                    # Cloudflare uses different parameter names
                    params = {
                        "name": domain,
                        "type": record_type.upper()
                    }

                response = await client.get(provider_url, params=params)

                if response.status_code == 200:
                    data = response.json()

                    # Parse response based on provider
                    if provider == "google":
                        answers = data.get("Answer", [])
                    else:
                        answers = data.get("Answer", [])

                    for answer in answers:
                        if answer.get("type") == qtype:
                            result.records.append(DNSRecord(
                                record_type=record_type,
                                name=answer.get("name", domain),
                                value=answer.get("data", ""),
                                ttl=answer.get("TTL", 0)
                            ))

                    self.logger.info(f"DoH ({provider}): {len(result.records)} {record_type} records")
                else:
                    result.success = False
                    result.error = f"HTTP {response.status_code}"

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"DoH error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def query_dot(
        self,
        domain: str,
        record_type: str = "A",
        server: str = "1.1.1.1"
    ) -> DoHResult:
        """
        Query DNS over TLS.

        Args:
            domain: Domain to query
            record_type: DNS record type
            server: DNS server address

        Returns:
            DoHResult with DNS records
        """
        result = DoHResult(provider=f"DOT-{server}")
        start_time = asyncio.get_event_loop().time()

        try:
            # Use dnspython with DoT
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.nameserver_ports = {server: 853}  # DoT port

            # Set DoT flag
            resolver.use_tls = True

            answers = resolver.resolve(domain, record_type)

            for answer in answers:
                result.records.append(DNSRecord(
                    record_type=record_type,
                    name=answer.name.to_text(),
                    value=str(answer),
                    ttl=answer.ttl
                ))

            self.logger.info(f"DoT ({server}): {len(result.records)} {record_type} records")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"DoT error: {e}")

        result.duration = asyncio.get_event_loop().time() - start_time
        return result

    async def nsec_walk(self, domain: str) -> NSECWalkResult:
        """
        Perform NSEC/NSEC3 zone walk for DNSSEC-signed zones.

        Args:
            domain: Domain to walk

        Returns:
            NSECWalkResult with discovered subdomains
        """
        result = NSECWalkResult(domain=domain)
        self.logger.info(f"Attempting NSEC walk for {domain}")

        try:
            resolver = dns.resolver.Resolver()

            # Check if zone is DNSSEC signed
            try:
                dnskey = resolver.resolve(domain, "DNSKEY")
                if not dnskey:
                    result.success = False
                    result.error = "Zone not DNSSEC signed"
                    return result
            except:
                result.success = False
                result.error = "Zone not DNSSEC signed"
                return result

            # Perform NSEC walk
            subdomains = set()
            current_name = domain

            while True:
                try:
                    # Query NSEC records
                    nsec = resolver.resolve(current_name, "NSEC")
                    for rr in nsec:
                        # Extract next domain name from NSEC record
                        next_name = rr.to_text().split()[1]
                        if next_name.endswith(f".{domain}."):
                            subdomain = next_name[:-(len(domain) + 2)]
                            if subdomain and subdomain != "@":
                                subdomains.add(subdomain)
                            current_name = next_name
                        else:
                            # End of zone
                            break
                except:
                    break

            result.subdomains = list(subdomains)
            result.walk_type = "NSEC"
            self.logger.info(f"NSEC walk: {len(result.subdomains)} subdomains found")

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"NSEC walk error: {e}")

        return result

    async def cache_snoop(
        self,
        nameserver: str,
        domains: List[str]
    ) -> Dict[str, bool]:
        """
        DNS cache snooping to discover recently queried domains.

        Args:
            nameserver: Nameserver to snoop
            domains: List of domains to check

        Returns:
            Dictionary of domain -> cached (True/False)
        """
        results = {}
        self.logger.info(f"Cache snooping {len(domains)} domains on {nameserver}")

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [nameserver]

            for domain in domains:
                try:
                    # Query with recursion disabled
                    answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
                    results[domain] = len(answer) > 0
                except:
                    results[domain] = False

        except Exception as e:
            self.logger.error(f"Cache snooping error: {e}")

        return results
