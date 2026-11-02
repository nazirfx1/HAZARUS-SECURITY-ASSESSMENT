"""
HAZARUS Subdomain Discovery
Subdomain enumeration and discovery.
"""

import asyncio
import logging
import httpx
from typing import List, Optional, Set
from dataclasses import dataclass
from .dns import DNSRecon


@dataclass
class SubdomainResult:
    """Subdomain discovery result."""
    domain: str
    subdomains: Set[str] = None
    sources: dict = None

    def __post_init__(self):
        if self.subdomains is None:
            self.subdomains = set()
        if self.sources is None:
            self.sources = {}


class SubdomainDiscovery:
    """Subdomain discovery module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.subdomain_discovery")
        self.dns_recon = DNSRecon(timeout=timeout)

    async def discover(self, domain: str) -> SubdomainResult:
        """Discover subdomains for a domain using multiple methods."""
        self.logger.info(f"Discovering subdomains for {domain}")

        result = SubdomainResult(domain=domain)

        # Method 1: Certificate Transparency
        ct_subdomains = await self._from_certificate_transparency(domain)
        for sub in ct_subdomains:
            result.subdomains.add(sub)
        result.sources["certificate_transparency"] = len(ct_subdomains)

        # Method 2: DNS Brute Force
        brute_subdomains = await self.dns_recon.subdomain_bruteforce(domain)
        for sub in brute_subdomains:
            result.subdomains.add(sub)
        result.sources["brute_force"] = len(brute_subdomains)

        # Method 3: Wordlist expansion
        wordlist_subdomains = await self._wordlist_expansion(domain)
        for sub in wordlist_subdomains:
            result.subdomains.add(sub)
        result.sources["wordlist"] = len(wordlist_subdomains)

        self.logger.info(f"Discovered {len(result.subdomains)} subdomains for {domain}")
        return result

    async def _from_certificate_transparency(self, domain: str) -> List[str]:
        """Query Certificate Transparency logs for subdomains."""
        subdomains = []

        try:
            import urllib.parse
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Use crt.sh API with proper URL encoding
                query = f"%.{domain}"
                encoded_query = urllib.parse.quote(query)
                url = f"https://crt.sh/?q={encoded_query}&output=json"
                response = await client.get(url)

                if response.status_code == 200:
                    data = response.json()
                    seen = set()

                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # Handle wildcard certificates
                        if "*" in name_value:
                            continue

                        # Extract subdomain
                        if name_value.endswith(domain):
                            subdomains.append(name_value)
                            seen.add(name_value)

                    subdomains = list(seen)
                    self.logger.debug(f"Found {len(subdomains)} subdomains from CT logs")
                else:
                    self.logger.warning(f"crt.sh returned status {response.status_code}")

        except Exception as e:
            self.logger.error(f"Certificate Transparency query failed: {e}")

        return subdomains

    async def _wordlist_expansion(self, domain: str) -> List[str]:
        """Extended wordlist-based subdomain discovery."""
        extended_wordlist = [
            'api', 'app', 'apps', 'admin', 'administrator', 'auth', 'beta',
            'blog', 'cache', 'cdn', 'cloud', 'console', 'crm', 'dashboard',
            'db', 'dev', 'development', 'docs', 'email', 'en', 'ftp',
            'git', 'grafana', 'help', 'home', 'img', 'images', 'internal',
            'jenkins', 'kibana', 'login', 'mail', 'mobile', 'monitor',
            'ns1', 'ns2', 'portal', 'pre', 'preview', 'prod', 'production',
            'public', 'qa', 'sandbox', 'secure', 'server', 'shop', 'sso',
            'stage', 'staging', 'static', 'stats', 'status', 'store',
            'support', 'test', 'testing', 'ticket', 'tools', 'uat',
            'vpn', 'web', 'webmail', 'www', 'www1', 'www2', 'www3'
        ]

        found = []
        for sub in extended_wordlist:
            full_domain = f"{sub}.{domain}"
            try:
                await self.dns_recon._query_records(full_domain, 'A')
                found.append(full_domain)
            except Exception:
                pass

        return found

    async def verify_subdomains(self, subdomains: List[str]) -> List[str]:
        """Verify that subdomains resolve."""
        verified = []

        for subdomain in subdomains:
            try:
                await self.dns_recon._query_records(subdomain, 'A')
                verified.append(subdomain)
            except Exception:
                pass

        self.logger.info(f"Verified {len(verified)}/{len(subdomains)} subdomains")
        return verified

    def to_dict(self, result: SubdomainResult) -> dict:
        """Convert SubdomainResult to dictionary."""
        return {
            "domain": result.domain,
            "subdomains": list(result.subdomains),
            "count": len(result.subdomains),
            "sources": result.sources
        }
