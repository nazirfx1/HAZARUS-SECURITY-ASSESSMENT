"""
HAZARUS DNS Reconnaissance
DNS enumeration and record analysis.
"""

import asyncio
import logging
import dns.resolver
import dns.message
import dns.query
import httpx
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DNSRecord:
    """DNS record data."""
    record_type: str
    name: str
    value: str
    ttl: int


@dataclass
class DNSResult:
    """DNS enumeration result."""
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dnssec_enabled: bool = False
    wildcards: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class DNSRecon:
    """DNS reconnaissance module."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.dns_recon")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def enumerate_records(self, domain: str) -> DNSResult:
        """Enumerate DNS records for a domain."""
        self.logger.info(f"Enumerating DNS records for {domain}")

        result = DNSResult(domain=domain)

        # Enumerate common record types
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'SRV']

        for record_type in record_types:
            try:
                records = await self._query_records(domain, record_type)
                result.records.extend(records)

                if record_type == 'NS':
                    result.nameservers = [r.value for r in records]
                elif record_type == 'MX':
                    result.mx_records = [
                        {"priority": r.value.split()[0], "server": r.value.split()[1]}
                        for r in records
                    ]
                elif record_type == 'TXT':
                    result.txt_records = [r.value for r in records]

            except Exception as e:
                result.errors.append(f"{record_type} query failed: {str(e)}")
                self.logger.debug(f"Failed to query {record_type} records: {e}")

        # Check for SPF
        result.spf_record = await self._check_spf(domain)

        # Check for DMARC
        result.dmarc_record = await self._check_dmarc(domain)

        # Check for DNSSEC
        result.dnssec_enabled = await self._check_dnssec(domain)

        # Check for wildcard DNS
        result.wildcards = await self._check_wildcard(domain)

        self.logger.info(f"Found {len(result.records)} DNS records for {domain}")
        return result

    async def _query_records(self, domain: str, record_type: str) -> List[DNSRecord]:
        """Query DNS records of a specific type."""
        loop = asyncio.get_event_loop()
        records = []

        try:
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, record_type)
            )

            for rdata in answers:
                records.append(DNSRecord(
                    record_type=record_type,
                    name=domain,
                    value=str(rdata),
                    ttl=answers.ttl
                ))

        except dns.resolver.NXDOMAIN:
            raise
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            raise

        return records

    async def _check_spf(self, domain: str) -> Optional[str]:
        """Check for SPF record."""
        try:
            txt_records = await self._query_records(domain, 'TXT')
            for record in txt_records:
                if 'v=spf1' in record.value:
                    return record.value
        except Exception:
            pass
        return None

    async def _check_dmarc(self, domain: str) -> Optional[str]:
        """Check for DMARC record."""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = await self._query_records(dmarc_domain, 'TXT')
            for record in txt_records:
                if 'v=DMARC1' in record.value:
                    return record.value
        except Exception:
            pass
        return None

    async def _check_dnssec(self, domain: str) -> bool:
        """Check if DNSSEC is enabled."""
        try:
            loop = asyncio.get_event_loop()
            answer = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, 'DNSKEY')
            )
            return len(answer) > 0
        except Exception:
            return False

    async def _check_wildcard(self, domain: str) -> List[str]:
        """Check for wildcard DNS records."""
        wildcards = []
        test_subdomains = ['test', 'asdf', 'random12345']

        for sub in test_subdomains:
            test_domain = f"{sub}.{domain}"
            try:
                records = await self._query_records(test_domain, 'A')
                if records:
                    wildcards.append(test_domain)
            except Exception:
                pass

        return wildcards

    async def subdomain_bruteforce(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None
    ) -> List[str]:
        """Brute force subdomain discovery with DNS validation."""
        if wordlist is None:
            # Common subdomain wordlist
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging',
                'test', 'api', 'app', 'portal', 'secure', 'vpn', 'cdn',
                'static', 'assets', 'img', 'images', 'video', 'docs',
                'support', 'help', 'shop', 'store', 'account', 'login',
                'auth', 'dashboard', 'panel', 'cp', 'webmail', 'email'
            ]

        self.logger.info(f"Brute forcing subdomains for {domain}")
        found_subdomains = []

        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            try:
                # Use DNS resolver to check if subdomain resolves
                loop = asyncio.get_event_loop()
                answer = await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(full_domain, 'A')
                )
                if answer and len(answer) > 0:
                    found_subdomains.append(full_domain)
                    self.logger.debug(f"Found subdomain: {full_domain}")
            except Exception as e:
                # Subdomain doesn't resolve or DNS error
                self.logger.debug(f"Subdomain {full_domain} not found: {e}")
                pass

        self.logger.info(f"Found {len(found_subdomains)} subdomains")
        return found_subdomains

    async def query_amass(self, domain: str) -> List[str]:
        """Query Amass for subdomain enumeration if available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "which", "amass",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                self.logger.info("Amass not installed, skipping")
                return []
            
            # Run Amass enumeration
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-d", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            subdomains = stdout.decode().strip().split('\n')
            return [s for s in subdomains if s and domain in s]
            
        except Exception as e:
            self.logger.warning(f"Amass query failed: {e}")
            return []

    async def query_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh for subdomain enumeration."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                # Use proper crt.sh API format
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json"
                )
                
                if response.status_code == 200:
                    import json
                    data = response.json()
                    subdomains = set()
                    
                    for cert in data:
                        name_value = cert.get('name_value', '')
                        # Split by newlines if multiple names
                        for name in name_value.split('\n'):
                            name = name.strip()
                            if name and domain in name and not name.startswith('*'):
                                subdomains.add(name)
                    
                    return list(subdomains)
                else:
                    self.logger.warning(f"crt.sh returned status {response.status_code}")
                    return []
                    
        except Exception as e:
            self.logger.warning(f"crt.sh query failed: {e}")
            return []

    async def zone_transfer(self, domain: str, nameserver: str) -> bool:
        """Attempt DNS zone transfer."""
        self.logger.warning(f"Attempting zone transfer for {domain} on {nameserver}")

        try:
            loop = asyncio.get_event_loop()
            zone = await loop.run_in_executor(
                None,
                lambda: dns.query.xfr(nameserver, domain)
            )

            # If we get here, zone transfer succeeded
            self.logger.warning(f"Zone transfer succeeded for {domain}")
            return True

        except Exception as e:
            self.logger.debug(f"Zone transfer failed: {e}")
            return False

    def to_dict(self, result: DNSResult) -> Dict[str, Any]:
        """Convert DNSResult to dictionary."""
        return {
            "domain": result.domain,
            "records": [
                {
                    "type": r.record_type,
                    "name": r.name,
                    "value": r.value,
                    "ttl": r.ttl
                }
                for r in result.records
            ],
            "nameservers": result.nameservers,
            "mx_records": result.mx_records,
            "txt_records": result.txt_records,
            "spf_record": result.spf_record,
            "dmarc_record": result.dmarc_record,
            "dnssec_enabled": result.dnssec_enabled,
            "wildcards": result.wildcards,
            "subdomains": result.subdomains,
            "errors": result.errors
        }
