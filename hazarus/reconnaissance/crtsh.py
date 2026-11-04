"""
HAZARUS Certificate Transparency
Certificate Transparency log queries.
"""

import asyncio
import logging
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class CertificateInfo:
    """Certificate information from CT logs."""
    domain: str
    subdomain: str
    issuer: Optional[str] = None
    issued_date: Optional[datetime] = None
    expired_date: Optional[datetime] = None


class CertificateTransparency:
    """Certificate Transparency module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.certificate_transparency")

    async def query(self, domain: str) -> List[CertificateInfo]:
        """Query Certificate Transparency logs for a domain."""
        self.logger.info(f"Querying CT logs for {domain}")

        certificates = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # crt.sh API
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = await client.get(url)

                if response.status_code == 200:
                    data = response.json()
                    seen = set()

                    for entry in data:
                        name_value = entry.get("name_value", "")

                        # Skip wildcards
                        if "*" in name_value:
                            continue

                        # Clean up the name
                        name = name_value.strip()

                        if name and name not in seen:
                            cert_info = CertificateInfo(
                                domain=domain,
                                subdomain=name,
                                issuer=entry.get("issuer_name"),
                                issued_date=self._parse_date(entry.get("not_before")),
                                expired_date=self._parse_date(entry.get("not_after"))
                            )
                            certificates.append(cert_info)
                            seen.add(name)

                    self.logger.info(f"Found {len(certificates)} certificates from CT logs")

        except Exception as e:
            self.logger.error(f"CT log query failed: {e}")

        return certificates

    async def query_expired(self, domain: str) -> List[CertificateInfo]:
        """Query for expired certificates."""
        self.logger.info(f"Querying expired certificates for {domain}")

        all_certs = await self.query(domain)
        now = datetime.utcnow()

        expired = [c for c in all_certs if c.expired_date and c.expired_date < now]

        self.logger.info(f"Found {len(expired)} expired certificates")
        return expired

    async def query_by_issuer(self, domain: str, issuer: str) -> List[CertificateInfo]:
        """Query certificates by issuer."""
        all_certs = await self.query(domain)

        filtered = [c for c in all_certs if issuer.lower() in (c.issuer or "").lower()]

        self.logger.info(f"Found {len(filtered)} certificates from issuer {issuer}")
        return filtered

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string from CT log."""
        if not date_str:
            return None

        try:
            # CT logs use various date formats
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def to_dict(self, certificates: List[CertificateInfo]) -> List[Dict[str, Any]]:
        """Convert certificates to dictionary."""
        return [
            {
                "domain": c.domain,
                "subdomain": c.subdomain,
                "issuer": c.issuer,
                "issued_date": c.issued_date.isoformat() if c.issued_date else None,
                "expired_date": c.expired_date.isoformat() if c.expired_date else None
            }
            for c in certificates
        ]
