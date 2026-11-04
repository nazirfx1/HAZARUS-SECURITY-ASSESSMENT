"""
HAZARUS WHOIS Reconnaissance
WHOIS and RDAP queries.
"""

import asyncio
import logging
import socket
import whois
from typing import Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class WhoisResult:
    """WHOIS query result."""
    domain: str
    registrar: Optional[str] = None
    created_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    status: Optional[str] = None
    name_servers: list = None
    registrant: Optional[Dict[str, str]] = None
    admin: Optional[Dict[str, str]] = None
    tech: Optional[Dict[str, str]] = None
    dnssec: Optional[bool] = None
    raw_data: Optional[str] = None

    def __post_init__(self):
        if self.name_servers is None:
            self.name_servers = []
        if self.registrant is None:
            self.registrant = {}
        if self.admin is None:
            self.admin = {}
        if self.tech is None:
            self.tech = {}


class WhoisRecon:
    """WHOIS reconnaissance module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.whois_recon")

    async def query(self, target: str) -> WhoisResult:
        """Query WHOIS for a target."""
        self.logger.info(f"Querying WHOIS for {target}")

        result = WhoisResult(domain=target)

        try:
            loop = asyncio.get_event_loop()

            # Use python-whois library
            whois_data = await loop.run_in_executor(
                None,
                lambda: whois.whois(target)
            )

            if whois_data:
                result.registrar = whois_data.registrar
                result.created_date = whois_data.creation_date
                result.expiration_date = whois_data.expiration_date
                result.updated_date = whois_data.updated_date
                result.status = whois_data.status
                result.name_servers = whois_data.name_servers or []

                # Extract contact information
                if whois_data.registrant:
                    result.registrant = {
                        "name": whois_data.registrant.name,
                        "email": whois_data.registrant.email,
                        "organization": whois_data.registrant.organization
                    }

                if whois_data.admin:
                    result.admin = {
                        "name": whois_data.admin.name,
                        "email": whois_data.admin.email,
                        "organization": whois_data.admin.organization
                    }

                if whois_data.tech:
                    result.tech = {
                        "name": whois_data.tech.name,
                        "email": whois_data.tech.email,
                        "organization": whois_data.tech.organization
                    }

                result.dnssec = whois_data.dnssec
                result.raw_data = str(whois_data)

            self.logger.info(f"WHOIS query successful for {target}")

        except Exception as e:
            self.logger.error(f"WHOIS query failed for {target}: {e}")

        return result

    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """Query WHOIS for an IP address."""
        self.logger.info(f"Querying WHOIS for IP {ip}")

        try:
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(
                None,
                lambda: whois.whois(ip)
            )

            return {
                "ip": ip,
                "org": whois_data.org if whois_data else None,
                "country": whois_data.country if whois_data else None,
                "raw": str(whois_data) if whois_data else None
            }

        except Exception as e:
            self.logger.error(f"IP WHOIS query failed: {e}")
            return {"ip": ip, "error": str(e)}

    def to_dict(self, result: WhoisResult) -> Dict[str, Any]:
        """Convert WhoisResult to dictionary."""
        return {
            "domain": result.domain,
            "registrar": result.registrar,
            "created_date": result.created_date.isoformat() if result.created_date else None,
            "expiration_date": result.expiration_date.isoformat() if result.expiration_date else None,
            "updated_date": result.updated_date.isoformat() if result.updated_date else None,
            "status": result.status,
            "name_servers": result.name_servers,
            "registrant": result.registrant,
            "admin": result.admin,
            "tech": result.tech,
            "dnssec": result.dnssec
        }
