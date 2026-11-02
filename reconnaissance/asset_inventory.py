"""
HAZARUS Asset Inventory
Asset discovery and inventory management.
"""

import asyncio
import logging
from typing import Dict, Any, List, Set
from dataclasses import dataclass, field
from datetime import datetime
from .dns import DNSRecon
from .subdomains import SubdomainDiscovery
from .whois import WhoisRecon
from .passive_recon import PassiveRecon


@dataclass
class Asset:
    """An identified asset."""
    type: str  # domain, subdomain, ip, url, service
    value: str
    confidence: float  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AssetInventory:
    """Asset inventory result."""
    assessment_id: str
    assets: List[Asset] = field(default_factory=list)
    relationships: Dict[str, List[str]] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)


class AssetInventoryBuilder:
    """Asset inventory module."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.logger = logging.getLogger("hazarus.asset_inventory")

        self.dns_recon = DNSRecon()
        self.subdomain_discovery = SubdomainDiscovery()
        self.whois_recon = WhoisRecon()
        self.passive_recon = PassiveRecon()

    async def build_inventory(self, targets: List[str]) -> AssetInventory:
        """Build asset inventory for targets."""
        self.logger.info(f"Building inventory for {len(targets)} targets")

        inventory = AssetInventory(assessment_id=self.assessment_id)

        for target in targets:
            await self._inventory_target(target, inventory)

        # Build relationships
        self._build_relationships(inventory)

        # Generate summary
        inventory.summary = self._generate_summary(inventory)

        self.logger.info(f"Inventory complete: {len(inventory.assets)} assets")
        return inventory

    async def _inventory_target(self, target: str, inventory: AssetInventory) -> None:
        """Inventory a single target."""
        self.logger.debug(f"Inventorying {target}")

        # Add the target itself
        if "." in target and not target.replace(".", "").isdigit():
            # It's a domain
            inventory.assets.append(Asset(
                type="domain",
                value=target,
                confidence=1.0
            ))

            # DNS enumeration
            try:
                dns_result = await self.dns_recon.enumerate_records(target)

                # Add nameservers as assets
                for ns in dns_result.nameservers:
                    inventory.assets.append(Asset(
                        type="nameserver",
                        value=ns,
                        confidence=0.9,
                        metadata={"domain": target}
                    ))

                # Add MX records as assets
                for mx in dns_result.mx_records:
                    inventory.assets.append(Asset(
                        type="mail_server",
                        value=mx.get("server", ""),
                        confidence=0.9,
                        metadata={"domain": target, "priority": mx.get("priority")}
                    ))

            except Exception as e:
                self.logger.error(f"DNS enumeration failed for {target}: {e}")

            # Subdomain discovery
            try:
                subdomain_result = await self.subdomain_discovery.discover(target)

                for subdomain in subdomain_result.subdomains:
                    inventory.assets.append(Asset(
                        type="subdomain",
                        value=subdomain,
                        confidence=0.8,
                        metadata={"domain": target}
                    ))

            except Exception as e:
                self.logger.error(f"Subdomain discovery failed for {target}: {e}")

            # WHOIS information
            try:
                whois_result = await self.whois_recon.query(target)

                if whois_result.registrar:
                    inventory.assets.append(Asset(
                        type="registrar",
                        value=whois_result.registrar,
                        confidence=1.0,
                        metadata={"domain": target}
                    ))

            except Exception as e:
                self.logger.error(f"WHOIS query failed for {target}: {e}")

            # Passive reconnaissance
            try:
                passive_result = await self.passive_recon.gather(target)

                # Add discovered technologies
                for tech in passive_result.technologies:
                    inventory.assets.append(Asset(
                        type="technology",
                        value=tech,
                        confidence=0.7,
                        metadata={"domain": target}
                    ))

                # Add cloud providers
                for provider in passive_result.cloud_providers:
                    inventory.assets.append(Asset(
                        type="cloud_provider",
                        value=provider,
                        confidence=0.8,
                        metadata={"domain": target}
                    ))

            except Exception as e:
                self.logger.error(f"Passive recon failed for {target}: {e}")

        else:
            # It's an IP address
            inventory.assets.append(Asset(
                type="ip",
                value=target,
                confidence=1.0
            ))

            # IP WHOIS
            try:
                ip_whois = await self.whois_recon.query_ip(target)

                if ip_whois.get("org"):
                    inventory.assets.append(Asset(
                        type="organization",
                        value=ip_whois["org"],
                        confidence=0.9,
                        metadata={"ip": target}
                    ))

            except Exception as e:
                self.logger.error(f"IP WHOIS failed for {target}: {e}")

    def _build_relationships(self, inventory: AssetInventory) -> None:
        """Build relationships between assets."""
        relationships = {}

        # Domain to subdomain relationships
        domains = {a.value for a in inventory.assets if a.type == "domain"}
        subdomains = {a for a in inventory.assets if a.type == "subdomain"}

        for subdomain in subdomains:
            for domain in domains:
                if subdomain.value.endswith(f".{domain}"):
                    if domain not in relationships:
                        relationships[domain] = []
                    relationships[domain].append(subdomain.value)

        inventory.relationships = relationships

    def _generate_summary(self, inventory: AssetInventory) -> Dict[str, int]:
        """Generate asset summary."""
        summary = {}

        for asset in inventory.assets:
            summary[asset.type] = summary.get(asset.type, 0) + 1

        summary["total"] = len(inventory.assets)
        return summary

    def to_dict(self, inventory: AssetInventory) -> Dict[str, Any]:
        """Convert inventory to dictionary."""
        return {
            "assessment_id": inventory.assessment_id,
            "assets": [
                {
                    "type": a.type,
                    "value": a.value,
                    "confidence": a.confidence,
                    "metadata": a.metadata,
                    "discovered_at": a.discovered_at.isoformat()
                }
                for a in inventory.assets
            ],
            "relationships": inventory.relationships,
            "summary": inventory.summary
        }
