"""
HAZARUS Asset Intelligence
Asset lifecycle management, ownership tracking, and grouping.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum


class AssetStatus(Enum):
    """Asset lifecycle status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETIRED = "retired"
    UNKNOWN = "unknown"


class AssetCriticality(Enum):
    """Asset criticality level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ExtendedAsset:
    """Extended asset with intelligence data."""
    type: str
    value: str
    confidence: float
    status: AssetStatus = AssetStatus.UNKNOWN
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    owner: Optional[str] = None
    team: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    first_seen: datetime = None
    last_seen: datetime = None
    risk_score: float = 0.0
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now(UTC)
        if self.last_seen is None:
            self.last_seen = datetime.now(UTC)


@dataclass
class AssetChange:
    """Asset change detection result."""
    asset_value: str
    change_type: str  # added, removed, modified
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    detected_at: datetime = None

    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.now(UTC)


@dataclass
class AssetIntelligenceResult:
    """Asset intelligence result."""
    assessment_id: str
    assets: List[ExtendedAsset] = field(default_factory=list)
    changes: List[AssetChange] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    analyzed_at: datetime = None

    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.now(UTC)


class AssetIntelligence:
    """Asset intelligence and lifecycle management."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.asset_intelligence")

    async def classify_assets(
        self,
        assets: List[Dict[str, Any]]
    ) -> List[ExtendedAsset]:
        """
        Classify assets with criticality and status.

        Args:
            assets: List of asset dictionaries

        Returns:
            List of ExtendedAsset objects
        """
        classified = []

        for asset in assets:
            asset_type = asset.get("type", "unknown")
            value = asset.get("value", "")
            confidence = asset.get("confidence", 0.5)

            # Determine criticality based on type
            if asset_type in ["domain", "ip"]:
                criticality = AssetCriticality.HIGH
            elif asset_type in ["nameserver", "mail_server"]:
                criticality = AssetCriticality.CRITICAL
            else:
                criticality = AssetCriticality.MEDIUM

            # Determine status based on metadata
            status = AssetStatus.ACTIVE

            extended = ExtendedAsset(
                type=asset_type,
                value=value,
                confidence=confidence,
                status=status,
                criticality=criticality,
                metadata=asset.get("metadata", {})
            )

            classified.append(extended)

        self.logger.info(f"Classified {len(classified)} assets")
        return classified

    async def detect_changes(
        self,
        old_assets: List[ExtendedAsset],
        new_assets: List[ExtendedAsset]
    ) -> List[AssetChange]:
        """
        Detect changes between asset sets.

        Args:
            old_assets: Previous asset set
            new_assets: Current asset set

        Returns:
            List of AssetChange objects
        """
        changes = []

        old_values = {a.value: a for a in old_assets}
        new_values = {a.value: a for a in new_assets}

        # Detect added assets
        for value, asset in new_values.items():
            if value not in old_values:
                changes.append(AssetChange(
                    asset_value=value,
                    change_type="added",
                    new_value=value
                ))

        # Detect removed assets
        for value, asset in old_values.items():
            if value not in new_values:
                changes.append(AssetChange(
                    asset_value=value,
                    change_type="removed",
                    old_value=value
                ))

        # Detect modified assets
        for value in set(old_values.keys()) & set(new_values.keys()):
            old_asset = old_values[value]
            new_asset = new_values[value]

            if old_asset.status != new_asset.status:
                changes.append(AssetChange(
                    asset_value=value,
                    change_type="modified",
                    old_value=old_asset.status.value,
                    new_value=new_asset.status.value
                ))

        self.logger.info(f"Detected {len(changes)} asset changes")
        return changes

    async def analyze_dependencies(
        self,
        assets: List[ExtendedAsset]
    ) -> List[ExtendedAsset]:
        """
        Analyze dependencies between assets.

        Args:
            assets: List of assets

        Returns:
            List of assets with dependencies populated
        """
        # Group assets by type
        by_type = {}
        for asset in assets:
            if asset.type not in by_type:
                by_type[asset.type] = []
            by_type[asset.type].append(asset)

        # Simple dependency mapping
        for asset in assets:
            # Domains depend on nameservers
            if asset.type == "domain" and "nameserver" in by_type:
                for ns in by_type["nameserver"]:
                    if ns.value in asset.value:
                        asset.dependencies.append(ns.value)

            # Subdomains depend on parent domain
            if asset.type == "subdomain":
                for domain in by_type.get("domain", []):
                    if asset.value.endswith(domain.value):
                        asset.dependencies.append(domain.value)

        self.logger.info("Analyzed asset dependencies")
        return assets

    async def generate_summary(
        self,
        assets: List[ExtendedAsset]
    ) -> Dict[str, Any]:
        """
        Generate summary statistics for assets.

        Args:
            assets: List of assets

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            "total_assets": len(assets),
            "by_type": {},
            "by_status": {},
            "by_criticality": {},
            "high_risk_count": 0
        }

        for asset in assets:
            # Count by type
            asset_type = asset.type
            summary["by_type"][asset_type] = summary["by_type"].get(asset_type, 0) + 1

            # Count by status
            status = asset.status.value
            summary["by_status"][status] = summary["by_status"].get(status, 0) + 1

            # Count by criticality
            criticality = asset.criticality.value
            summary["by_criticality"][criticality] = summary["by_criticality"].get(criticality, 0) + 1

            # Count high risk
            if asset.risk_score >= 0.7:
                summary["high_risk_count"] += 1

        return summary

    async def analyze(
        self,
        assets: List[Dict[str, Any]],
        previous_assets: Optional[List[ExtendedAsset]] = None
    ) -> AssetIntelligenceResult:
        """
        Run full asset intelligence analysis.

        Args:
            assets: Current asset set
            previous_assets: Previous asset set for change detection

        Returns:
            AssetIntelligenceResult with full analysis
        """
        result = AssetIntelligenceResult(assessment_id="current")

        # Classify assets
        result.assets = await self.classify_assets(assets)

        # Analyze dependencies
        result.assets = await self.analyze_dependencies(result.assets)

        # Detect changes if previous assets provided
        if previous_assets:
            result.changes = await self.detect_changes(previous_assets, result.assets)

        # Generate summary
        result.summary = await self.generate_summary(result.assets)

        self.logger.info("Asset intelligence analysis complete")
        return result
