"""
HAZARUS Asset Lifecycle Management
Track asset lifecycle, retirement, and change detection.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC, timedelta
from enum import Enum

from .inventory import AssetStatus, ExtendedAsset


@dataclass
class LifecycleEvent:
    """Asset lifecycle event."""
    asset_value: str
    event_type: str  # created, updated, retired, reactivated
    timestamp: datetime
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LifecycleHistory:
    """Asset lifecycle history."""
    asset_value: str
    events: List[LifecycleEvent] = field(default_factory=list)
    first_seen: datetime = None
    last_seen: datetime = None
    total_lifetime_days: float = 0.0


class AssetLifecycle:
    """Asset lifecycle management."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.asset_lifecycle")
        self.history: Dict[str, LifecycleHistory] = {}

    async def update_asset_status(
        self,
        asset: ExtendedAsset,
        new_status: AssetStatus
    ) -> LifecycleEvent:
        """
        Update asset status and record lifecycle event.

        Args:
            asset: Asset to update
            new_status: New status

        Returns:
            LifecycleEvent object
        """
        previous_status = asset.status
        asset.status = new_status
        asset.last_seen = datetime.now(UTC)

        event = LifecycleEvent(
            asset_value=asset.value,
            event_type="updated",
            timestamp=datetime.now(UTC),
            previous_status=previous_status.value,
            new_status=new_status.value
        )

        # Record in history
        if asset.value not in self.history:
            self.history[asset.value] = LifecycleHistory(
                asset_value=asset.value,
                first_seen=asset.first_seen
            )

        self.history[asset.value].events.append(event)
        self.history[asset.value].last_seen = asset.last_seen

        self.logger.info(f"Updated {asset.value} status: {previous_status.value} -> {new_status.value}")
        return event

    async def retire_asset(self, asset: ExtendedAsset) -> LifecycleEvent:
        """
        Retire an asset.

        Args:
            asset: Asset to retire

        Returns:
            LifecycleEvent object
        """
        return await self.update_asset_status(asset, AssetStatus.RETIRED)

    async def reactivate_asset(self, asset: ExtendedAsset) -> LifecycleEvent:
        """
        Reactivate a retired asset.

        Args:
            asset: Asset to reactivate

        Returns:
            LifecycleEvent object
        """
        return await self.update_asset_status(asset, AssetStatus.ACTIVE)

    async def get_lifecycle_history(
        self,
        asset_value: str
    ) -> Optional[LifecycleHistory]:
        """
        Get lifecycle history for an asset.

        Args:
            asset_value: Asset value

        Returns:
            LifecycleHistory object or None
        """
        return self.history.get(asset_value)

    async def calculate_lifetime(self, asset_value: str) -> float:
        """
        Calculate total lifetime of an asset in days.

        Args:
            asset_value: Asset value

        Returns:
            Lifetime in days
        """
        history = await self.get_lifecycle_history(asset_value)
        if history and history.first_seen:
            delta = datetime.now(UTC) - history.first_seen
            return delta.total_seconds() / 86400
        return 0.0

    async def get_stale_assets(
        self,
        days_threshold: int = 90
    ) -> List[str]:
        """
        Get assets that haven't been seen in X days.

        Args:
            days_threshold: Number of days threshold

        Returns:
            List of asset values
        """
        stale = []
        threshold = datetime.now(UTC) - timedelta(days=days_threshold)

        for asset_value, history in self.history.items():
            if history.last_seen and history.last_seen < threshold:
                stale.append(asset_value)

        self.logger.info(f"Found {len(stale)} stale assets (> {days_threshold} days)")
        return stale

    async def cleanup_retired_assets(
        self,
        retention_days: int = 30
    ) -> List[str]:
        """
        Remove retired assets older than retention period.

        Args:
            retention_days: Retention period in days

        Returns:
            List of removed asset values
        """
        removed = []
        threshold = datetime.now(UTC) - timedelta(days=retention_days)

        for asset_value, history in list(self.history.items()):
            # Check if asset is retired and older than threshold
            latest_event = history.events[-1] if history.events else None
            if (latest_event and 
                latest_event.new_status == AssetStatus.RETIRED.value and
                latest_event.timestamp < threshold):
                del self.history[asset_value]
                removed.append(asset_value)

        self.logger.info(f"Cleaned up {len(removed)} retired assets")
        return removed
