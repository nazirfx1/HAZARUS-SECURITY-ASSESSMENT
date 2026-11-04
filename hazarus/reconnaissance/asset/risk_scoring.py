"""
HAZARUS Asset Risk Scoring
Calculate risk scores for assets based on multiple factors.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, UTC

from .inventory import AssetCriticality, ExtendedAsset


@dataclass
class RiskFactor:
    """Risk factor for scoring."""
    name: str
    weight: float
    value: float
    description: str


@dataclass
class RiskAssessment:
    """Risk assessment result."""
    asset_value: str
    risk_score: float  # 0.0 to 1.0
    risk_level: str  # critical, high, medium, low
    factors: List[RiskFactor]
    assessed_at: datetime = None

    def __post_init__(self):
        if self.assessed_at is None:
            self.assessed_at = datetime.now(UTC)


class AssetRiskScoring:
    """Asset risk scoring engine."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.asset_risk_scoring")

        # Risk factor weights
        self.criticality_weights = {
            AssetCriticality.CRITICAL: 0.4,
            AssetCriticality.HIGH: 0.3,
            AssetCriticality.MEDIUM: 0.2,
            AssetCriticality.LOW: 0.1
        }

    async def calculate_risk_score(
        self,
        asset: ExtendedAsset,
        context: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Calculate risk score for an asset.

        Args:
            asset: Asset to assess
            context: Additional context (vulnerabilities, exposure, etc.)

        Returns:
            RiskAssessment object
        """
        factors = []
        total_score = 0.0

        # Factor 1: Criticality
        criticality_weight = self.criticality_weights.get(
            asset.criticality,
            0.2
        )
        factors.append(RiskFactor(
            name="criticality",
            weight=0.4,
            value=criticality_weight,
            description=f"Asset criticality: {asset.criticality.value}"
        ))
        total_score += 0.4 * criticality_weight

        # Factor 2: Exposure (if exposed to internet)
        if asset.type in ["domain", "ip", "subdomain"]:
            exposure_score = 0.8  # High exposure
            factors.append(RiskFactor(
                name="exposure",
                weight=0.3,
                value=exposure_score,
                description="Asset is internet-facing"
            ))
            total_score += 0.3 * exposure_score
        else:
            exposure_score = 0.3  # Lower exposure
            factors.append(RiskFactor(
                name="exposure",
                weight=0.3,
                value=exposure_score,
                description="Asset is internal"
            ))
            total_score += 0.3 * exposure_score

        # Factor 3: Confidence in discovery
        confidence_score = 1.0 - asset.confidence
        factors.append(RiskFactor(
            name="discovery_confidence",
            weight=0.1,
            value=confidence_score,
            description=f"Discovery confidence: {asset.confidence}"
        ))
        total_score += 0.1 * confidence_score

        # Factor 4: Dependencies (more dependencies = higher risk)
        dependency_risk = min(len(asset.dependencies) / 10, 1.0)
        factors.append(RiskFactor(
            name="dependencies",
            weight=0.1,
            value=dependency_risk,
            description=f"Dependency count: {len(asset.dependencies)}"
        ))
        total_score += 0.1 * dependency_risk

        # Factor 5: Status (inactive/retired = lower risk)
        if asset.status.value in ["inactive", "retired"]:
            status_factor = 0.2
        else:
            status_factor = 0.8
        factors.append(RiskFactor(
            name="status",
            weight=0.1,
            value=status_factor,
            description=f"Asset status: {asset.status.value}"
        ))
        total_score += 0.1 * status_factor

        # Contextual factors (if provided)
        if context:
            # Vulnerabilities
            vuln_count = context.get("vulnerabilities", 0)
            if vuln_count > 0:
                vuln_factor = min(vuln_count / 5, 1.0)
                factors.append(RiskFactor(
                    name="vulnerabilities",
                    weight=0.2,
                    value=vuln_factor,
                    description=f"Vulnerability count: {vuln_count}"
                ))
                total_score += 0.2 * vuln_factor

            # Recent changes
            recent_changes = context.get("recent_changes", 0)
            if recent_changes > 0:
                change_factor = min(recent_changes / 3, 1.0)
                factors.append(RiskFactor(
                    name="recent_changes",
                    weight=0.1,
                    value=change_factor,
                    description=f"Recent changes: {recent_changes}"
                ))
                total_score += 0.1 * change_factor

        # Normalize score to 0-1
        risk_score = min(total_score, 1.0)

        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"

        assessment = RiskAssessment(
            asset_value=asset.value,
            risk_score=risk_score,
            risk_level=risk_level,
            factors=factors
        )

        self.logger.info(
            f"Risk assessment for {asset.value}: "
            f"{risk_score:.2f} ({risk_level})"
        )

        return assessment

    async def batch_score(
        self,
        assets: List[ExtendedAsset],
        context: Optional[Dict[str, Any]] = None
    ) -> List[RiskAssessment]:
        """
        Calculate risk scores for multiple assets.

        Args:
            assets: List of assets to assess
            context: Additional context

        Returns:
            List of RiskAssessment objects
        """
        assessments = []

        for asset in assets:
            assessment = await self.calculate_risk_score(asset, context)
            assessments.append(assessment)

        # Sort by risk score (highest first)
        assessments.sort(key=lambda x: x.risk_score, reverse=True)

        self.logger.info(f"Batch risk assessment complete: {len(assessments)} assets")
        return assessments

    async def get_high_risk_assets(
        self,
        assessments: List[RiskAssessment],
        threshold: float = 0.7
    ) -> List[RiskAssessment]:
        """
        Get assets above risk threshold.

        Args:
            assessments: List of risk assessments
            threshold: Risk threshold (default: 0.7)

        Returns:
            List of high-risk assessments
        """
        high_risk = [a for a in assessments if a.risk_score >= threshold]
        self.logger.info(f"Found {len(high_risk)} high-risk assets (threshold: {threshold})")
        return high_risk
