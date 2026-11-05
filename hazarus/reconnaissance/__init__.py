"""
HAZARUS Reconnaissance Module
Asset discovery and passive reconnaissance.
"""

from hazarus.reconnaissance.dns import DNSRecon
from hazarus.reconnaissance.whois import WhoisRecon
from hazarus.reconnaissance.subdomains import SubdomainDiscovery
from hazarus.reconnaissance.crtsh import CertificateTransparency
from hazarus.reconnaissance.passive_recon import PassiveRecon
from hazarus.reconnaissance.asset_inventory import AssetInventory
from hazarus.reconnaissance.live_hosts import LiveHostDiscovery
from hazarus.reconnaissance.origin_ip import OriginIPDiscovery

# Core infrastructure
from hazarus.reconnaissance.core import (
    ReconPersistence,
    AssessmentRecord,
    AssetRecord,
    FindingRecord,
    ParallelRecon,
    PriorityParallelRecon,
    TaskResult,
    ParallelStats,
    PriorityTask,
    ReconCache,
    CacheEntry,
    CacheStats,
    get_global_cache,
    reset_global_cache,
    ReconReport,
    ReconReportGenerator
)

# Advanced tools
from hazarus.reconnaissance.advanced import (
    AdvancedSubdomainTools,
    AdvancedDNS,
    EnhancedPassiveRecon
)

# Security features
from hazarus.reconnaissance.security import (
    SubdomainTakeoverDetector,
    VirtualHostEnumerator
)

# Intelligence sources
from hazarus.reconnaissance.intelligence import (
    APIIntelligence
)

# Asset intelligence
from hazarus.reconnaissance.asset import (
    AssetIntelligence,
    AssetLifecycle,
    AssetRiskScoring
)

__all__ = [
    # Core modules
    "DNSRecon",
    "WhoisRecon",
    "SubdomainDiscovery",
    "CertificateTransparency",
    "PassiveRecon",
    "AssetInventory",
    "LiveHostDiscovery",
    "OriginIPDiscovery",
    # Core infrastructure
    "ReconPersistence",
    "AssessmentRecord",
    "AssetRecord",
    "FindingRecord",
    "ParallelRecon",
    "PriorityParallelRecon",
    "TaskResult",
    "ParallelStats",
    "PriorityTask",
    "ReconCache",
    "CacheEntry",
    "CacheStats",
    "get_global_cache",
    "reset_global_cache",
    "ReconReport",
    "ReconReportGenerator",
    # Advanced tools
    "AdvancedSubdomainTools",
    "AdvancedDNS",
    "EnhancedPassiveRecon",
    # Security features
    "SubdomainTakeoverDetector",
    "VirtualHostEnumerator",
    # Intelligence sources
    "APIIntelligence",
    # Asset intelligence
    "AssetIntelligence",
    "AssetLifecycle",
    "AssetRiskScoring",
]
