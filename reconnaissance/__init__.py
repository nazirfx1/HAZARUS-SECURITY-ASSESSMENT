"""
HAZARUS Reconnaissance Module
Asset discovery and passive reconnaissance.
"""

from .dns import DNSRecon
from .whois import WhoisRecon
from .subdomains import SubdomainDiscovery
from .crtsh import CertificateTransparency
from .passive_recon import PassiveRecon
from .asset_inventory import AssetInventory
from .live_hosts import LiveHostDiscovery
from .origin_ip import OriginIPDiscovery

# Core infrastructure
from .core import (
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
from .advanced import (
    AdvancedSubdomainTools,
    AdvancedDNS,
    EnhancedPassiveRecon
)

# Security features
from .security import (
    SubdomainTakeoverDetector,
    VirtualHostEnumerator
)

# Intelligence sources
from .intelligence import (
    APIIntelligence
)

# Asset intelligence
from .asset import (
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
