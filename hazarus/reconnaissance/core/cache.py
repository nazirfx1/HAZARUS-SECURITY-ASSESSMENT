"""
HAZARUS Reconnaissance Caching Layer
TTL-based caching for DNS, WHOIS, and API calls.
"""

import asyncio
import json
import hashlib
import logging
from typing import Optional, Any, Dict
from datetime import datetime, UTC, timedelta
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CacheEntry:
    """Cache entry with TTL."""
    key: str
    value: Any
    created_at: datetime
    ttl: int  # Time to live in seconds
    hit_count: int = 0
    last_accessed: Optional[datetime] = None

    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.ttl == 0:
            return False  # Never expire
        return datetime.now(UTC) > self.created_at + timedelta(seconds=self.ttl)

    def access(self) -> Any:
        """Mark entry as accessed and return value."""
        self.hit_count += 1
        self.last_accessed = datetime.now(UTC)
        return self.value


@dataclass
class CacheStats:
    """Cache statistics."""
    total_entries: int = 0
    hit_count: int = 0
    miss_count: int = 0
    expired_count: int = 0
    hit_rate: float = 0.0


class ReconCache:
    """Caching layer for reconnaissance results."""

    def __init__(
        self,
        ttl: int = 3600,  # Default TTL: 1 hour
        max_size: int = 10000,  # Maximum cache entries
        persist_to_disk: bool = True,
        cache_dir: Optional[str] = None
    ):
        """
        Initialize cache.

        Args:
            ttl: Default time-to-live in seconds
            max_size: Maximum number of cache entries
            persist_to_disk: Whether to persist cache to disk
            cache_dir: Directory for disk cache (default: ~/.hazarus/cache)
        """
        self.ttl = ttl
        self.max_size = max_size
        self.persist_to_disk = persist_to_disk
        self.cache: Dict[str, CacheEntry] = {}
        self.stats = CacheStats()
        self.logger = logging.getLogger("hazarus.recon_cache")

        if persist_to_disk:
            if cache_dir is None:
                home = Path.home()
                hazarus_dir = home / ".hazarus"
                cache_dir = str(hazarus_dir / "cache")

            self.cache_dir = Path(cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()

    def generate_key(self, method: str, **kwargs) -> str:
        """
        Generate cache key from method and parameters.

        Args:
            method: Method name
            **kwargs: Method parameters

        Returns:
            Cache key (hash)
        """
        # Create deterministic string representation
        key_dict = {"method": method, "kwargs": kwargs}
        key_str = json.dumps(key_dict, sort_keys=True, default=str)
        return hashlib.sha256(key_str.encode()).hexdigest()

    async def get(self, key: str) -> Optional[Any]:
        """
        Get cached value if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if key not in self.cache:
            self.stats.miss_count += 1
            self._update_hit_rate()
            return None

        entry = self.cache[key]

        if entry.is_expired():
            # Remove expired entry
            del self.cache[key]
            self.stats.expired_count += 1
            self.stats.miss_count += 1
            self._update_hit_rate()
            self.logger.debug(f"Cache expired: {key[:16]}...")
            return None

        # Hit - mark as accessed
        value = entry.access()
        self.stats.hit_count += 1
        self._update_hit_rate()
        self.logger.debug(f"Cache hit: {key[:16]}... (hits: {entry.hit_count})")
        return value

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> None:
        """
        Cache value with TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        if ttl is None:
            ttl = self.ttl

        # Check cache size limit
        if len(self.cache) >= self.max_size:
            await self._evict_oldest()

        entry = CacheEntry(
            key=key,
            value=value,
            created_at=datetime.now(UTC),
            ttl=ttl
        )

        self.cache[key] = entry
        self.stats.total_entries = len(self.cache)

        if self.persist_to_disk:
            await self._save_to_disk_async()

        self.logger.debug(f"Cache set: {key[:16]}... (TTL: {ttl}s)")

    async def delete(self, key: str) -> bool:
        """
        Delete cache entry.

        Args:
            key: Cache key

        Returns:
            True if deleted, False if not found
        """
        if key in self.cache:
            del self.cache[key]
            self.stats.total_entries = len(self.cache)
            if self.persist_to_disk:
                await self._save_to_disk_async()
            return True
        return False

    async def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()
        self.stats = CacheStats()
        if self.persist_to_disk:
            await self._save_to_disk_async()
        self.logger.info("Cache cleared")

    async def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        expired_keys = [
            key for key, entry in self.cache.items()
            if entry.is_expired()
        ]

        for key in expired_keys:
            del self.cache[key]

        self.stats.total_entries = len(self.cache)
        self.stats.expired_count += len(expired_keys)

        if self.persist_to_disk:
            await self._save_to_disk_async()

        self.logger.info(f"Cleaned up {len(expired_keys)} expired entries")
        return len(expired_keys)

    async def _evict_oldest(self) -> None:
        """Evict oldest cache entry (LRU)."""
        if not self.cache:
            return

        # Find least recently accessed
        oldest_key = min(
            self.cache.keys(),
            key=lambda k: self.cache[k].last_accessed or datetime.min
        )

        del self.cache[oldest_key]
        self.logger.debug(f"Evicted oldest entry: {oldest_key[:16]}...")

    def _update_hit_rate(self) -> None:
        """Update cache hit rate."""
        total = self.stats.hit_count + self.stats.miss_count
        if total > 0:
            self.stats.hit_rate = self.stats.hit_count / total

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        self.stats.total_entries = len(self.cache)
        return self.stats

    def reset_stats(self) -> None:
        """Reset cache statistics."""
        self.stats = CacheStats()

    async def _save_to_disk_async(self) -> None:
        """Save cache to disk asynchronously."""
        try:
            cache_file = self.cache_dir / "recon_cache.json"

            # Convert cache entries to serializable format
            serializable = {}
            for key, entry in self.cache.items():
                serializable[key] = {
                    "key": entry.key,
                    "value": entry.value,
                    "created_at": entry.created_at.isoformat(),
                    "ttl": entry.ttl,
                    "hit_count": entry.hit_count,
                    "last_accessed": entry.last_accessed.isoformat() if entry.last_accessed else None
                }

            with open(cache_file, "w") as f:
                json.dump(serializable, f, default=str)

        except Exception as e:
            self.logger.warning(f"Failed to save cache to disk: {e}")

    def _load_from_disk(self) -> None:
        """Load cache from disk."""
        try:
            cache_file = self.cache_dir / "recon_cache.json"

            if not cache_file.exists():
                return

            with open(cache_file, "r") as f:
                serializable = json.load(f)

            # Restore cache entries
            for key, data in serializable.items():
                entry = CacheEntry(
                    key=data["key"],
                    value=data["value"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    ttl=data["ttl"],
                    hit_count=data["hit_count"],
                    last_accessed=datetime.fromisoformat(data["last_accessed"]) if data["last_accessed"] else None
                )

                # Only restore if not expired
                if not entry.is_expired():
                    self.cache[key] = entry

            self.stats.total_entries = len(self.cache)
            self.logger.info(f"Loaded {len(self.cache)} entries from disk")

        except Exception as e:
            self.logger.warning(f"Failed to load cache from disk: {e}")


# Global cache instance
_global_cache: Optional[ReconCache] = None


def get_global_cache(ttl: int = 3600) -> ReconCache:
    """Get or create global cache instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = ReconCache(ttl=ttl)
    return _global_cache


def reset_global_cache() -> None:
    """Reset global cache instance."""
    global _global_cache
    _global_cache = None
