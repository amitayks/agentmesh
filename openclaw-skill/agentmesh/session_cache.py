"""
Session caching for AgentMesh.
Caches successful session information to skip KNOCK handshake for trusted contacts.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Tuple
from collections import OrderedDict

logger = logging.getLogger(__name__)

# Cache configuration
AGENTMESH_DIR = Path.home() / ".agentmesh"
CACHE_FILE = AGENTMESH_DIR / "session_cache.json"
DEFAULT_TTL_HOURS = 24
DEFAULT_MAX_ENTRIES = 1000


@dataclass
class CachedSession:
    """A cached session entry."""
    our_amid: str
    peer_amid: str
    intent_category: str
    session_key: str  # Base64-encoded encrypted session key
    peer_exchange_key: str  # Base64-encoded peer's exchange public key
    created_at: datetime
    last_used: datetime
    expires_at: datetime
    use_count: int = 0

    def is_expired(self) -> bool:
        """Check if this cache entry has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> dict:
        return {
            'our_amid': self.our_amid,
            'peer_amid': self.peer_amid,
            'intent_category': self.intent_category,
            'session_key': self.session_key,
            'peer_exchange_key': self.peer_exchange_key,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'use_count': self.use_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CachedSession":
        return cls(
            our_amid=data['our_amid'],
            peer_amid=data['peer_amid'],
            intent_category=data['intent_category'],
            session_key=data['session_key'],
            peer_exchange_key=data['peer_exchange_key'],
            created_at=datetime.fromisoformat(data['created_at']),
            last_used=datetime.fromisoformat(data['last_used']),
            expires_at=datetime.fromisoformat(data['expires_at']),
            use_count=data.get('use_count', 0),
        )


class SessionCache:
    """
    LRU cache for session information.

    Allows skipping KNOCK handshake for subsequent interactions with
    the same peer and intent category.

    Cache key: (our_amid, peer_amid, intent_category)
    """

    def __init__(
        self,
        our_amid: str,
        ttl_hours: int = DEFAULT_TTL_HOURS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self.our_amid = our_amid
        self.ttl_hours = ttl_hours
        self.max_entries = max_entries
        self._cache: OrderedDict[str, CachedSession] = OrderedDict()
        self._load()

    def _make_key(self, peer_amid: str, intent_category: str) -> str:
        """Create cache key from components."""
        return f"{self.our_amid}:{peer_amid}:{intent_category}"

    def _load(self) -> None:
        """Load cache from disk."""
        if not CACHE_FILE.exists():
            return

        try:
            with open(CACHE_FILE, 'r') as f:
                data = json.load(f)

            for entry_data in data.get('entries', []):
                try:
                    entry = CachedSession.from_dict(entry_data)
                    # Skip expired entries
                    if not entry.is_expired() and entry.our_amid == self.our_amid:
                        key = self._make_key(entry.peer_amid, entry.intent_category)
                        self._cache[key] = entry
                except Exception as e:
                    logger.debug(f"Skipping invalid cache entry: {e}")

            logger.info(f"Loaded {len(self._cache)} cached sessions")

        except Exception as e:
            logger.warning(f"Failed to load session cache: {e}")

    def _save(self) -> None:
        """Save cache to disk."""
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

        entries = [entry.to_dict() for entry in self._cache.values()]
        data = {
            'version': 1,
            'entries': entries,
            'saved_at': datetime.now(timezone.utc).isoformat(),
        }

        try:
            with open(CACHE_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            CACHE_FILE.chmod(0o600)
        except Exception as e:
            logger.error(f"Failed to save session cache: {e}")

    def _evict_lru(self) -> None:
        """Evict least recently used entry if over capacity."""
        while len(self._cache) > self.max_entries:
            # OrderedDict: first item is least recently used
            self._cache.popitem(last=False)
            logger.debug("Evicted LRU cache entry")

    def _evict_expired(self) -> int:
        """Remove all expired entries. Returns count of evicted entries."""
        expired_keys = [
            key for key, entry in self._cache.items()
            if entry.is_expired()
        ]
        for key in expired_keys:
            del self._cache[key]
        return len(expired_keys)

    def get(
        self,
        peer_amid: str,
        intent_category: str,
    ) -> Optional[CachedSession]:
        """
        Look up a cached session.

        Returns the cached session if found and not expired, None otherwise.
        Updates last_used timestamp and moves to end of LRU.
        """
        key = self._make_key(peer_amid, intent_category)

        if key not in self._cache:
            return None

        entry = self._cache[key]

        # Check expiration
        if entry.is_expired():
            del self._cache[key]
            return None

        # Update last used and move to end (most recently used)
        entry.last_used = datetime.now(timezone.utc)
        entry.use_count += 1
        self._cache.move_to_end(key)

        logger.debug(f"Cache hit for {peer_amid}:{intent_category}")
        return entry

    def put(
        self,
        peer_amid: str,
        intent_category: str,
        session_key: str,
        peer_exchange_key: str,
        ttl_hours: Optional[int] = None,
    ) -> CachedSession:
        """
        Add or update a cached session.

        Returns the created cache entry.
        """
        now = datetime.now(timezone.utc)
        ttl = ttl_hours or self.ttl_hours
        expires_at = now + timedelta(hours=ttl)

        entry = CachedSession(
            our_amid=self.our_amid,
            peer_amid=peer_amid,
            intent_category=intent_category,
            session_key=session_key,
            peer_exchange_key=peer_exchange_key,
            created_at=now,
            last_used=now,
            expires_at=expires_at,
            use_count=0,
        )

        key = self._make_key(peer_amid, intent_category)
        self._cache[key] = entry
        self._cache.move_to_end(key)

        # Evict if necessary
        self._evict_lru()

        # Save to disk
        self._save()

        logger.debug(f"Cached session for {peer_amid}:{intent_category}")
        return entry

    def invalidate(self, peer_amid: Optional[str] = None) -> int:
        """
        Invalidate cache entries.

        If peer_amid is provided, only invalidate entries for that peer.
        Otherwise, invalidate all entries.

        Returns count of invalidated entries.
        """
        if peer_amid is None:
            count = len(self._cache)
            self._cache.clear()
        else:
            keys_to_remove = [
                key for key, entry in self._cache.items()
                if entry.peer_amid == peer_amid
            ]
            for key in keys_to_remove:
                del self._cache[key]
            count = len(keys_to_remove)

        if count > 0:
            self._save()
            logger.info(f"Invalidated {count} cache entries")

        return count

    def invalidate_all(self) -> int:
        """
        Clear all cache entries.
        Used when key rotation or policy change occurs.
        """
        return self.invalidate(None)

    def invalidate_for_intent(
        self,
        intent_category: str,
    ) -> int:
        """Invalidate all entries for a specific intent category."""
        keys_to_remove = [
            key for key, entry in self._cache.items()
            if entry.intent_category == intent_category
        ]
        for key in keys_to_remove:
            del self._cache[key]

        if keys_to_remove:
            self._save()
            logger.info(f"Invalidated {len(keys_to_remove)} entries for intent {intent_category}")

        return len(keys_to_remove)

    def cleanup(self) -> int:
        """
        Perform cache maintenance.
        Evicts expired entries and saves to disk.
        Returns count of evicted entries.
        """
        count = self._evict_expired()
        if count > 0:
            self._save()
            logger.info(f"Cleaned up {count} expired cache entries")
        return count

    def get_stats(self) -> dict:
        """Get cache statistics."""
        now = datetime.now(timezone.utc)
        entries = list(self._cache.values())

        return {
            'total_entries': len(entries),
            'max_entries': self.max_entries,
            'expired_entries': sum(1 for e in entries if e.is_expired()),
            'ttl_hours': self.ttl_hours,
            'total_uses': sum(e.use_count for e in entries),
            'unique_peers': len(set(e.peer_amid for e in entries)),
            'unique_intents': len(set(e.intent_category for e in entries)),
        }

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, key: Tuple[str, str]) -> bool:
        """Check if (peer_amid, intent_category) is in cache."""
        peer_amid, intent_category = key
        cache_key = self._make_key(peer_amid, intent_category)
        if cache_key not in self._cache:
            return False
        return not self._cache[cache_key].is_expired()
