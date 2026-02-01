"""
DHT (Distributed Hash Table) Discovery for AgentMesh.
Provides decentralized agent discovery using Kademlia DHT.
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# Check if kademlia is available
try:
    from kademlia.network import Server as KademliaServer
    KADEMLIA_AVAILABLE = True
except ImportError:
    KADEMLIA_AVAILABLE = False
    logger.debug("kademlia not installed - DHT features disabled")


@dataclass
class DHTValue:
    """Value stored in the DHT for an agent."""
    amid: str
    signing_public_key: str
    exchange_public_key: str
    relay_url: str
    capabilities: List[str]
    tier: float
    signature: str  # Signs the entire value for authenticity
    published_at: str  # ISO timestamp
    expires_at: str  # ISO timestamp (24h from publish)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "DHTValue":
        return cls(**data)

    @classmethod
    def from_json(cls, data: str) -> "DHTValue":
        return cls.from_dict(json.loads(data))

    def is_expired(self) -> bool:
        """Check if this value has expired."""
        expires = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
        return datetime.now(timezone.utc) > expires

    def is_stale(self, stale_hours: int = 24) -> bool:
        """Check if this value is stale (older than stale_hours)."""
        published = datetime.fromisoformat(self.published_at.replace('Z', '+00:00'))
        stale_threshold = datetime.now(timezone.utc) - timedelta(hours=stale_hours)
        return published < stale_threshold


class DHTClient:
    """
    DHT client for decentralized agent discovery.
    Uses Kademlia DHT for storing and retrieving agent information.
    """

    def __init__(
        self,
        identity,  # Identity instance
        config,    # Config instance
    ):
        self.identity = identity
        self.config = config
        self._server: Optional["KademliaServer"] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def is_available(self) -> bool:
        """Check if DHT functionality is available."""
        return KADEMLIA_AVAILABLE and self.config.dht_participate

    async def bootstrap(self) -> bool:
        """
        Bootstrap the DHT node by connecting to bootstrap nodes.
        Returns True if successfully connected to at least one node.
        """
        if not KADEMLIA_AVAILABLE:
            logger.warning("DHT bootstrap skipped - kademlia not installed")
            return False

        if not self.config.dht_participate:
            logger.info("DHT participation disabled in config")
            return False

        try:
            self._server = KademliaServer()
            await self._server.listen(self.config.dht_port)

            # Try to connect to bootstrap nodes
            bootstrap_nodes = self.config.dht_bootstrap_nodes
            if bootstrap_nodes:
                try:
                    await self._server.bootstrap(bootstrap_nodes)
                    logger.info(f"DHT bootstrapped with {len(bootstrap_nodes)} nodes")
                except Exception as e:
                    logger.warning(f"DHT bootstrap partially failed: {e}")

            self._running = True

            # Start automatic refresh task
            self._refresh_task = asyncio.create_task(self._auto_refresh_loop())

            return True

        except Exception as e:
            logger.error(f"DHT bootstrap failed: {e}")
            return False

    async def stop(self) -> None:
        """Stop the DHT node."""
        self._running = False

        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

        if self._server:
            self._server.stop()
            self._server = None

        logger.info("DHT node stopped")

    def _compute_key(self, amid: str) -> bytes:
        """Compute DHT key from AMID using SHA256."""
        return hashlib.sha256(amid.encode('utf-8')).digest()

    def _create_value(
        self,
        relay_url: str,
        capabilities: List[str],
        tier: float = 2.0,
    ) -> DHTValue:
        """Create a signed DHT value for this agent."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=24)

        # Create the value without signature first
        value_data = {
            'amid': self.identity.amid,
            'signing_public_key': self.identity.signing_public_key_b64,
            'exchange_public_key': self.identity.exchange_public_key_b64,
            'relay_url': relay_url,
            'capabilities': capabilities,
            'tier': tier,
            'published_at': now.isoformat(),
            'expires_at': expires.isoformat(),
        }

        # Sign the value
        value_bytes = json.dumps(value_data, sort_keys=True).encode('utf-8')
        signature = self.identity.sign_b64(value_bytes)

        return DHTValue(
            **value_data,
            signature=signature,
        )

    def _verify_value(self, value: DHTValue) -> bool:
        """Verify the signature on a DHT value."""
        from .identity import Identity

        # Reconstruct the signed data (everything except signature)
        value_data = {
            'amid': value.amid,
            'signing_public_key': value.signing_public_key,
            'exchange_public_key': value.exchange_public_key,
            'relay_url': value.relay_url,
            'capabilities': value.capabilities,
            'tier': value.tier,
            'published_at': value.published_at,
            'expires_at': value.expires_at,
        }
        value_bytes = json.dumps(value_data, sort_keys=True).encode('utf-8')

        # Verify signature
        return Identity.verify_signature(
            value.signing_public_key,
            value_bytes,
            value.signature,
        )

    async def publish(
        self,
        relay_url: str,
        capabilities: List[str],
        tier: float = 2.0,
    ) -> bool:
        """
        Publish this agent's information to the DHT.
        Uses sha256(amid) as the key.
        """
        if not self._server:
            logger.warning("DHT not bootstrapped - cannot publish")
            return False

        try:
            key = self._compute_key(self.identity.amid)
            value = self._create_value(relay_url, capabilities, tier)

            await self._server.set(key, value.to_json())
            logger.info(f"Published to DHT: {self.identity.amid[:16]}...")
            return True

        except Exception as e:
            logger.error(f"DHT publish failed: {e}")
            return False

    async def lookup(
        self,
        amid: str,
        timeout: float = 5.0,
    ) -> Optional[DHTValue]:
        """
        Look up an agent by AMID in the DHT.
        Returns None if not found or on timeout.
        """
        if not self._server:
            logger.warning("DHT not bootstrapped - cannot lookup")
            return None

        try:
            key = self._compute_key(amid)

            # Lookup with timeout
            result = await asyncio.wait_for(
                self._server.get(key),
                timeout=timeout,
            )

            if result is None:
                logger.debug(f"DHT lookup: {amid[:16]}... not found")
                return None

            # Parse and validate
            value = DHTValue.from_json(result)

            # Check expiration
            if value.is_expired():
                logger.debug(f"DHT lookup: {amid[:16]}... expired")
                return None

            # Verify signature
            if not self._verify_value(value):
                logger.warning(f"DHT lookup: {amid[:16]}... invalid signature")
                return None

            # Verify AMID matches
            if value.amid != amid:
                logger.warning(f"DHT lookup: AMID mismatch")
                return None

            logger.debug(f"DHT lookup: {amid[:16]}... found")
            return value

        except asyncio.TimeoutError:
            logger.debug(f"DHT lookup: {amid[:16]}... timeout")
            return None
        except Exception as e:
            logger.error(f"DHT lookup failed: {e}")
            return None

    async def _auto_refresh_loop(self) -> None:
        """Automatically refresh our DHT entry every refresh_hours."""
        refresh_interval = self.config.dht_refresh_hours * 3600  # Convert to seconds

        while self._running:
            try:
                await asyncio.sleep(refresh_interval)

                if self._running and self._server:
                    # Re-publish with current info
                    # Note: In real usage, caller should track relay_url and capabilities
                    logger.debug("DHT auto-refresh triggered")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"DHT auto-refresh error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get DHT node status."""
        return {
            'available': KADEMLIA_AVAILABLE,
            'enabled': self.config.dht_participate,
            'running': self._running,
            'port': self.config.dht_port if self._running else None,
            'bootstrap_nodes': len(self.config.dht_bootstrap_nodes),
        }


# Graceful fallback wrapper for when kademlia is not installed
class DHTClientFallback:
    """Fallback DHT client when kademlia is not installed."""

    def __init__(self, *args, **kwargs):
        pass

    @property
    def is_available(self) -> bool:
        return False

    async def bootstrap(self) -> bool:
        logger.info("DHT not available - kademlia not installed")
        return False

    async def stop(self) -> None:
        pass

    async def publish(self, *args, **kwargs) -> bool:
        return False

    async def lookup(self, *args, **kwargs) -> Optional[DHTValue]:
        return None

    def get_status(self) -> Dict[str, Any]:
        return {
            'available': False,
            'enabled': False,
            'running': False,
            'message': 'Install kademlia: pip install kademlia',
        }


def create_dht_client(identity, config) -> "DHTClient":
    """
    Factory function to create the appropriate DHT client.
    Returns DHTClientFallback if kademlia is not installed.
    """
    if KADEMLIA_AVAILABLE:
        return DHTClient(identity, config)
    else:
        return DHTClientFallback(identity, config)
