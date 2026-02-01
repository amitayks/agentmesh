"""
Configuration management for AgentMesh.
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any

# Default security policy
DEFAULT_POLICY = {
    "accept_tiers": [1, 1.5, 2],
    "min_reputation": 0.3,
    "accepted_intents": [
        "travel", "commerce", "productivity", "research",
        "development", "communication", "creative", "marketplace"
    ],
    "rejected_intents": [],
    "blocklist": [],
    "allowlist": [],
    "strict_mode": False,
    "max_concurrent_sessions": 10,
    "rate_limit": {
        "knocks_per_minute": 30,
        "messages_per_minute": 100
    },
    "store_transcripts": True,
    "auto_reject_when_offline": False,
    "notify_owner": {
        "on_knock_from_unknown": False,
        "on_high_value_transaction": True,
        "on_error": True,
        "threshold_usd": 50
    }
}

# Production endpoints (Railway)
PRODUCTION_RELAY_URL = os.environ.get(
    "AGENTMESH_RELAY_URL",
    "wss://relay.agentmesh.online/v1/connect"
)
PRODUCTION_REGISTRY_URL = os.environ.get(
    "AGENTMESH_REGISTRY_URL",
    "https://agentmesh.online/v1"
)


@dataclass
class RateLimitConfig:
    knocks_per_minute: int = 30
    messages_per_minute: int = 100

    @classmethod
    def from_dict(cls, data: dict) -> "RateLimitConfig":
        return cls(**data)


@dataclass
class NotifyConfig:
    on_knock_from_unknown: bool = False
    on_high_value_transaction: bool = True
    on_error: bool = True
    threshold_usd: float = 50.0

    @classmethod
    def from_dict(cls, data: dict) -> "NotifyConfig":
        return cls(**data)


@dataclass
class Policy:
    """Security policy for incoming connections."""
    accept_tiers: List[float] = field(default_factory=lambda: [1, 1.5, 2])
    min_reputation: float = 0.3
    accepted_intents: List[str] = field(default_factory=list)
    rejected_intents: List[str] = field(default_factory=list)
    blocklist: List[str] = field(default_factory=list)
    allowlist: List[str] = field(default_factory=list)
    strict_mode: bool = False
    max_concurrent_sessions: int = 10
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    store_transcripts: bool = True
    auto_reject_when_offline: bool = False
    notify_owner: NotifyConfig = field(default_factory=NotifyConfig)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        """Load policy from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        """Create policy from dictionary."""
        rate_limit = RateLimitConfig.from_dict(data.get('rate_limit', {}))
        notify = NotifyConfig.from_dict(data.get('notify_owner', {}))

        return cls(
            accept_tiers=data.get('accept_tiers', [1, 1.5, 2]),
            min_reputation=data.get('min_reputation', 0.3),
            accepted_intents=data.get('accepted_intents', []),
            rejected_intents=data.get('rejected_intents', []),
            blocklist=data.get('blocklist', []),
            allowlist=data.get('allowlist', []),
            strict_mode=data.get('strict_mode', False),
            max_concurrent_sessions=data.get('max_concurrent_sessions', 10),
            rate_limit=rate_limit,
            store_transcripts=data.get('store_transcripts', True),
            auto_reject_when_offline=data.get('auto_reject_when_offline', False),
            notify_owner=notify,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'accept_tiers': self.accept_tiers,
            'min_reputation': self.min_reputation,
            'accepted_intents': self.accepted_intents,
            'rejected_intents': self.rejected_intents,
            'blocklist': self.blocklist,
            'allowlist': self.allowlist,
            'strict_mode': self.strict_mode,
            'max_concurrent_sessions': self.max_concurrent_sessions,
            'rate_limit': asdict(self.rate_limit),
            'store_transcripts': self.store_transcripts,
            'auto_reject_when_offline': self.auto_reject_when_offline,
            'notify_owner': asdict(self.notify_owner),
        }

    def save(self, path: Path) -> None:
        """Save policy to file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def is_allowlisted(self, amid: str) -> bool:
        """Check if an AMID is in the allowlist."""
        return amid in self.allowlist

    def is_blocklisted(self, amid: str) -> bool:
        """Check if an AMID is in the blocklist."""
        return amid in self.blocklist

    def accepts_tier(self, tier: float) -> bool:
        """Check if a tier is accepted by this policy."""
        return tier in self.accept_tiers

    def accepts_intent(self, intent: str) -> bool:
        """Check if an intent is accepted by this policy."""
        # Rejected intents take priority
        if intent in self.rejected_intents:
            return False
        # In strict mode, only explicitly accepted intents allowed
        if self.strict_mode:
            return intent in self.accepted_intents
        # Otherwise, accept if not rejected
        return True


# Default DHT bootstrap nodes
# Can be overridden via AGENTMESH_DHT_BOOTSTRAP environment variable
# Format: "host1:port1,host2:port2,host3:port3"
DEFAULT_DHT_BOOTSTRAP_NODES = [
    ("bootstrap1.agentmesh.online", 8468),
    ("bootstrap2.agentmesh.online", 8468),
    ("bootstrap3.agentmesh.online", 8468),
]

# Parse DHT bootstrap nodes from environment variable
_dht_env = os.environ.get("AGENTMESH_DHT_BOOTSTRAP")
if _dht_env:
    try:
        DEFAULT_DHT_BOOTSTRAP_NODES = []
        for node in _dht_env.split(","):
            host, port = node.strip().rsplit(":", 1)
            DEFAULT_DHT_BOOTSTRAP_NODES.append((host, int(port)))
    except ValueError:
        pass  # Keep defaults on parse error

# DHT Fallback Behavior:
# When DHT is unavailable (all bootstrap nodes unreachable):
# 1. Agent discovery falls back to registry-only mode
# 2. P2P connections fall back to relay-only mode
# 3. A warning is logged but operation continues
# 4. DHT reconnection is attempted periodically (every 5 minutes)
DHT_RECONNECT_INTERVAL_SECONDS = 300
DHT_CONNECTION_TIMEOUT_SECONDS = 10

# TURN server configuration for NAT traversal
# These are loaded from environment variables for security
DEFAULT_TURN_SERVERS = []

# Load TURN configuration from environment
_turn_url = os.environ.get("TURN_SERVER_URL")
_turn_username = os.environ.get("TURN_USERNAME")
_turn_credential = os.environ.get("TURN_CREDENTIAL")

if _turn_url and _turn_username and _turn_credential:
    DEFAULT_TURN_SERVERS.append({
        "url": _turn_url,
        "username": _turn_username,
        "credential": _turn_credential,
    })


@dataclass
class TurnServerConfig:
    """Configuration for a TURN server."""
    url: str
    username: str
    credential: str
    credential_type: str = "password"  # 'password' or 'oauth'
    expires_at: Optional[str] = None  # ISO8601 timestamp for time-limited credentials

    @classmethod
    def from_dict(cls, data: dict) -> "TurnServerConfig":
        return cls(
            url=data["url"],
            username=data["username"],
            credential=data["credential"],
            credential_type=data.get("credential_type", "password"),
            expires_at=data.get("expires_at"),
        )

    def to_dict(self) -> dict:
        result = {
            "url": self.url,
            "username": self.username,
            "credential": self.credential,
            "credential_type": self.credential_type,
        }
        if self.expires_at:
            result["expires_at"] = self.expires_at
        return result

    def is_expired(self) -> bool:
        """Check if time-limited credentials have expired."""
        if not self.expires_at:
            return False
        from datetime import datetime, timezone
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            return datetime.now(timezone.utc) >= expiry
        except (ValueError, AttributeError):
            return False


@dataclass
class Config:
    """AgentMesh client configuration."""
    relay_url: str = PRODUCTION_RELAY_URL
    registry_url: str = PRODUCTION_REGISTRY_URL
    stun_servers: List[str] = field(default_factory=lambda: [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
    ])
    # TURN servers for NAT traversal fallback (configured via env vars)
    turn_servers: List[Dict[str, Any]] = field(default_factory=lambda: DEFAULT_TURN_SERVERS.copy())
    turn_fallback_timeout: float = 5.0  # Seconds to wait for STUN before trying TURN
    enable_p2p: bool = True
    enable_store_forward: bool = True
    session_cache_ttl_hours: int = 24
    session_cache_max_entries: int = 1000
    key_rotation_days: int = 7
    dashboard_port: int = 7777
    log_level: str = "INFO"
    capabilities: List[str] = field(default_factory=list)
    # DHT configuration
    dht_participate: bool = True
    dht_bootstrap_nodes: List[tuple] = field(default_factory=lambda: DEFAULT_DHT_BOOTSTRAP_NODES.copy())
    dht_port: int = 8468
    dht_refresh_hours: int = 4
    dht_stale_hours: int = 24

    def get_turn_configs(self) -> List[TurnServerConfig]:
        """Get parsed TURN server configurations."""
        return [TurnServerConfig.from_dict(ts) for ts in self.turn_servers]

    def get_valid_turn_servers(self) -> List[TurnServerConfig]:
        """Get non-expired TURN server configurations."""
        return [ts for ts in self.get_turn_configs() if not ts.is_expired()]

    @classmethod
    def default(cls) -> "Config":
        """Create default configuration."""
        return cls()

    @classmethod
    def load(cls, path: Path) -> "Config":
        """Load configuration from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    def save(self, path: Path) -> None:
        """Save configuration to file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
