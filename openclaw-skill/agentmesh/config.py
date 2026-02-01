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
    "wss://relay.agentmesh.net/v1/connect"
)
PRODUCTION_REGISTRY_URL = os.environ.get(
    "AGENTMESH_REGISTRY_URL",
    "https://api.agentmesh.net/v1"
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


@dataclass
class Config:
    """AgentMesh client configuration."""
    relay_url: str = PRODUCTION_RELAY_URL
    registry_url: str = PRODUCTION_REGISTRY_URL
    stun_servers: List[str] = field(default_factory=lambda: [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
    ])
    enable_p2p: bool = True
    enable_store_forward: bool = True
    session_cache_ttl_hours: int = 24
    key_rotation_days: int = 7
    dashboard_port: int = 7777
    log_level: str = "INFO"
    capabilities: List[str] = field(default_factory=list)

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
