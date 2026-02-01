"""
Discovery layer for AgentMesh.
Handles agent registration and capability-based search.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

import aiohttp

from .identity import Identity

logger = logging.getLogger(__name__)


@dataclass
class AgentInfo:
    """Information about a discovered agent."""
    amid: str
    tier: str
    display_name: Optional[str]
    organization: Optional[str]
    signing_public_key: str
    exchange_public_key: str
    capabilities: List[str]
    relay_endpoint: str
    direct_endpoint: Optional[str]
    status: str
    reputation_score: float
    last_seen: datetime

    @classmethod
    def from_dict(cls, data: dict) -> "AgentInfo":
        return cls(
            amid=data['amid'],
            tier=data['tier'],
            display_name=data.get('display_name'),
            organization=data.get('organization'),
            signing_public_key=data['signing_public_key'],
            exchange_public_key=data['exchange_public_key'],
            capabilities=data.get('capabilities', []),
            relay_endpoint=data['relay_endpoint'],
            direct_endpoint=data.get('direct_endpoint'),
            status=data['status'],
            reputation_score=data.get('reputation_score', 0.5),
            last_seen=datetime.fromisoformat(data['last_seen']),
        )


class RegistryClient:
    """Client for the AgentMesh registry API."""

    def __init__(
        self,
        base_url: str = "https://api.agentmesh.net/v1",
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip('/')
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def register(
        self,
        identity: Identity,
        display_name: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        relay_endpoint: str = "wss://relay.agentmesh.net/v1/connect",
        direct_endpoint: Optional[str] = None,
        verification_token: Optional[str] = None,
    ) -> dict:
        """Register this agent with the registry."""
        timestamp, signature = identity.sign_timestamp()

        payload = {
            'amid': identity.amid,
            'signing_public_key': identity.signing_public_key_b64,
            'exchange_public_key': identity.exchange_public_key_b64,
            'display_name': display_name,
            'capabilities': capabilities or [],
            'relay_endpoint': relay_endpoint,
            'direct_endpoint': direct_endpoint,
            'verification_token': verification_token,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/register",
                    json=payload,
                ) as response:
                    data = await response.json()

                    if response.status == 201:
                        logger.info(f"Registered successfully: {identity.amid}")
                        return {'success': True, **data}
                    elif response.status == 409:
                        logger.info(f"Already registered: {identity.amid}")
                        return {'success': True, 'already_registered': True, **data}
                    else:
                        logger.error(f"Registration failed: {data}")
                        return {'success': False, 'error': data.get('error', 'Unknown error')}

        except aiohttp.ClientError as e:
            logger.error(f"Registry connection error: {e}")
            return {'success': False, 'error': str(e)}

    async def lookup(self, amid: str) -> Optional[AgentInfo]:
        """Look up an agent by AMID."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/registry/lookup",
                    params={'amid': amid},
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return AgentInfo.from_dict(data)
                    elif response.status == 404:
                        logger.info(f"Agent not found: {amid}")
                        return None
                    else:
                        logger.error(f"Lookup failed: {response.status}")
                        return None

        except aiohttp.ClientError as e:
            logger.error(f"Registry connection error: {e}")
            return None

    async def search(
        self,
        capability: str,
        tier_min: Optional[int] = None,
        reputation_min: Optional[float] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[List[AgentInfo], int]:
        """Search for agents by capability."""
        params = {
            'capability': capability,
            'limit': limit,
            'offset': offset,
        }

        if tier_min is not None:
            params['tier_min'] = tier_min
        if reputation_min is not None:
            params['reputation_min'] = reputation_min
        if status:
            params['status'] = status

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/registry/search",
                    params=params,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        agents = [AgentInfo.from_dict(a) for a in data['results']]
                        return agents, data['total']
                    else:
                        logger.error(f"Search failed: {response.status}")
                        return [], 0

        except aiohttp.ClientError as e:
            logger.error(f"Registry connection error: {e}")
            return [], 0

    async def update_status(
        self,
        identity: Identity,
        status: str,
    ) -> bool:
        """Update agent presence status."""
        timestamp, signature = identity.sign_timestamp()

        payload = {
            'amid': identity.amid,
            'status': status,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/status",
                    json=payload,
                ) as response:
                    return response.status == 200

        except aiohttp.ClientError as e:
            logger.error(f"Status update error: {e}")
            return False

    async def update_capabilities(
        self,
        identity: Identity,
        capabilities: List[str],
    ) -> bool:
        """Update agent capabilities."""
        timestamp, signature = identity.sign_timestamp()

        payload = {
            'amid': identity.amid,
            'capabilities': capabilities,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/capabilities",
                    json=payload,
                ) as response:
                    return response.status == 200

        except aiohttp.ClientError as e:
            logger.error(f"Capabilities update error: {e}")
            return False

    async def submit_reputation(
        self,
        identity: Identity,
        target_amid: str,
        session_id: str,
        score: float,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Submit reputation feedback for another agent."""
        if not 0.0 <= score <= 1.0:
            raise ValueError("Score must be between 0.0 and 1.0")

        timestamp, signature = identity.sign_timestamp()

        payload = {
            'target_amid': target_amid,
            'from_amid': identity.amid,
            'session_id': session_id,
            'score': score,
            'tags': tags,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/reputation",
                    json=payload,
                ) as response:
                    return response.status == 200

        except aiohttp.ClientError as e:
            logger.error(f"Reputation submission error: {e}")
            return False

    async def health_check(self) -> dict:
        """Check registry health."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/health") as response:
                    if response.status == 200:
                        return await response.json()
                    return {'status': 'unhealthy'}

        except aiohttp.ClientError:
            return {'status': 'unreachable'}
