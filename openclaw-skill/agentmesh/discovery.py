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

    async def upload_prekeys(
        self,
        identity: Identity,
        signed_prekey: str,
        signed_prekey_signature: str,
        signed_prekey_id: int,
        one_time_prekeys: List[Dict[str, Any]],
    ) -> bool:
        """Upload X3DH prekeys to registry."""
        timestamp, signature = identity.sign_timestamp()

        payload = {
            'amid': identity.amid,
            'signed_prekey': signed_prekey,
            'signed_prekey_signature': signed_prekey_signature,
            'signed_prekey_id': signed_prekey_id,
            'one_time_prekeys': one_time_prekeys,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/prekeys",
                    json=payload,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(
                            f"Uploaded prekeys: signed_prekey_id={signed_prekey_id}, "
                            f"one_time_prekeys={data.get('one_time_prekeys_stored', 0)}"
                        )
                        return True
                    else:
                        data = await response.json()
                        logger.error(f"Prekey upload failed: {data}")
                        return False

        except aiohttp.ClientError as e:
            logger.error(f"Prekey upload error: {e}")
            return False

    async def get_prekeys(self, amid: str) -> Optional[Dict[str, Any]]:
        """
        Fetch prekeys for an agent (for X3DH key exchange).
        Note: This consumes one one-time prekey from the target agent.
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/registry/prekeys/{amid}",
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 404:
                        logger.warning(f"No prekeys found for {amid}")
                        return None
                    else:
                        logger.error(f"Prekey fetch failed: {response.status}")
                        return None

        except aiohttp.ClientError as e:
            logger.error(f"Prekey fetch error: {e}")
            return None

    async def get_oauth_providers(self) -> List[Dict[str, Any]]:
        """Get available OAuth providers for tier verification."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/auth/oauth/providers",
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('providers', [])
                    else:
                        logger.error(f"Failed to get OAuth providers: {response.status}")
                        return []

        except aiohttp.ClientError as e:
            logger.error(f"OAuth providers error: {e}")
            return []

    async def start_oauth_verification(
        self,
        identity: Identity,
        provider: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Start OAuth verification flow for tier upgrade.

        Args:
            identity: The identity to verify
            provider: OAuth provider ('github' or 'google')

        Returns:
            Dict with 'authorization_url' and 'state' if successful, None otherwise
        """
        timestamp, signature = identity.sign_timestamp()

        payload = {
            'amid': identity.amid,
            'provider': provider,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/auth/oauth/authorize",
                    json=payload,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"OAuth flow started for {identity.amid} via {provider}")
                        return data
                    else:
                        data = await response.json()
                        logger.error(f"OAuth authorization failed: {data}")
                        return None

        except aiohttp.ClientError as e:
            logger.error(f"OAuth authorization error: {e}")
            return None

    async def get_verification_status(
        self,
        amid: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Get verification status for an agent.

        Returns verification info including provider, verified_at, and certificate.
        """
        agent_info = await self.lookup(amid)
        if not agent_info:
            return None

        # The tier indicates verification status
        return {
            'amid': amid,
            'tier': agent_info.tier,
            'is_verified': agent_info.tier in ['verified', 'organization'],
        }

    async def check_revocation(self, amid: str) -> Dict[str, Any]:
        """
        Check if an agent's certificate has been revoked.

        Returns:
            Dict with 'revoked' boolean and optional 'revocation' details
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/registry/revocation",
                    params={'amid': amid},
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Revocation check failed: {response.status}")
                        return {'revoked': False, 'error': 'Check failed'}

        except aiohttp.ClientError as e:
            logger.error(f"Revocation check error: {e}")
            return {'revoked': False, 'error': str(e)}

    async def bulk_check_revocation(self, amids: List[str]) -> Dict[str, Any]:
        """
        Check revocation status for multiple agents at once.

        Args:
            amids: List of AMIDs to check (max 100)

        Returns:
            Dict with revocation status for each AMID
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/revocations/bulk",
                    json={'amids': amids},
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Bulk revocation check failed: {response.status}")
                        return {'revocations': [], 'error': 'Check failed'}

        except aiohttp.ClientError as e:
            logger.error(f"Bulk revocation check error: {e}")
            return {'revocations': [], 'error': str(e)}

    async def revoke_agent(
        self,
        identity: Identity,
        target_amid: str,
        reason: str = "admin_request",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Revoke an agent's certificate.

        Args:
            identity: The revoker's identity
            target_amid: AMID of the agent to revoke
            reason: Revocation reason (key_compromise, policy_violation, etc.)
            notes: Optional notes about the revocation

        Returns:
            Dict with success status and revocation_id if successful
        """
        timestamp, signature = identity.sign_timestamp()

        payload = {
            'amid': target_amid,
            'reason': reason,
            'notes': notes,
            'revoker_amid': identity.amid,
            'timestamp': timestamp.isoformat(),
            'signature': signature,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.base_url}/registry/revoke",
                    json=payload,
                ) as response:
                    data = await response.json()
                    if response.status == 200:
                        logger.info(f"Revoked agent {target_amid}")
                        return data
                    else:
                        logger.error(f"Revocation failed: {data}")
                        return {'success': False, 'error': data.get('error', 'Unknown error')}

        except aiohttp.ClientError as e:
            logger.error(f"Revocation error: {e}")
            return {'success': False, 'error': str(e)}
