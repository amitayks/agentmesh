"""
High-level AgentMesh client for OpenClaw agents.
"""

import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable

from .identity import Identity
from .config import Config, Policy
from .transport import RelayTransport
from .discovery import RegistryClient, AgentInfo
from .session import (
    SessionManager, Session, SessionState,
    Intent, SessionType, KnockMessage
)
from .encryption import E2EEncryption
from .audit import AuditLog
from .session_cache import SessionCache

logger = logging.getLogger(__name__)

AGENTMESH_DIR = Path.home() / ".agentmesh"


class AgentMeshClient:
    """
    Main client for interacting with the AgentMesh network.

    Usage:
        client = AgentMeshClient()
        await client.connect()

        # Search for agents
        agents = await client.search("travel/flights")

        # Send a message
        response = await client.send(
            to="5Kd3...",
            intent="travel/flights",
            message={"origin": "TLV", "destination": "BER"}
        )
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        policy_path: Optional[Path] = None,
    ):
        # Load or create identity
        self.identity = self._load_identity()

        # Load configuration
        config_path = config_path or AGENTMESH_DIR / "config.json"
        if config_path.exists():
            self.config = Config.load(config_path)
        else:
            self.config = Config.default()

        # Load policy
        policy_path = policy_path or AGENTMESH_DIR / "policy.json"
        if policy_path.exists():
            self.policy = Policy.load(policy_path)
        else:
            self.policy = Policy()

        # Initialize components
        self.transport = RelayTransport(
            self.identity,
            self.config.relay_url,
            self.config.enable_p2p,
        )
        self.registry = RegistryClient(self.config.registry_url)
        self.session_manager = SessionManager(self.identity, self.policy)
        self.encryption = E2EEncryption(self.identity.exchange_private_key)
        self.audit = AuditLog()

        # Session cache for skipping KNOCK with trusted contacts
        self._session_cache = SessionCache(
            our_amid=self.identity.amid,
            ttl_hours=getattr(self.config, 'session_cache_ttl_hours', 24),
            max_entries=getattr(self.config, 'session_cache_max_entries', 1000),
        )

        # Message handlers
        self._message_handlers: Dict[str, Callable] = {}
        self._pending_responses: Dict[str, asyncio.Future] = {}

        # Circuit breaker state
        self._paused_for_new = False  # When True, reject all incoming KNOCKs

        # Setup internal handlers
        self._setup_handlers()

    def _load_identity(self) -> Identity:
        """Load or generate identity."""
        identity_path = AGENTMESH_DIR / "keys" / "identity.json"

        if identity_path.exists():
            return Identity.load(identity_path)
        else:
            # First run - generate identity
            identity = Identity.generate()
            identity.save(identity_path)
            return identity

    def _setup_handlers(self) -> None:
        """Setup internal message handlers."""
        self.transport.on_message('receive', self._handle_receive)
        self.transport.on_message('presence_response', self._handle_presence_response)
        self.transport.on_message('ice_offer', self._handle_ice_offer)
        self.transport.on_message('error', self._handle_error)

    @property
    def is_connected(self) -> bool:
        return self.transport.is_connected

    @property
    def amid(self) -> str:
        return self.identity.amid

    async def connect(self) -> bool:
        """Connect to the AgentMesh network."""
        logger.info(f"Connecting as {self.amid}")

        # Connect to relay
        if not await self.transport.connect():
            logger.error("Failed to connect to relay")
            return False

        # Update status in registry
        await self.registry.update_status(self.identity, "online")

        # Log audit event
        self.audit.log_event("connected", {
            'amid': self.amid,
            'relay': self.config.relay_url,
        })

        return True

    async def disconnect(self) -> None:
        """Disconnect from the network."""
        # Update status
        await self.registry.update_status(self.identity, "offline")

        # Disconnect from relay
        await self.transport.disconnect()

        # Log audit event
        self.audit.log_event("disconnected", {'amid': self.amid})

    async def search(
        self,
        capability: str,
        tier_min: Optional[int] = None,
        reputation_min: Optional[float] = None,
        online_only: bool = False,
    ) -> List[AgentInfo]:
        """Search for agents by capability."""
        status = "online" if online_only else None

        agents, total = await self.registry.search(
            capability=capability,
            tier_min=tier_min,
            reputation_min=reputation_min,
            status=status,
        )

        logger.info(f"Found {len(agents)} agents for capability '{capability}'")
        return agents

    async def lookup(self, amid: str) -> Optional[AgentInfo]:
        """Look up an agent by AMID."""
        return await self.registry.lookup(amid)

    async def send(
        self,
        to: str,
        intent: str,
        message: Dict[str, Any],
        session_type: SessionType = SessionType.REQUEST_RESPONSE,
        timeout: float = 30.0,
        skip_cache: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Send a message to another agent and wait for response.

        Args:
            to: Target agent's AMID
            intent: Intent category (e.g., "travel/flights")
            message: The message payload
            session_type: Type of session
            timeout: Response timeout in seconds
            skip_cache: If True, always perform KNOCK even if session is cached

        Returns:
            Response payload or None if failed
        """
        import base64
        import uuid

        if not self.is_connected:
            logger.error("Not connected to network")
            return None

        # Parse intent
        parts = intent.split('/')
        intent_obj = Intent(
            category=parts[0],
            subcategory=parts[1] if len(parts) > 1 else None,
            action=parts[2] if len(parts) > 2 else None,
        )

        # Get peer's public key
        peer_info = await self.registry.lookup(to)
        if not peer_info:
            logger.error(f"Agent not found: {to}")
            return None

        peer_public_key = base64.b64decode(peer_info.exchange_public_key)
        session_id = None
        used_cache = False

        # Check session cache for existing session with this peer and intent
        if not skip_cache:
            cached = self._session_cache.get(to, intent_obj.category)
            if cached:
                logger.debug(f"Using cached session for {to}:{intent_obj.category}")
                session_id = str(uuid.uuid4())  # New session ID, but reuse trust

                # Establish session with cached keys
                self.encryption.establish_session(
                    session_id=session_id,
                    peer_amid=to,
                    peer_public_key=base64.b64decode(cached.peer_exchange_key),
                )

                self.audit.log_event("session_cache_hit", {
                    'to': to,
                    'intent': intent,
                    'use_count': cached.use_count,
                })
                used_cache = True

        # If no cached session, perform KNOCK handshake
        if not used_cache:
            # Create KNOCK
            knock = self.session_manager.create_knock(
                to_amid=to,
                intent=intent_obj,
                session_type=session_type,
            )

            # Log knock
            self.audit.log_event("knock_sent", {
                'to': to,
                'intent': intent,
            })

            # Send KNOCK
            knock_payload = json.dumps(knock.to_dict())
            await self.transport.send(
                to=to,
                encrypted_payload=knock_payload,  # KNOCK is not encrypted
                message_type='knock',
            )

            # Wait for ACCEPT/REJECT
            response_future = asyncio.get_event_loop().create_future()
            response_key = f"knock_{to}"
            self._pending_responses[response_key] = response_future

            try:
                knock_response = await asyncio.wait_for(
                    response_future,
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"KNOCK timeout for {to}")
                del self._pending_responses[response_key]
                return None

            if knock_response.get('type') == 'reject':
                logger.info(f"KNOCK rejected by {to}: {knock_response.get('reason')}")
                self.audit.log_event("knock_rejected", {
                    'by': to,
                    'reason': knock_response.get('reason'),
                })
                return None

            # KNOCK accepted - establish encrypted session
            session_id = knock_response.get('session_id')
            session_key_b64 = knock_response.get('session_key')

            self.encryption.establish_session(
                session_id=session_id,
                peer_amid=to,
                peer_public_key=peer_public_key,
            )

            # Cache the session for future use
            self._session_cache.put(
                peer_amid=to,
                intent_category=intent_obj.category,
                session_key=session_key_b64,
                peer_exchange_key=peer_info.exchange_public_key,
            )
            logger.debug(f"Cached session for {to}:{intent_obj.category}")

        # Encrypt and send the actual message
        encrypted_msg = self.encryption.encrypt_message(session_id, {
            'type': 'request',
            'intent': intent_obj.to_dict(),
            'parameters': message,
        })

        await self.transport.send(
            to=to,
            encrypted_payload=encrypted_msg,
            message_type='message',
        )

        # Wait for response
        response_future = asyncio.get_event_loop().create_future()
        self._pending_responses[session_id] = response_future

        try:
            response = await asyncio.wait_for(
                response_future,
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Response timeout from {to}")
            del self._pending_responses[session_id]
            return None

        # Log success
        self.audit.log_event("message_exchanged", {
            'with': to,
            'session_id': session_id,
            'used_cache': used_cache,
        })

        return response

    async def _handle_receive(self, data: dict) -> None:
        """Handle incoming messages from relay."""
        from_amid = data.get('from')
        msg_type = data.get('message_type')
        encrypted_payload = data.get('encrypted_payload')

        logger.debug(f"Received {msg_type} from {from_amid}")

        if msg_type == 'knock':
            await self._handle_knock(from_amid, encrypted_payload)
        elif msg_type == 'accept':
            await self._handle_accept(from_amid, encrypted_payload)
        elif msg_type == 'reject':
            await self._handle_reject(from_amid, encrypted_payload)
        elif msg_type == 'message':
            await self._handle_message(from_amid, encrypted_payload)
        elif msg_type == 'close':
            self._handle_close(from_amid, encrypted_payload)

    async def _handle_knock(self, from_amid: str, payload: str) -> None:
        """Handle incoming KNOCK request."""
        try:
            # Check if we're paused (circuit breaker)
            if self._paused_for_new:
                logger.info(f"KNOCK rejected (paused): {from_amid}")
                self.audit.log_event("knock_rejected_paused", {'from': from_amid})
                reject_msg = json.dumps({
                    'type': 'reject',
                    'reason': 'paused',
                    'human_readable': 'Agent is not accepting new connections',
                })
                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=reject_msg,
                    message_type='reject',
                )
                return

            # Check if sender is blocklisted
            if self.policy.is_blocklisted(from_amid):
                logger.info(f"KNOCK rejected (blocklisted): {from_amid}")
                self.audit.log_event("knock_rejected_blocklisted", {'from': from_amid})
                reject_msg = json.dumps({
                    'type': 'reject',
                    'reason': 'blocklisted',
                    'human_readable': 'Sender is blocklisted',
                })
                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=reject_msg,
                    message_type='reject',
                )
                return

            knock_data = json.loads(payload)
            knock = KnockMessage.from_dict(knock_data)

            # Verify KNOCK signature by looking up sender's public key
            peer_info = await self.registry.lookup(from_amid)
            if not peer_info:
                logger.warning(f"KNOCK rejected: could not lookup sender {from_amid}")
                reject_msg = json.dumps({
                    'type': 'reject',
                    'reason': 'sender_not_found',
                    'human_readable': f"Sender {from_amid} not found in registry",
                })
                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=reject_msg,
                    message_type='reject',
                )
                return

            # Verify the signature
            knock_content = {
                'from': knock.from_amid,
                'to': self.identity.amid,
                'intent': knock.intent.to_dict(),
                'timestamp': knock.timestamp.isoformat(),
            }
            if not Identity.verify_signature(
                peer_info.signing_public_key,
                json.dumps(knock_content).encode(),
                knock.signature
            ):
                logger.warning(f"KNOCK rejected: invalid signature from {from_amid}")
                self.audit.log_event("knock_rejected", {
                    'from': from_amid,
                    'reason': 'invalid_signature',
                })
                reject_msg = json.dumps({
                    'type': 'reject',
                    'reason': 'invalid_signature',
                    'human_readable': 'KNOCK signature verification failed',
                })
                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=reject_msg,
                    message_type='reject',
                )
                return

            logger.debug(f"KNOCK signature verified for {from_amid}")

            # Evaluate the KNOCK
            accepted, rejection_reason = self.session_manager.evaluate_knock(knock)

            self.audit.log_event("knock_received", {
                'from': from_amid,
                'intent': knock.intent.category,
                'accepted': accepted,
            })

            if accepted:
                # Generate session key
                import uuid
                import base64
                from nacl.utils import random

                session_id = str(uuid.uuid4())
                session_key = base64.b64encode(random(32)).decode()
                timestamp = datetime.now(timezone.utc)

                # Accept the session
                self.session_manager.accept_session(knock, session_key)

                # Sign the accept message
                accept_content = {
                    'session_id': session_id,
                    'from': self.identity.amid,
                    'to': from_amid,
                    'timestamp': timestamp.isoformat(),
                }
                accept_signature = self.identity.sign_b64(json.dumps(accept_content).encode())

                # Send ACCEPT
                accept_msg = json.dumps({
                    'type': 'accept',
                    'session_id': session_id,
                    'session_key': session_key,
                    'capabilities': self.config.capabilities,
                    'constraints': {
                        'max_message_size_bytes': 65536,
                        'max_messages': 20,
                        'ttl_seconds': 300,
                    },
                    'timestamp': timestamp.isoformat(),
                    'signature': accept_signature,
                })

                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=accept_msg,
                    message_type='accept',
                )
            else:
                # Sign the reject message
                reject_timestamp = datetime.now(timezone.utc)
                reject_content = {
                    'reason': rejection_reason,
                    'from': self.identity.amid,
                    'to': from_amid,
                    'timestamp': reject_timestamp.isoformat(),
                }
                reject_signature = self.identity.sign_b64(json.dumps(reject_content).encode())

                # Send REJECT
                reject_msg = json.dumps({
                    'type': 'reject',
                    'reason': rejection_reason,
                    'human_readable': f"Connection rejected: {rejection_reason}",
                    'timestamp': reject_timestamp.isoformat(),
                    'signature': reject_signature,
                })

                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=reject_msg,
                    message_type='reject',
                )

        except Exception as e:
            logger.error(f"Error handling KNOCK: {e}")

    async def _handle_accept(self, from_amid: str, payload: str) -> None:
        """Handle KNOCK acceptance with signature verification."""
        try:
            data = json.loads(payload)
            response_key = f"knock_{from_amid}"

            # Verify ACCEPT signature
            if 'signature' in data and 'timestamp' in data:
                peer_info = await self.registry.lookup(from_amid)
                if peer_info:
                    accept_content = {
                        'session_id': data.get('session_id'),
                        'from': from_amid,
                        'to': self.identity.amid,
                        'timestamp': data.get('timestamp'),
                    }
                    if not Identity.verify_signature(
                        peer_info.signing_public_key,
                        json.dumps(accept_content).encode(),
                        data['signature']
                    ):
                        logger.warning(f"ACCEPT signature verification failed from {from_amid}")
                        self.audit.log_event("accept_invalid_signature", {'from': from_amid})
                        # Still process but log the failure for monitoring
                    else:
                        logger.debug(f"ACCEPT signature verified from {from_amid}")
                else:
                    logger.warning(f"Could not lookup peer {from_amid} to verify ACCEPT signature")

            if response_key in self._pending_responses:
                self._pending_responses[response_key].set_result(data)
                del self._pending_responses[response_key]

        except Exception as e:
            logger.error(f"Error handling ACCEPT: {e}")

    async def _handle_reject(self, from_amid: str, payload: str) -> None:
        """Handle KNOCK rejection with signature verification."""
        try:
            data = json.loads(payload)
            response_key = f"knock_{from_amid}"

            # Verify REJECT signature if present
            if 'signature' in data and 'timestamp' in data:
                peer_info = await self.registry.lookup(from_amid)
                if peer_info:
                    reject_content = {
                        'reason': data.get('reason'),
                        'from': from_amid,
                        'to': self.identity.amid,
                        'timestamp': data.get('timestamp'),
                    }
                    if not Identity.verify_signature(
                        peer_info.signing_public_key,
                        json.dumps(reject_content).encode(),
                        data['signature']
                    ):
                        logger.warning(f"REJECT signature verification failed from {from_amid}")
                    else:
                        logger.debug(f"REJECT signature verified from {from_amid}")

            if response_key in self._pending_responses:
                self._pending_responses[response_key].set_result(data)
                del self._pending_responses[response_key]

        except Exception as e:
            logger.error(f"Error handling REJECT: {e}")

    async def _handle_message(self, from_amid: str, payload: str) -> None:
        """Handle an encrypted message."""
        # Find the session for this peer
        session_id = None
        for sid, session in self.session_manager.sessions.items():
            if session.initiator_amid == from_amid or session.receiver_amid == from_amid:
                session_id = sid
                break

        if not session_id:
            logger.warning(f"No session found for message from {from_amid}")
            return

        # Decrypt message
        message = self.encryption.decrypt_message(session_id, payload)
        if not message:
            logger.error(f"Failed to decrypt message from {from_amid}")
            return

        # If this is a response to a pending request
        if session_id in self._pending_responses:
            self._pending_responses[session_id].set_result(message)
            del self._pending_responses[session_id]
        else:
            # Call registered handler
            if 'message' in self._message_handlers:
                await self._message_handlers['message'](from_amid, message)

    def _handle_close(self, from_amid: str, payload: str) -> None:
        """Handle session close."""
        try:
            data = json.loads(payload)
            session_id = data.get('session_id')

            if session_id:
                self.session_manager.close_session(session_id)
                self.encryption.close_session(session_id)

        except Exception as e:
            logger.error(f"Error handling CLOSE: {e}")

    async def _handle_presence_response(self, data: dict) -> None:
        """Handle presence query response."""
        logger.debug(f"Presence response: {data}")

    async def _handle_ice_offer(self, data: dict) -> None:
        """Handle ICE offer for P2P upgrade."""
        logger.debug(f"ICE offer received: {data}")
        # P2P upgrade logic would go here

    async def _handle_error(self, data: dict) -> None:
        """Handle error messages from relay."""
        logger.error(f"Relay error: {data}")

    def on_message(self, handler: Callable) -> None:
        """Register a handler for incoming messages."""
        self._message_handlers['message'] = handler

    def get_status(self) -> dict:
        """Get current client status."""
        return {
            'connected': self.is_connected,
            'amid': self.amid,
            'active_sessions': len(self.session_manager.sessions),
            'relay': self.config.relay_url,
            'session_cache': self._session_cache.get_stats(),
        }

    def clear_session_cache(self) -> int:
        """
        Clear all cached sessions.
        Call this when policy changes or key rotation occurs.
        Returns the number of cleared entries.
        """
        count = self._session_cache.invalidate_all()
        self.audit.log_event("session_cache_cleared", {'entries_cleared': count})
        return count

    def invalidate_peer_sessions(self, peer_amid: str) -> int:
        """
        Invalidate cached sessions for a specific peer.
        Call this when blocking a peer or when they rotate keys.
        Returns the number of invalidated entries.
        """
        count = self._session_cache.invalidate(peer_amid)
        if count > 0:
            self.audit.log_event("peer_sessions_invalidated", {
                'peer': peer_amid,
                'entries_invalidated': count,
            })
        return count

    def invalidate_intent_sessions(self, intent_category: str) -> int:
        """
        Invalidate cached sessions for a specific intent category.
        Call this when policy for that intent changes.
        Returns the number of invalidated entries.
        """
        count = self._session_cache.invalidate_for_intent(intent_category)
        if count > 0:
            self.audit.log_event("intent_sessions_invalidated", {
                'intent': intent_category,
                'entries_invalidated': count,
            })
        return count

    def on_key_rotation(self) -> None:
        """
        Handle key rotation event.
        Invalidates all cached sessions since keys have changed.
        """
        count = self.clear_session_cache()
        logger.info(f"Key rotation: cleared {count} cached sessions")

    def on_policy_change(self) -> None:
        """
        Handle policy change event.
        Invalidates all cached sessions since policy has changed.
        """
        count = self.clear_session_cache()
        logger.info(f"Policy change: cleared {count} cached sessions")

    def cleanup_session_cache(self) -> int:
        """
        Perform cache maintenance.
        Removes expired entries. Call periodically for housekeeping.
        Returns the number of cleaned entries.
        """
        return self._session_cache.cleanup()

    async def send_optimistic(
        self,
        to: str,
        intent: str,
        message: Dict[str, Any],
        timeout: float = 30.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Send a message optimistically to an allowlisted contact.

        For contacts in the allowlist with cached sessions, sends immediately
        without waiting for KNOCK. Falls back to regular send if needed.

        Args:
            to: Target agent's AMID (must be in allowlist)
            intent: Intent category
            message: The message payload
            timeout: Response timeout in seconds

        Returns:
            Response payload or None if failed
        """
        # Check if peer is allowlisted
        if not self.policy.is_allowlisted(to):
            logger.debug(f"Peer {to} not in allowlist, using regular send")
            return await self.send(to, intent, message, timeout=timeout)

        # Parse intent
        parts = intent.split('/')
        intent_category = parts[0]

        # Check if we have a cached session
        cached = self._session_cache.get(to, intent_category)
        if not cached:
            logger.debug(f"No cached session for allowlisted peer {to}, using regular send")
            return await self.send(to, intent, message, timeout=timeout)

        import base64
        import uuid

        # Use cached session for optimistic send
        session_id = str(uuid.uuid4())
        intent_obj = Intent(
            category=parts[0],
            subcategory=parts[1] if len(parts) > 1 else None,
            action=parts[2] if len(parts) > 2 else None,
        )

        # Establish session with cached keys
        self.encryption.establish_session(
            session_id=session_id,
            peer_amid=to,
            peer_public_key=base64.b64decode(cached.peer_exchange_key),
        )

        # Encrypt and send immediately
        encrypted_msg = self.encryption.encrypt_message(session_id, {
            'type': 'request',
            'intent': intent_obj.to_dict(),
            'parameters': message,
            'optimistic': True,  # Mark as optimistic send
        })

        await self.transport.send(
            to=to,
            encrypted_payload=encrypted_msg,
            message_type='optimistic_message',
        )

        self.audit.log_event("optimistic_send", {
            'to': to,
            'intent': intent,
        })

        # Wait for response
        response_future = asyncio.get_event_loop().create_future()
        self._pending_responses[session_id] = response_future

        try:
            response = await asyncio.wait_for(
                response_future,
                timeout=timeout
            )
            return response
        except asyncio.TimeoutError:
            logger.warning(f"Optimistic send timeout for {to}, falling back to regular send")
            del self._pending_responses[session_id]
            # Invalidate cache and retry with regular KNOCK
            self._session_cache.invalidate(to)
            return await self.send(to, intent, message, timeout=timeout, skip_cache=True)
