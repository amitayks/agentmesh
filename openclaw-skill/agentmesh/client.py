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

        # Message handlers
        self._message_handlers: Dict[str, Callable] = {}
        self._pending_responses: Dict[str, asyncio.Future] = {}

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
    ) -> Optional[Dict[str, Any]]:
        """
        Send a message to another agent and wait for response.

        Args:
            to: Target agent's AMID
            intent: Intent category (e.g., "travel/flights")
            message: The message payload
            session_type: Type of session
            timeout: Response timeout in seconds

        Returns:
            Response payload or None if failed
        """
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

        import base64
        peer_public_key = base64.b64decode(peer_info.exchange_public_key)

        self.encryption.establish_session(
            session_id=session_id,
            peer_amid=to,
            peer_public_key=peer_public_key,
        )

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
            self._handle_accept(from_amid, encrypted_payload)
        elif msg_type == 'reject':
            self._handle_reject(from_amid, encrypted_payload)
        elif msg_type == 'message':
            await self._handle_message(from_amid, encrypted_payload)
        elif msg_type == 'close':
            self._handle_close(from_amid, encrypted_payload)

    async def _handle_knock(self, from_amid: str, payload: str) -> None:
        """Handle incoming KNOCK request."""
        try:
            knock_data = json.loads(payload)
            knock = KnockMessage.from_dict(knock_data)

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

                # Accept the session
                self.session_manager.accept_session(knock, session_key)

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
                })

                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=accept_msg,
                    message_type='accept',
                )
            else:
                # Send REJECT
                reject_msg = json.dumps({
                    'type': 'reject',
                    'reason': rejection_reason,
                    'human_readable': f"Connection rejected: {rejection_reason}",
                })

                await self.transport.send(
                    to=from_amid,
                    encrypted_payload=reject_msg,
                    message_type='reject',
                )

        except Exception as e:
            logger.error(f"Error handling KNOCK: {e}")

    def _handle_accept(self, from_amid: str, payload: str) -> None:
        """Handle KNOCK acceptance."""
        try:
            data = json.loads(payload)
            response_key = f"knock_{from_amid}"

            if response_key in self._pending_responses:
                self._pending_responses[response_key].set_result(data)
                del self._pending_responses[response_key]

        except Exception as e:
            logger.error(f"Error handling ACCEPT: {e}")

    def _handle_reject(self, from_amid: str, payload: str) -> None:
        """Handle KNOCK rejection."""
        try:
            data = json.loads(payload)
            response_key = f"knock_{from_amid}"

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
        }
