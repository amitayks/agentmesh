"""
Transport layer for AgentMesh.
Handles WebSocket relay connections and P2P upgrades.
"""

import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass

import websockets
from websockets.client import WebSocketClientProtocol

from .identity import Identity

logger = logging.getLogger(__name__)


@dataclass
class RelayMessage:
    """Message envelope for relay communication."""
    type: str
    data: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps({'type': self.type, **self.data})

    @classmethod
    def from_json(cls, text: str) -> "RelayMessage":
        data = json.loads(text)
        msg_type = data.pop('type')
        return cls(type=msg_type, data=data)


class RelayTransport:
    """
    WebSocket transport via the AgentMesh relay server.
    Handles connection, authentication, and message routing.
    """

    def __init__(
        self,
        identity: Identity,
        relay_url: str = "wss://relay.agentmesh.net/v1/connect",
        p2p_capable: bool = True,
    ):
        self.identity = identity
        self.relay_url = relay_url
        self.p2p_capable = p2p_capable

        self._ws: Optional[WebSocketClientProtocol] = None
        self._session_id: Optional[str] = None
        self._connected = False
        self._message_handlers: Dict[str, Callable] = {}
        self._receive_task: Optional[asyncio.Task] = None
        self._pending_messages: int = 0

    @property
    def is_connected(self) -> bool:
        return self._connected and self._ws is not None

    async def connect(self) -> bool:
        """Connect to the relay server."""
        try:
            logger.info(f"Connecting to relay: {self.relay_url}")

            self._ws = await websockets.connect(
                self.relay_url,
                ping_interval=30,
                ping_timeout=10,
            )

            # Send authentication
            timestamp, signature = self.identity.sign_timestamp()

            connect_msg = {
                'type': 'connect',
                'protocol': 'agentmesh/0.1',
                'amid': self.identity.amid,
                'signature': signature,
                'timestamp': timestamp.isoformat(),
                'p2p_capable': self.p2p_capable,
            }

            await self._ws.send(json.dumps(connect_msg))

            # Wait for connected response
            response = await asyncio.wait_for(
                self._ws.recv(),
                timeout=10.0
            )

            data = json.loads(response)

            if data.get('type') == 'connected':
                self._session_id = data.get('session_id')
                self._pending_messages = data.get('pending_messages', 0)
                self._connected = True

                logger.info(
                    f"Connected to relay (session: {self._session_id}, "
                    f"pending: {self._pending_messages})"
                )

                # Start receive loop
                self._receive_task = asyncio.create_task(self._receive_loop())

                return True
            else:
                logger.error(f"Connection rejected: {data}")
                await self._ws.close()
                self._ws = None
                return False

        except Exception as e:
            logger.error(f"Failed to connect to relay: {e}")
            if self._ws:
                await self._ws.close()
                self._ws = None
            return False

    async def disconnect(self, reason: str = "client_disconnect") -> None:
        """Disconnect from the relay server."""
        if self._ws and self._connected:
            try:
                await self._ws.send(json.dumps({
                    'type': 'disconnect',
                    'reason': reason,
                }))
                await self._ws.close()
            except Exception:
                pass

        self._connected = False
        self._ws = None

        if self._receive_task:
            self._receive_task.cancel()
            self._receive_task = None

        logger.info("Disconnected from relay")

    async def send(
        self,
        to: str,
        encrypted_payload: str,
        message_type: str,
        ice_candidates: Optional[list] = None,
    ) -> bool:
        """Send a message to another agent."""
        if not self.is_connected:
            logger.error("Not connected to relay")
            return False

        message = {
            'type': 'send',
            'to': to,
            'encrypted_payload': encrypted_payload,
            'message_type': message_type,
        }

        if ice_candidates:
            message['ice_candidates'] = ice_candidates

        try:
            await self._ws.send(json.dumps(message))
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False

    async def update_presence(self, status: str) -> bool:
        """Update presence status."""
        if not self.is_connected:
            return False

        try:
            await self._ws.send(json.dumps({
                'type': 'presence',
                'status': status,
            }))
            return True
        except Exception as e:
            logger.error(f"Failed to update presence: {e}")
            return False

    async def query_presence(self, amid: str) -> Optional[dict]:
        """Query another agent's presence status."""
        if not self.is_connected:
            return None

        try:
            await self._ws.send(json.dumps({
                'type': 'presence_query',
                'amid': amid,
            }))
            # Response will come through message handler
            return {'status': 'pending'}
        except Exception as e:
            logger.error(f"Failed to query presence: {e}")
            return None

    def on_message(self, message_type: str, handler: Callable) -> None:
        """Register a handler for a message type."""
        self._message_handlers[message_type] = handler

    async def _receive_loop(self) -> None:
        """Background task to receive messages."""
        try:
            while self._connected and self._ws:
                try:
                    message = await self._ws.recv()
                    data = json.loads(message)
                    msg_type = data.get('type')

                    if msg_type in self._message_handlers:
                        try:
                            await self._message_handlers[msg_type](data)
                        except Exception as e:
                            logger.error(f"Handler error for {msg_type}: {e}")
                    else:
                        logger.debug(f"Unhandled message type: {msg_type}")

                except websockets.ConnectionClosed:
                    logger.warning("Relay connection closed")
                    self._connected = False
                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Receive loop error: {e}")
            self._connected = False


class P2PTransport:
    """
    Direct peer-to-peer transport using WebRTC data channels.
    Used when NAT traversal succeeds for lower latency.
    """

    def __init__(self, identity: Identity, peer_amid: str):
        self.identity = identity
        self.peer_amid = peer_amid
        self._connected = False
        # Note: Full WebRTC implementation would use aiortc or similar

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self, sdp_offer: str, ice_candidates: list) -> Optional[str]:
        """
        Attempt to establish a direct P2P connection.
        Returns SDP answer if successful, None otherwise.
        """
        # Placeholder - full implementation would use WebRTC
        logger.info(f"P2P connection attempt to {self.peer_amid}")
        return None

    async def send(self, data: bytes) -> bool:
        """Send data over the P2P connection."""
        if not self._connected:
            return False
        # Placeholder
        return True

    async def close(self) -> None:
        """Close the P2P connection."""
        self._connected = False
