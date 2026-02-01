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
                'protocol': 'agentmesh/0.2',
                'amid': self.identity.amid,
                'public_key': self.identity.signing_public_key_b64_raw,
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


# Check if aiortc is available for P2P WebRTC
try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
    from aiortc.contrib.signaling import object_to_string, object_from_string
    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False
    logger.debug("aiortc not installed - P2P features disabled")


@dataclass
class P2PMetrics:
    """Metrics for P2P connection."""
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    connection_time: Optional[float] = None
    ice_state: str = "new"
    data_channel_state: str = "closed"


class P2PTransport:
    """
    Direct peer-to-peer transport using WebRTC data channels.
    Used when NAT traversal succeeds for lower latency.
    Falls back gracefully when aiortc is not installed.
    Supports TURN server fallback when STUN fails.
    """

    # Default STUN servers for ICE
    DEFAULT_STUN_SERVERS = [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
        "stun:stun2.l.google.com:19302",
    ]

    # Negotiation timeout for STUN before trying TURN
    STUN_TIMEOUT = 5.0
    # Overall negotiation timeout including TURN fallback
    NEGOTIATION_TIMEOUT = 15.0

    def __init__(
        self,
        identity: Identity,
        peer_amid: str,
        stun_servers: Optional[list] = None,
        turn_servers: Optional[list] = None,
        turn_fallback_timeout: float = 5.0,
    ):
        self.identity = identity
        self.peer_amid = peer_amid
        self.stun_servers = stun_servers or self.DEFAULT_STUN_SERVERS
        self.turn_servers = turn_servers or []
        self.turn_fallback_timeout = turn_fallback_timeout

        self._pc: Optional["RTCPeerConnection"] = None
        self._data_channel = None
        self._connected = False
        self._connection_event = asyncio.Event()
        self._pending_candidates: list = []
        self._on_message: Optional[Callable] = None
        self._metrics = P2PMetrics()
        self._health_check_task: Optional[asyncio.Task] = None
        self._using_turn = False  # Track if we fell back to TURN

    @property
    def is_available(self) -> bool:
        """Check if P2P functionality is available."""
        return AIORTC_AVAILABLE

    @property
    def is_connected(self) -> bool:
        return self._connected and self._data_channel is not None

    def get_metrics(self) -> Dict[str, Any]:
        """Get P2P connection metrics."""
        return {
            'available': AIORTC_AVAILABLE,
            'connected': self.is_connected,
            'using_turn': self._using_turn,
            'turn_servers_configured': len(self.turn_servers),
            'bytes_sent': self._metrics.bytes_sent,
            'bytes_received': self._metrics.bytes_received,
            'messages_sent': self._metrics.messages_sent,
            'messages_received': self._metrics.messages_received,
            'connection_time': self._metrics.connection_time,
            'ice_state': self._metrics.ice_state,
            'data_channel_state': self._metrics.data_channel_state,
        }

    def _create_peer_connection(self, include_turn: bool = False) -> "RTCPeerConnection":
        """
        Create a new RTCPeerConnection with ICE servers.

        Args:
            include_turn: If True, include TURN servers for relay fallback
        """
        if not AIORTC_AVAILABLE:
            raise RuntimeError("aiortc not installed")

        ice_servers = []

        # Add STUN servers
        for url in self.stun_servers:
            ice_servers.append(RTCIceServer(urls=url))

        # Add TURN servers if requested and available
        if include_turn and self.turn_servers:
            for turn in self.turn_servers:
                # Support both dict and TurnServerConfig objects
                if hasattr(turn, 'url'):
                    # TurnServerConfig object
                    if not turn.is_expired():
                        ice_servers.append(RTCIceServer(
                            urls=turn.url,
                            username=turn.username,
                            credential=turn.credential,
                        ))
                else:
                    # Dict format
                    ice_servers.append(RTCIceServer(
                        urls=turn.get("url"),
                        username=turn.get("username"),
                        credential=turn.get("credential"),
                    ))
            self._using_turn = True
            logger.info("TURN servers included in ICE configuration")

        config = RTCConfiguration(iceServers=ice_servers)
        pc = RTCPeerConnection(configuration=config)

        # Track ICE connection state
        @pc.on("iceconnectionstatechange")
        async def on_ice_state():
            self._metrics.ice_state = pc.iceConnectionState
            logger.debug(f"P2P ICE state: {pc.iceConnectionState}")

            if pc.iceConnectionState == "connected":
                self._connection_event.set()
            elif pc.iceConnectionState in ("failed", "disconnected", "closed"):
                self._connected = False
                self._connection_event.set()

        return pc

    async def gather_ice_candidates(self) -> list:
        """Gather local ICE candidates for signaling."""
        if not AIORTC_AVAILABLE:
            return []

        candidates = []

        if self._pc:
            # ICE candidates are gathered during offer/answer creation
            # They're included in the SDP, but we can also extract them
            local_desc = self._pc.localDescription
            if local_desc:
                # Parse candidates from SDP
                for line in local_desc.sdp.split('\n'):
                    if line.startswith('a=candidate:'):
                        candidates.append(line[2:])  # Remove 'a='

        return candidates

    async def create_offer(self, include_turn: bool = False) -> Optional[str]:
        """
        Create an ICE offer as the initiator.

        Args:
            include_turn: If True, include TURN servers in ICE configuration

        Returns:
            SDP offer string or None on failure.
        """
        if not AIORTC_AVAILABLE:
            logger.warning("P2P offer skipped - aiortc not installed")
            return None

        try:
            self._pc = self._create_peer_connection(include_turn=include_turn)

            # Create data channel
            self._data_channel = self._pc.createDataChannel(
                "agentmesh",
                ordered=True,
            )
            self._setup_data_channel_handlers(self._data_channel)

            # Create offer
            offer = await self._pc.createOffer()
            await self._pc.setLocalDescription(offer)

            # Wait for ICE gathering to complete
            await asyncio.sleep(0.5)  # Allow time for candidates

            logger.debug(f"P2P offer created for {self.peer_amid[:16]}... (TURN: {include_turn})")
            return object_to_string(self._pc.localDescription)

        except Exception as e:
            logger.error(f"P2P offer creation failed: {e}")
            return None

    async def create_offer_with_fallback(self) -> Optional[str]:
        """
        Create an ICE offer, starting with STUN only and falling back to TURN.

        Returns:
            SDP offer string or None on failure.
        """
        # First try with STUN only
        offer = await self.create_offer(include_turn=False)
        if offer:
            return offer

        # If STUN-only offer fails and TURN servers are available, retry with TURN
        if self.turn_servers:
            logger.info("STUN-only offer failed, retrying with TURN servers")
            return await self.create_offer(include_turn=True)

        return None

    async def process_answer(self, sdp_answer: str) -> bool:
        """
        Process an ICE answer from the remote peer.

        Implements TURN fallback: waits for STUN connection, and if it fails
        after turn_fallback_timeout seconds, logs that TURN would be needed
        for retry.

        Returns True if connection is established.
        """
        if not AIORTC_AVAILABLE or not self._pc:
            return False

        try:
            answer = object_from_string(sdp_answer)
            await self._pc.setRemoteDescription(answer)

            # Wait for connection with STUN timeout first
            try:
                await asyncio.wait_for(
                    self._connection_event.wait(),
                    timeout=self.turn_fallback_timeout,
                )

                if self._pc.iceConnectionState == "connected":
                    self._connected = True
                    self._metrics.connection_time = asyncio.get_event_loop().time()
                    self._start_health_monitoring()
                    connection_type = "TURN relay" if self._using_turn else "STUN direct"
                    logger.info(f"P2P connected to {self.peer_amid[:16]}... ({connection_type})")
                    return True

            except asyncio.TimeoutError:
                # STUN-only connection timed out
                if not self._using_turn and self.turn_servers:
                    logger.info(f"STUN connection timeout after {self.turn_fallback_timeout}s, "
                               f"TURN fallback available for retry")
                else:
                    logger.warning(f"P2P connection timeout for {self.peer_amid[:16]}...")

            return False

        except Exception as e:
            logger.error(f"P2P answer processing failed: {e}")
            return False

    async def connect_with_fallback(self, create_offer_func, process_answer_func) -> bool:
        """
        Attempt P2P connection with automatic TURN fallback.

        First tries STUN-only, then falls back to TURN if available and STUN fails.

        Args:
            create_offer_func: Async function to create and send offer
            process_answer_func: Async function to receive and process answer

        Returns:
            True if connection established, False otherwise.
        """
        # First attempt: STUN only
        self._using_turn = False
        offer = await self.create_offer(include_turn=False)
        if offer:
            await create_offer_func(offer)
            sdp_answer = await process_answer_func()
            if sdp_answer and await self.process_answer(sdp_answer):
                return True

        # Second attempt: Include TURN servers
        if self.turn_servers:
            logger.info("STUN connection failed, attempting with TURN fallback")
            # Reset connection state
            self._connection_event.clear()
            await self.close()

            self._using_turn = True
            offer = await self.create_offer(include_turn=True)
            if offer:
                await create_offer_func(offer)
                sdp_answer = await process_answer_func()
                if sdp_answer and await self.process_answer(sdp_answer):
                    return True

        return False

    async def create_answer(self, sdp_offer: str, include_turn: bool = False) -> Optional[str]:
        """
        Create an ICE answer as the responder.

        Args:
            sdp_offer: The SDP offer from the initiator
            include_turn: If True, include TURN servers in ICE configuration

        Returns:
            SDP answer string or None on failure.
        """
        if not AIORTC_AVAILABLE:
            logger.warning("P2P answer skipped - aiortc not installed")
            return None

        try:
            self._pc = self._create_peer_connection(include_turn=include_turn)

            # Set up data channel handler for incoming channel
            @self._pc.on("datachannel")
            def on_datachannel(channel):
                self._data_channel = channel
                self._setup_data_channel_handlers(channel)

            # Process offer
            offer = object_from_string(sdp_offer)
            await self._pc.setRemoteDescription(offer)

            # Create answer
            answer = await self._pc.createAnswer()
            await self._pc.setLocalDescription(answer)

            # Wait for ICE gathering
            await asyncio.sleep(0.5)

            logger.debug(f"P2P answer created for {self.peer_amid[:16]}... (TURN: {include_turn})")
            return object_to_string(self._pc.localDescription)

        except Exception as e:
            logger.error(f"P2P answer creation failed: {e}")
            return None

    async def create_answer_with_fallback(self, sdp_offer: str) -> Optional[str]:
        """
        Create an ICE answer, including TURN servers if available.

        For answers, we proactively include TURN to maximize connection success.

        Args:
            sdp_offer: The SDP offer from the initiator

        Returns:
            SDP answer string or None on failure.
        """
        # Include TURN if available to maximize connection success
        include_turn = bool(self.turn_servers)
        return await self.create_answer(sdp_offer, include_turn=include_turn)

    def _setup_data_channel_handlers(self, channel) -> None:
        """Set up event handlers for the data channel."""
        @channel.on("open")
        def on_open():
            self._metrics.data_channel_state = "open"
            self._connected = True
            self._connection_event.set()
            logger.debug("P2P data channel opened")

        @channel.on("close")
        def on_close():
            self._metrics.data_channel_state = "closed"
            self._connected = False
            logger.debug("P2P data channel closed")

        @channel.on("message")
        def on_message(message):
            self._metrics.messages_received += 1
            if isinstance(message, bytes):
                self._metrics.bytes_received += len(message)
            else:
                self._metrics.bytes_received += len(message.encode('utf-8'))

            if self._on_message:
                asyncio.create_task(self._on_message(message))

    def on_message(self, handler: Callable) -> None:
        """Register a message handler for incoming data channel messages."""
        self._on_message = handler

    async def send(self, data: bytes) -> bool:
        """Send data over the P2P data channel."""
        if not self.is_connected or not self._data_channel:
            return False

        try:
            self._data_channel.send(data)
            self._metrics.bytes_sent += len(data)
            self._metrics.messages_sent += 1
            return True
        except Exception as e:
            logger.error(f"P2P send failed: {e}")
            return False

    async def send_text(self, text: str) -> bool:
        """Send text over the P2P data channel."""
        if not self.is_connected or not self._data_channel:
            return False

        try:
            self._data_channel.send(text)
            self._metrics.bytes_sent += len(text.encode('utf-8'))
            self._metrics.messages_sent += 1
            return True
        except Exception as e:
            logger.error(f"P2P send failed: {e}")
            return False

    def _start_health_monitoring(self) -> None:
        """Start background health monitoring task."""
        if self._health_check_task:
            return

        async def health_loop():
            while self._connected:
                await asyncio.sleep(30)  # Check every 30 seconds
                if not self.is_connected:
                    logger.warning("P2P connection health check failed")
                    break

        self._health_check_task = asyncio.create_task(health_loop())

    async def close(self) -> None:
        """Close the P2P connection."""
        self._connected = False

        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None

        if self._data_channel:
            self._data_channel.close()
            self._data_channel = None

        if self._pc:
            await self._pc.close()
            self._pc = None

        logger.debug(f"P2P connection closed for {self.peer_amid[:16]}...")


class P2PTransportFallback:
    """Fallback P2P transport when aiortc is not installed."""

    def __init__(self, *args, **kwargs):
        self.peer_amid = kwargs.get('peer_amid', 'unknown')
        self.turn_servers = kwargs.get('turn_servers', [])
        self._using_turn = False

    @property
    def is_available(self) -> bool:
        return False

    @property
    def is_connected(self) -> bool:
        return False

    def get_metrics(self) -> Dict[str, Any]:
        return {
            'available': False,
            'connected': False,
            'using_turn': False,
            'turn_servers_configured': len(self.turn_servers),
            'message': 'Install aiortc: pip install aiortc',
        }

    async def gather_ice_candidates(self) -> list:
        return []

    async def create_offer(self, include_turn: bool = False) -> Optional[str]:
        return None

    async def create_offer_with_fallback(self) -> Optional[str]:
        return None

    async def process_answer(self, sdp_answer: str) -> bool:
        return False

    async def create_answer(self, sdp_offer: str, include_turn: bool = False) -> Optional[str]:
        return None

    async def create_answer_with_fallback(self, sdp_offer: str) -> Optional[str]:
        return None

    async def connect_with_fallback(self, create_offer_func, process_answer_func) -> bool:
        return False

    def on_message(self, handler: Callable) -> None:
        pass

    async def send(self, data: bytes) -> bool:
        return False

    async def send_text(self, text: str) -> bool:
        return False

    async def close(self) -> None:
        pass


def create_p2p_transport(
    identity: Identity,
    peer_amid: str,
    stun_servers: Optional[list] = None,
    turn_servers: Optional[list] = None,
    turn_fallback_timeout: float = 5.0,
):
    """
    Factory function to create the appropriate P2P transport.

    Args:
        identity: The local agent's identity
        peer_amid: The remote agent's AMID
        stun_servers: List of STUN server URLs
        turn_servers: List of TURN server configurations (dicts or TurnServerConfig)
        turn_fallback_timeout: Seconds to wait for STUN before trying TURN

    Returns:
        P2PTransport if aiortc is installed, P2PTransportFallback otherwise.
    """
    if AIORTC_AVAILABLE:
        return P2PTransport(
            identity,
            peer_amid,
            stun_servers,
            turn_servers=turn_servers,
            turn_fallback_timeout=turn_fallback_timeout,
        )
    else:
        return P2PTransportFallback(
            identity=identity,
            peer_amid=peer_amid,
            turn_servers=turn_servers,
        )
