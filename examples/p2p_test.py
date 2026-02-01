#!/usr/bin/env python3
"""
AgentMesh P2P (Peer-to-Peer) Connection Test

This script tests direct WebRTC data channel communication between two agents,
bypassing the relay server entirely after initial signaling.

Usage:
    python3 examples/p2p_test.py
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add the openclaw-skill to path
sys.path.insert(0, str(Path(__file__).parent.parent / "openclaw-skill"))

from agentmesh.identity import Identity

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("p2p_test")

# Check if aiortc is available
try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel
    from aiortc.contrib.signaling import object_to_string, object_from_string
    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False
    logger.error("aiortc not installed. Run: pip install aiortc")
    sys.exit(1)


class P2PAgent:
    """Simple P2P agent using WebRTC data channels."""

    def __init__(self, name: str):
        self.name = name
        self.identity = Identity.generate()
        self.pc: RTCPeerConnection = None
        self.data_channel: RTCDataChannel = None
        self.received_messages = asyncio.Queue()
        self._connected = asyncio.Event()

    @property
    def amid(self) -> str:
        return self.identity.amid

    async def create_offer(self) -> str:
        """Create a WebRTC offer (initiator side)."""
        self.pc = RTCPeerConnection()

        # Create data channel
        self.data_channel = self.pc.createDataChannel("agentmesh")
        self._setup_data_channel(self.data_channel)

        # Handle ICE connection state
        @self.pc.on("connectionstatechange")
        async def on_connectionstatechange():
            logger.info(f"[{self.name}] Connection state: {self.pc.connectionState}")
            if self.pc.connectionState == "connected":
                self._connected.set()

        # Create offer
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        # Wait for ICE gathering to complete
        await self._wait_for_ice_gathering()

        return object_to_string(self.pc.localDescription)

    async def accept_offer(self, offer_str: str) -> str:
        """Accept an offer and create an answer (responder side)."""
        self.pc = RTCPeerConnection()

        # Handle incoming data channel
        @self.pc.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logger.info(f"[{self.name}] Data channel received: {channel.label}")
            self.data_channel = channel
            self._setup_data_channel(channel)

        # Handle ICE connection state
        @self.pc.on("connectionstatechange")
        async def on_connectionstatechange():
            logger.info(f"[{self.name}] Connection state: {self.pc.connectionState}")
            if self.pc.connectionState == "connected":
                self._connected.set()

        # Set remote description (the offer)
        offer = object_from_string(offer_str)
        await self.pc.setRemoteDescription(offer)

        # Create answer
        answer = await self.pc.createAnswer()
        await self.pc.setLocalDescription(answer)

        # Wait for ICE gathering to complete
        await self._wait_for_ice_gathering()

        return object_to_string(self.pc.localDescription)

    async def complete_connection(self, answer_str: str):
        """Complete the connection with the answer (initiator side)."""
        answer = object_from_string(answer_str)
        await self.pc.setRemoteDescription(answer)

    async def _wait_for_ice_gathering(self):
        """Wait for ICE gathering to complete."""
        if self.pc.iceGatheringState == "complete":
            return

        gathering_complete = asyncio.Event()

        @self.pc.on("icegatheringstatechange")
        def on_ice_gathering_state_change():
            if self.pc.iceGatheringState == "complete":
                gathering_complete.set()

        await asyncio.wait_for(gathering_complete.wait(), timeout=10.0)

    def _setup_data_channel(self, channel: RTCDataChannel):
        """Setup data channel event handlers."""

        @channel.on("open")
        def on_open():
            logger.info(f"[{self.name}] Data channel OPEN")

        @channel.on("message")
        def on_message(message):
            logger.info(f"[{self.name}] Received: {message}")
            asyncio.get_event_loop().call_soon_threadsafe(
                self.received_messages.put_nowait, message
            )

        @channel.on("close")
        def on_close():
            logger.info(f"[{self.name}] Data channel closed")

    async def wait_connected(self, timeout: float = 15.0):
        """Wait for the P2P connection to be established."""
        await asyncio.wait_for(self._connected.wait(), timeout=timeout)

    def send(self, message: str):
        """Send a message over the P2P data channel."""
        if self.data_channel and self.data_channel.readyState == "open":
            self.data_channel.send(message)
            logger.info(f"[{self.name}] Sent: {message}")
        else:
            logger.error(f"[{self.name}] Data channel not open!")

    async def receive(self, timeout: float = 5.0) -> str:
        """Wait for and receive a message."""
        return await asyncio.wait_for(self.received_messages.get(), timeout=timeout)

    async def close(self):
        """Close the P2P connection."""
        if self.pc:
            await self.pc.close()
            logger.info(f"[{self.name}] Connection closed")


async def run_p2p_test():
    """Run a complete P2P test between two agents."""

    print("\n" + "=" * 60)
    print("  AgentMesh P2P (WebRTC) Connection Test")
    print("=" * 60 + "\n")

    # Create two agents
    alice = P2PAgent("Alice")
    bob = P2PAgent("Bob")

    print(f"Alice AMID: {alice.amid}")
    print(f"Bob AMID:   {bob.amid}\n")

    try:
        # Step 1: Alice creates an offer
        print("Step 1: Alice creates WebRTC offer...")
        offer = await alice.create_offer()
        print(f"  Offer created (SDP size: {len(offer)} bytes)")

        # Step 2: Bob accepts the offer and creates an answer
        print("\nStep 2: Bob accepts offer and creates answer...")
        answer = await bob.accept_offer(offer)
        print(f"  Answer created (SDP size: {len(answer)} bytes)")

        # Step 3: Alice completes the connection with Bob's answer
        print("\nStep 3: Alice completes connection with answer...")
        await alice.complete_connection(answer)

        # Step 4: Wait for P2P connection to establish
        print("\nStep 4: Waiting for P2P connection...")
        await asyncio.gather(
            alice.wait_connected(timeout=15.0),
            bob.wait_connected(timeout=15.0),
        )
        print("  P2P connection established!")

        # Give data channel a moment to fully open
        await asyncio.sleep(0.5)

        # Step 5: Exchange messages directly (no relay!)
        print("\n" + "-" * 40)
        print("  DIRECT P2P MESSAGE EXCHANGE")
        print("-" * 40 + "\n")

        # Alice sends to Bob
        alice.send("Hello Bob! This is a direct P2P message from Alice.")
        msg = await bob.receive()
        print(f"  Bob received: {msg}")

        # Bob sends to Alice
        bob.send("Hi Alice! Got your message. P2P is working!")
        msg = await alice.receive()
        print(f"  Alice received: {msg}")

        # Multiple messages
        for i in range(3):
            alice.send(f"P2P message #{i+1} from Alice")
            await bob.receive()
            bob.send(f"P2P reply #{i+1} from Bob")
            await alice.receive()

        print("\n" + "=" * 60)
        print("  P2P TEST PASSED!")
        print("  Messages exchanged directly without relay server")
        print("=" * 60 + "\n")

    except asyncio.TimeoutError:
        print("\n  TIMEOUT: P2P connection failed to establish")
        print("  This can happen due to NAT/firewall restrictions")
        print("  In production, would fall back to relay")

    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        await alice.close()
        await bob.close()


async def run_p2p_with_relay_fallback():
    """
    Test P2P with relay integration (using the full AgentMesh transport).
    This shows how the production client upgrades from relay to P2P.
    """
    print("\n" + "=" * 60)
    print("  P2P with Relay Signaling Test")
    print("=" * 60 + "\n")

    # Import the full transport
    from agentmesh.transport import RelayTransport, P2PTransport

    # Create identities
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()

    print(f"Alice: {alice_identity.amid}")
    print(f"Bob:   {bob_identity.amid}\n")

    # Check P2P availability
    p2p = P2PTransport(alice_identity, bob_identity.amid)
    print(f"P2P Available: {p2p.is_available}")
    print(f"STUN Servers: {p2p.stun_servers[:2]}...")

    metrics = p2p.get_metrics()
    print(f"Initial metrics: connected={metrics['connected']}, available={metrics['available']}")


def main():
    print("\nChecking dependencies...")
    print(f"  aiortc: {'installed' if AIORTC_AVAILABLE else 'MISSING'}")

    if not AIORTC_AVAILABLE:
        print("\nInstall aiortc first: pip install aiortc")
        return

    # Run the basic P2P test
    asyncio.run(run_p2p_test())

    # Show P2P transport info
    asyncio.run(run_p2p_with_relay_fallback())


if __name__ == "__main__":
    main()
