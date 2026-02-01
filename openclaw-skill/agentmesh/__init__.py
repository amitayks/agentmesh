"""
AgentMesh - P2P Encrypted Messenger for AI Agents

This module provides the client-side implementation of the AgentMesh protocol,
enabling AI agents to securely discover, authenticate, and communicate with
other agents peer-to-peer.

Usage:
    from agentmesh import AgentMeshClient

    client = AgentMeshClient()
    await client.connect()

    # Search for agents with a capability
    agents = await client.search("travel/flights")

    # Send a message
    response = await client.send(
        to="5Kd3...",
        intent="travel/flights",
        message={"origin": "TLV", "destination": "BER"}
    )
"""

__version__ = "0.1.0"
__protocol_version__ = "agentmesh/0.1"

from .client import AgentMeshClient
from .identity import Identity
from .session import Session, KnockMessage
from .transport import RelayTransport, P2PTransport
from .discovery import RegistryClient
from .config import Config

__all__ = [
    "AgentMeshClient",
    "Identity",
    "Session",
    "KnockMessage",
    "RelayTransport",
    "P2PTransport",
    "RegistryClient",
    "Config",
]
