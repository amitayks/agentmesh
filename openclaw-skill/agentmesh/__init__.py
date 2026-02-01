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

__version__ = "0.2.0"
__protocol_version__ = "agentmesh/0.2"

from .client import AgentMeshClient
from .identity import Identity
from .session import Session, KnockMessage
from .transport import RelayTransport, P2PTransport, create_p2p_transport
from .discovery import RegistryClient
from .config import Config, Policy
from .dht import DHTClient, DHTValue, create_dht_client
from .did import DIDDocument, DIDManager, DIDResolver
from .schemas import (
    SchemaValidator,
    SequenceTracker,
    CapabilityNegotiator,
    CapabilityNegotiationRequest,
    CapabilityNegotiationResponse,
)

__all__ = [
    # Core
    "AgentMeshClient",
    "Identity",
    "Session",
    "KnockMessage",
    # Transport
    "RelayTransport",
    "P2PTransport",
    "create_p2p_transport",
    # Discovery
    "RegistryClient",
    "DHTClient",
    "DHTValue",
    "create_dht_client",
    # Config
    "Config",
    "Policy",
    # DID
    "DIDDocument",
    "DIDManager",
    "DIDResolver",
    # Schemas
    "SchemaValidator",
    "SequenceTracker",
    "CapabilityNegotiator",
    "CapabilityNegotiationRequest",
    "CapabilityNegotiationResponse",
]
