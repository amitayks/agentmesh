"""
DID (Decentralized Identifier) Document support for AgentMesh.
Implements W3C DID Core specification for agent identity.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

AGENTMESH_DIR = Path.home() / ".agentmesh"
DID_DIR = AGENTMESH_DIR / "did"

# DID method for AgentMesh
DID_METHOD = "agentmesh"


@dataclass
class VerificationMethod:
    """A verification method in a DID document."""
    id: str
    type: str
    controller: str
    public_key_multibase: str


@dataclass
class Service:
    """A service endpoint in a DID document."""
    id: str
    type: str
    service_endpoint: str


@dataclass
class DIDDocument:
    """
    W3C DID Document for an AgentMesh agent.

    See: https://www.w3.org/TR/did-core/
    """
    context: List[str]
    id: str  # did:agentmesh:<amid>
    controller: str
    verification_method: List[VerificationMethod]
    authentication: List[str]
    key_agreement: List[str]
    service: List[Service]
    created: datetime
    updated: datetime
    version_id: int

    @classmethod
    def create(
        cls,
        amid: str,
        signing_public_key_b64: str,
        exchange_public_key_b64: str,
        relay_endpoint: str = "wss://relay.agentmesh.net/v1/connect",
        registry_endpoint: str = "https://api.agentmesh.net/v1",
    ) -> "DIDDocument":
        """Create a new DID document for an agent."""
        did = f"did:{DID_METHOD}:{amid}"
        now = datetime.now(timezone.utc)

        # Verification methods
        signing_method = VerificationMethod(
            id=f"{did}#signing-key",
            type="Ed25519VerificationKey2020",
            controller=did,
            public_key_multibase=f"z{signing_public_key_b64}",  # z = base64url
        )

        exchange_method = VerificationMethod(
            id=f"{did}#key-agreement-key",
            type="X25519KeyAgreementKey2020",
            controller=did,
            public_key_multibase=f"z{exchange_public_key_b64}",
        )

        # Service endpoints
        services = [
            Service(
                id=f"{did}#relay",
                type="AgentMeshRelay",
                service_endpoint=relay_endpoint,
            ),
            Service(
                id=f"{did}#registry",
                type="AgentMeshRegistry",
                service_endpoint=registry_endpoint,
            ),
        ]

        return cls(
            context=[
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
                "https://w3id.org/security/suites/x25519-2020/v1",
            ],
            id=did,
            controller=did,
            verification_method=[signing_method, exchange_method],
            authentication=[f"{did}#signing-key"],
            key_agreement=[f"{did}#key-agreement-key"],
            service=services,
            created=now,
            updated=now,
            version_id=1,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-LD dictionary."""
        return {
            "@context": self.context,
            "id": self.id,
            "controller": self.controller,
            "verificationMethod": [
                {
                    "id": vm.id,
                    "type": vm.type,
                    "controller": vm.controller,
                    "publicKeyMultibase": vm.public_key_multibase,
                }
                for vm in self.verification_method
            ],
            "authentication": self.authentication,
            "keyAgreement": self.key_agreement,
            "service": [
                {
                    "id": s.id,
                    "type": s.type,
                    "serviceEndpoint": s.service_endpoint,
                }
                for s in self.service
            ],
            "created": self.created.isoformat(),
            "updated": self.updated.isoformat(),
            "versionId": self.version_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DIDDocument":
        """Parse from JSON-LD dictionary."""
        verification_methods = [
            VerificationMethod(
                id=vm["id"],
                type=vm["type"],
                controller=vm["controller"],
                public_key_multibase=vm["publicKeyMultibase"],
            )
            for vm in data.get("verificationMethod", [])
        ]

        services = [
            Service(
                id=s["id"],
                type=s["type"],
                service_endpoint=s["serviceEndpoint"],
            )
            for s in data.get("service", [])
        ]

        return cls(
            context=data.get("@context", []),
            id=data["id"],
            controller=data.get("controller", data["id"]),
            verification_method=verification_methods,
            authentication=data.get("authentication", []),
            key_agreement=data.get("keyAgreement", []),
            service=services,
            created=datetime.fromisoformat(data["created"]),
            updated=datetime.fromisoformat(data["updated"]),
            version_id=data.get("versionId", 1),
        )

    def update_keys(
        self,
        signing_public_key_b64: str,
        exchange_public_key_b64: str,
    ) -> None:
        """Update the keys in the DID document (for key rotation)."""
        did = self.id

        self.verification_method = [
            VerificationMethod(
                id=f"{did}#signing-key",
                type="Ed25519VerificationKey2020",
                controller=did,
                public_key_multibase=f"z{signing_public_key_b64}",
            ),
            VerificationMethod(
                id=f"{did}#key-agreement-key",
                type="X25519KeyAgreementKey2020",
                controller=did,
                public_key_multibase=f"z{exchange_public_key_b64}",
            ),
        ]

        self.updated = datetime.now(timezone.utc)
        self.version_id += 1

    def add_service(self, service_id: str, service_type: str, endpoint: str) -> None:
        """Add a service endpoint."""
        self.service.append(Service(
            id=f"{self.id}#{service_id}",
            type=service_type,
            service_endpoint=endpoint,
        ))
        self.updated = datetime.now(timezone.utc)

    def get_signing_key(self) -> Optional[str]:
        """Get the signing public key."""
        for vm in self.verification_method:
            if vm.type == "Ed25519VerificationKey2020":
                # Remove 'z' prefix (multibase)
                return vm.public_key_multibase[1:]
        return None

    def get_exchange_key(self) -> Optional[str]:
        """Get the key agreement public key."""
        for vm in self.verification_method:
            if vm.type == "X25519KeyAgreementKey2020":
                return vm.public_key_multibase[1:]
        return None

    def get_relay_endpoint(self) -> Optional[str]:
        """Get the relay service endpoint."""
        for s in self.service:
            if s.type == "AgentMeshRelay":
                return s.service_endpoint
        return None


class DIDManager:
    """Manages DID document lifecycle."""

    def __init__(self):
        DID_DIR.mkdir(parents=True, exist_ok=True)

    def get_document_path(self) -> Path:
        """Get path to the DID document."""
        return DID_DIR / "document.json"

    def create_document(
        self,
        amid: str,
        signing_public_key_b64: str,
        exchange_public_key_b64: str,
        relay_endpoint: str = "wss://relay.agentmesh.net/v1/connect",
    ) -> DIDDocument:
        """Create and save a new DID document."""
        doc = DIDDocument.create(
            amid=amid,
            signing_public_key_b64=signing_public_key_b64,
            exchange_public_key_b64=exchange_public_key_b64,
            relay_endpoint=relay_endpoint,
        )

        self.save_document(doc)
        logger.info(f"Created DID document: {doc.id}")
        return doc

    def save_document(self, doc: DIDDocument) -> None:
        """Save DID document to disk."""
        path = self.get_document_path()
        with open(path, 'w') as f:
            json.dump(doc.to_dict(), f, indent=2)
        path.chmod(0o600)

    def load_document(self) -> Optional[DIDDocument]:
        """Load DID document from disk."""
        path = self.get_document_path()
        if not path.exists():
            return None

        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return DIDDocument.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load DID document: {e}")
            return None

    def update_on_key_rotation(
        self,
        signing_public_key_b64: str,
        exchange_public_key_b64: str,
    ) -> Optional[DIDDocument]:
        """Update DID document after key rotation."""
        doc = self.load_document()
        if not doc:
            logger.error("No DID document to update")
            return None

        doc.update_keys(signing_public_key_b64, exchange_public_key_b64)
        self.save_document(doc)
        logger.info(f"Updated DID document to version {doc.version_id}")
        return doc

    def get_did(self) -> Optional[str]:
        """Get the DID from the stored document."""
        doc = self.load_document()
        return doc.id if doc else None


def amid_to_did(amid: str) -> str:
    """Convert an AMID to a DID."""
    return f"did:{DID_METHOD}:{amid}"


def did_to_amid(did: str) -> Optional[str]:
    """Extract AMID from a DID."""
    prefix = f"did:{DID_METHOD}:"
    if did.startswith(prefix):
        return did[len(prefix):]
    return None


def resolve_did(did: str) -> Optional[DIDDocument]:
    """
    Resolve a DID to its document.

    For local DIDs, loads from disk.
    For remote DIDs, fetches from registry.
    """
    amid = did_to_amid(did)
    if not amid:
        logger.error(f"Invalid DID format: {did}")
        return None

    # Check if it's our own DID
    manager = DIDManager()
    local_doc = manager.load_document()
    if local_doc and local_doc.id == did:
        return local_doc

    # For remote DIDs, would need to fetch from registry
    # This is implemented in the RegistryClient
    logger.debug(f"Remote DID resolution not implemented locally: {did}")
    return None


async def resolve_did_async(
    did: str,
    registry_client=None,
    dht_client=None,
) -> Optional[DIDDocument]:
    """
    Resolve a DID to its document asynchronously.

    Resolution order:
    1. Local DID document (if it's our own DID)
    2. Registry lookup
    3. DHT fallback (if registry fails)

    Args:
        did: The DID to resolve (did:agentmesh:<amid>)
        registry_client: Optional RegistryClient instance
        dht_client: Optional DHTClient instance for fallback

    Returns:
        DIDDocument if found, None otherwise
    """
    amid = did_to_amid(did)
    if not amid:
        logger.error(f"Invalid DID format: {did}")
        return None

    # 1. Check if it's our own DID
    manager = DIDManager()
    local_doc = manager.load_document()
    if local_doc and local_doc.id == did:
        return local_doc

    # 2. Try registry lookup
    if registry_client:
        try:
            doc_data = await registry_client.resolve_did(did)
            if doc_data:
                logger.debug(f"DID resolved via registry: {did}")
                return DIDDocument.from_dict(doc_data)
        except Exception as e:
            logger.warning(f"Registry DID resolution failed: {e}")

    # 3. DHT fallback
    if dht_client and dht_client.is_available:
        try:
            dht_value = await dht_client.lookup(amid)
            if dht_value:
                # Construct DID document from DHT value
                doc = DIDDocument.create(
                    amid=dht_value.amid,
                    signing_public_key_b64=_strip_key_prefix(dht_value.signing_public_key),
                    exchange_public_key_b64=_strip_key_prefix(dht_value.exchange_public_key),
                    relay_endpoint=dht_value.relay_url,
                )
                logger.debug(f"DID resolved via DHT fallback: {did}")
                return doc
        except Exception as e:
            logger.warning(f"DHT DID resolution failed: {e}")

    logger.debug(f"DID resolution failed for: {did}")
    return None


def _strip_key_prefix(key: str) -> str:
    """Strip ed25519: or x25519: prefix from a key."""
    if key.startswith("ed25519:"):
        return key[8:]
    if key.startswith("x25519:"):
        return key[7:]
    return key


class DIDResolver:
    """
    DID resolver with registry and DHT support.
    """

    def __init__(self, registry_client=None, dht_client=None):
        self.registry_client = registry_client
        self.dht_client = dht_client
        self._cache: Dict[str, DIDDocument] = {}
        self._cache_ttl = 300  # 5 minutes

    async def resolve(self, did: str, use_cache: bool = True) -> Optional[DIDDocument]:
        """
        Resolve a DID with caching.

        Args:
            did: The DID to resolve
            use_cache: Whether to use cached results

        Returns:
            DIDDocument if found, None otherwise
        """
        # Check cache
        if use_cache and did in self._cache:
            logger.debug(f"DID cache hit: {did}")
            return self._cache[did]

        # Resolve
        doc = await resolve_did_async(
            did,
            registry_client=self.registry_client,
            dht_client=self.dht_client,
        )

        # Cache result
        if doc:
            self._cache[did] = doc

        return doc

    def clear_cache(self, did: Optional[str] = None) -> None:
        """Clear the resolution cache."""
        if did:
            self._cache.pop(did, None)
        else:
            self._cache.clear()
