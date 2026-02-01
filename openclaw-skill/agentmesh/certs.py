"""
Certificate chain validation for AgentMesh.

Implements X.509-style certificate chain validation for the trust hierarchy:
Root CA → Organization → Agent → Session

Certificates are used to verify:
- Organization identity (after DNS verification)
- Agent identity (issued by org or directly by registry)
- Session validity (short-lived session certificates)
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CertificateType(Enum):
    """Types of certificates in the chain."""
    ROOT_CA = "root_ca"
    ORGANIZATION = "organization"
    AGENT = "agent"
    SESSION = "session"


class CertificateValidationError(Exception):
    """Raised when certificate validation fails."""
    pass


@dataclass
class CertificateInfo:
    """Parsed certificate information."""
    cert_type: CertificateType
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    public_key_bytes: bytes
    serial_number: int
    is_ca: bool = False
    amid: Optional[str] = None
    organization: Optional[str] = None
    raw_bytes: bytes = field(default=b"", repr=False)

    def is_expired(self) -> bool:
        """Check if certificate has expired."""
        return datetime.now(timezone.utc) > self.not_after

    def is_not_yet_valid(self) -> bool:
        """Check if certificate is not yet valid."""
        return datetime.now(timezone.utc) < self.not_before

    def is_valid_time(self) -> bool:
        """Check if certificate is within its validity period."""
        now = datetime.now(timezone.utc)
        return self.not_before <= now <= self.not_after


class RootCAStore:
    """
    Storage and management of trusted Root CA certificates.

    Root CAs are loaded from:
    1. Built-in AgentMesh Root CA (for production)
    2. User-provided CAs in ~/.agentmesh/trusted_cas/
    3. Environment variable AGENTMESH_TRUSTED_CAS (comma-separated paths)
    """

    # Default location for trusted CAs
    DEFAULT_CA_DIR = Path.home() / ".agentmesh" / "trusted_cas"

    def __init__(self):
        self._trusted_cas: Dict[str, CertificateInfo] = {}
        self._load_default_cas()
        self._load_user_cas()
        self._load_env_cas()

    def _load_default_cas(self) -> None:
        """Load built-in AgentMesh Root CA."""
        # In production, this would load the AgentMesh Root CA
        # For now, we support loading from environment or files
        pass

    def _load_user_cas(self) -> None:
        """Load user-provided CAs from ~/.agentmesh/trusted_cas/."""
        if not self.DEFAULT_CA_DIR.exists():
            return

        for ca_file in self.DEFAULT_CA_DIR.glob("*.pem"):
            try:
                self._load_ca_from_file(ca_file)
            except Exception as e:
                logger.warning(f"Failed to load CA from {ca_file}: {e}")

    def _load_env_cas(self) -> None:
        """Load CAs specified in AGENTMESH_TRUSTED_CAS environment variable."""
        ca_paths = os.environ.get("AGENTMESH_TRUSTED_CAS", "")
        if not ca_paths:
            return

        for path_str in ca_paths.split(","):
            path = Path(path_str.strip())
            if path.exists():
                try:
                    self._load_ca_from_file(path)
                except Exception as e:
                    logger.warning(f"Failed to load CA from {path}: {e}")

    def _load_ca_from_file(self, path: Path) -> None:
        """Load a CA certificate from a PEM file."""
        with open(path, "rb") as f:
            pem_data = f.read()

        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        info = _parse_certificate(cert)

        if not info.is_ca:
            logger.warning(f"Certificate in {path} is not a CA certificate")
            return

        # Use subject as key for lookup
        self._trusted_cas[info.subject] = info
        logger.info(f"Loaded trusted CA: {info.subject}")

    def add_ca(self, cert_bytes: bytes) -> None:
        """Add a CA certificate to the trust store."""
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        info = _parse_certificate(cert)

        if not info.is_ca:
            raise CertificateValidationError("Certificate is not a CA certificate")

        self._trusted_cas[info.subject] = info

    def get_ca(self, subject: str) -> Optional[CertificateInfo]:
        """Get a CA certificate by subject name."""
        return self._trusted_cas.get(subject)

    def is_trusted_ca(self, subject: str) -> bool:
        """Check if a CA is in the trust store."""
        return subject in self._trusted_cas

    @property
    def trusted_subjects(self) -> List[str]:
        """Get list of trusted CA subjects."""
        return list(self._trusted_cas.keys())


def _parse_certificate(cert: x509.Certificate) -> CertificateInfo:
    """Parse an X.509 certificate into CertificateInfo."""
    # Extract subject and issuer
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Check if CA
    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        pass

    # Get public key bytes
    public_key = cert.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Try to extract AMID and organization from subject
    amid = None
    organization = None
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            # AMID is typically in CN
            value = attr.value
            if value.startswith("amid:"):
                amid = value[5:]
            else:
                amid = value
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            organization = attr.value

    # Determine certificate type
    cert_type = CertificateType.AGENT
    if is_ca:
        if "Root CA" in subject or organization == "AgentMesh":
            cert_type = CertificateType.ROOT_CA
        else:
            cert_type = CertificateType.ORGANIZATION
    elif "session" in subject.lower():
        cert_type = CertificateType.SESSION

    return CertificateInfo(
        cert_type=cert_type,
        subject=subject,
        issuer=issuer,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        public_key_bytes=public_key_bytes,
        serial_number=cert.serial_number,
        is_ca=is_ca,
        amid=amid,
        organization=organization,
        raw_bytes=cert.public_bytes(serialization.Encoding.PEM),
    )


class CertificateChain:
    """
    Represents and validates a certificate chain.

    The chain structure is:
    Root CA → Organization Certificate → Agent Certificate → Session Certificate

    Each certificate in the chain must be signed by the previous one.
    """

    def __init__(self, certificates: List[bytes]):
        """
        Initialize with a list of PEM-encoded certificates.

        Args:
            certificates: List of PEM-encoded certificates, from leaf to root
        """
        self.certificates = certificates
        self._parsed: List[CertificateInfo] = []
        self._x509_certs: List[x509.Certificate] = []

        for cert_bytes in certificates:
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            self._x509_certs.append(cert)
            self._parsed.append(_parse_certificate(cert))

    @property
    def leaf(self) -> Optional[CertificateInfo]:
        """Get the leaf (end-entity) certificate."""
        return self._parsed[0] if self._parsed else None

    @property
    def root(self) -> Optional[CertificateInfo]:
        """Get the root certificate."""
        return self._parsed[-1] if self._parsed else None

    def validate_chain(self, trust_store: Optional[RootCAStore] = None) -> bool:
        """
        Validate the entire certificate chain.

        Args:
            trust_store: Optional RootCAStore for verifying the root CA

        Returns:
            True if the chain is valid

        Raises:
            CertificateValidationError: If validation fails
        """
        if not self._parsed:
            raise CertificateValidationError("Empty certificate chain")

        # Check each certificate's validity period
        for i, cert_info in enumerate(self._parsed):
            if cert_info.is_expired():
                raise CertificateValidationError(
                    f"Certificate {i} ({cert_info.subject}) has expired"
                )
            if cert_info.is_not_yet_valid():
                raise CertificateValidationError(
                    f"Certificate {i} ({cert_info.subject}) is not yet valid"
                )

        # Verify chain signatures (each cert signed by the next)
        for i in range(len(self._x509_certs) - 1):
            child_cert = self._x509_certs[i]
            parent_cert = self._x509_certs[i + 1]

            # Check that child's issuer matches parent's subject
            if child_cert.issuer != parent_cert.subject:
                raise CertificateValidationError(
                    f"Certificate {i} issuer does not match certificate {i+1} subject"
                )

            # Verify signature
            try:
                parent_public_key = parent_cert.public_key()
                parent_public_key.verify(
                    child_cert.signature,
                    child_cert.tbs_certificate_bytes,
                )
            except Exception as e:
                raise CertificateValidationError(
                    f"Certificate {i} signature verification failed: {e}"
                )

        # If trust store provided, verify root is trusted
        if trust_store and self.root:
            if not trust_store.is_trusted_ca(self.root.subject):
                # Check if self-signed root matches a trusted CA
                root_cert = self._x509_certs[-1]
                if root_cert.issuer == root_cert.subject:
                    # Self-signed, must be in trust store
                    raise CertificateValidationError(
                        f"Root CA not in trust store: {self.root.subject}"
                    )

        return True

    def get_agent_amid(self) -> Optional[str]:
        """Get the AMID from the agent certificate in the chain."""
        for cert_info in self._parsed:
            if cert_info.cert_type == CertificateType.AGENT and cert_info.amid:
                return cert_info.amid
        return None

    def get_organization(self) -> Optional[str]:
        """Get the organization from the chain."""
        for cert_info in self._parsed:
            if cert_info.organization:
                return cert_info.organization
        return None


class RevocationCache:
    """
    Cache for certificate revocation status.

    Checks are cached for 1 hour to reduce registry load.
    """

    CACHE_DURATION = timedelta(hours=1)

    def __init__(self):
        self._cache: Dict[str, Tuple[bool, datetime]] = {}

    def is_revoked(self, serial_number: int) -> Optional[bool]:
        """
        Check if a certificate is revoked (from cache).

        Returns:
            True if revoked, False if not revoked, None if not in cache
        """
        key = str(serial_number)
        if key not in self._cache:
            return None

        is_revoked, cached_at = self._cache[key]
        if datetime.now(timezone.utc) - cached_at > self.CACHE_DURATION:
            # Cache expired
            del self._cache[key]
            return None

        return is_revoked

    def cache_result(self, serial_number: int, is_revoked: bool) -> None:
        """Cache a revocation check result."""
        self._cache[str(serial_number)] = (is_revoked, datetime.now(timezone.utc))

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()


# Global instances
_root_ca_store: Optional[RootCAStore] = None
_revocation_cache: Optional[RevocationCache] = None


def get_root_ca_store() -> RootCAStore:
    """Get the global Root CA store."""
    global _root_ca_store
    if _root_ca_store is None:
        _root_ca_store = RootCAStore()
    return _root_ca_store


def get_revocation_cache() -> RevocationCache:
    """Get the global revocation cache."""
    global _revocation_cache
    if _revocation_cache is None:
        _revocation_cache = RevocationCache()
    return _revocation_cache


def validate_agent_certificate_chain(
    cert_chain_pem: List[bytes],
    expected_amid: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validate an agent's certificate chain.

    Args:
        cert_chain_pem: List of PEM-encoded certificates (leaf to root)
        expected_amid: Optional AMID to verify matches the certificate

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        chain = CertificateChain(cert_chain_pem)
        chain.validate_chain(get_root_ca_store())

        # Verify AMID if expected
        if expected_amid:
            cert_amid = chain.get_agent_amid()
            if cert_amid != expected_amid:
                return False, f"AMID mismatch: expected {expected_amid}, got {cert_amid}"

        return True, None

    except CertificateValidationError as e:
        return False, str(e)
    except Exception as e:
        logger.error(f"Certificate validation error: {e}")
        return False, f"Validation error: {e}"


async def check_certificate_revocation(
    serial_number: int,
    registry_url: str,
) -> Tuple[bool, Optional[str]]:
    """
    Check if a certificate is revoked via the registry.

    Uses caching to reduce registry load (1-hour cache).

    Args:
        serial_number: Certificate serial number
        registry_url: Registry API URL

    Returns:
        Tuple of (is_revoked, error_message)
    """
    import aiohttp

    cache = get_revocation_cache()

    # Check cache first
    cached_result = cache.is_revoked(serial_number)
    if cached_result is not None:
        return cached_result, None

    # Query registry
    try:
        async with aiohttp.ClientSession() as session:
            url = f"{registry_url}/certificates/revocation/{serial_number}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    is_revoked = data.get("revoked", False)
                    cache.cache_result(serial_number, is_revoked)
                    return is_revoked, None
                elif response.status == 404:
                    # Certificate not found in revocation list = not revoked
                    cache.cache_result(serial_number, False)
                    return False, None
                else:
                    return False, f"Registry returned status {response.status}"

    except Exception as e:
        logger.error(f"Revocation check failed: {e}")
        return False, f"Revocation check failed: {e}"
