## ADDED Requirements

### Requirement: Session cache for trusted contacts
The client SHALL cache successful session information to skip KNOCK handshake for subsequent interactions with the same peer and intent category.

#### Scenario: Cache hit skips KNOCK
- **WHEN** agent initiates session with peer+intent that exists in cache
- **THEN** client uses cached session key directly
- **AND** sends message without KNOCK handshake

#### Scenario: Cache miss performs KNOCK
- **WHEN** agent initiates session with peer+intent not in cache
- **THEN** client performs full KNOCK handshake

### Requirement: Session cache key structure
Cache entries SHALL be keyed by tuple of (our_amid, peer_amid, intent_category). This allows different intents with same peer to have separate cache entries.

#### Scenario: Different intents cached separately
- **WHEN** agent has cached session for travel intent with peer X
- **AND** agent initiates commerce intent with peer X
- **THEN** client performs KNOCK for commerce intent (cache miss)

#### Scenario: Same intent uses cache
- **WHEN** agent has cached session for travel intent with peer X
- **AND** agent initiates another travel session with peer X
- **THEN** client uses cached session (cache hit)

### Requirement: Session cache TTL
Cached sessions SHALL have configurable TTL defaulting to 24 hours. Expired entries SHALL be evicted automatically.

#### Scenario: Cache entry expires
- **WHEN** cached session is older than session_cache_ttl_hours
- **THEN** entry is considered invalid
- **AND** next request performs full KNOCK

#### Scenario: TTL configurable
- **WHEN** config.session_cache_ttl_hours is set to 48
- **THEN** cache entries expire after 48 hours

### Requirement: Session cache invalidation
Cache entries SHALL be invalidated on key rotation, policy change, or explicit revocation.

#### Scenario: Key rotation invalidates cache
- **WHEN** agent rotates exchange key
- **THEN** all cache entries are invalidated

#### Scenario: Policy change invalidates cache
- **WHEN** agent updates security policy
- **THEN** cache entries are invalidated
- **AND** peers must re-KNOCK with updated policy

#### Scenario: Explicit cache clear
- **WHEN** agent calls clear_session_cache() or clear_session_cache(peer_amid)
- **THEN** matching cache entries are removed

### Requirement: Session cache persistence
Cache SHALL be persisted to disk at ~/.agentmesh/session_cache.json for survival across restarts.

#### Scenario: Cache persisted on update
- **WHEN** new cache entry is created
- **THEN** cache file is updated

#### Scenario: Cache loaded on startup
- **WHEN** client starts
- **THEN** cache is loaded from disk
- **AND** expired entries are evicted

### Requirement: Optimistic send for allowlisted contacts
For allowlisted AMIDs, client SHALL support optimistic send where KNOCK and first message are sent together. Server buffers message until KNOCK evaluation completes.

#### Scenario: Optimistic send for allowlisted peer
- **WHEN** agent sends to peer in policy.allowlist
- **THEN** client sends KNOCK + first message in single relay SEND

#### Scenario: Optimistic send rejection handling
- **WHEN** optimistic send is rejected by peer's policy
- **THEN** client receives REJECT
- **AND** first message is discarded (not processed by peer)

### Requirement: LRU cache eviction
Session cache SHALL use LRU eviction when cache size exceeds configurable limit (default 1000 entries).

#### Scenario: LRU eviction on capacity
- **WHEN** cache has 1000 entries and new entry is added
- **THEN** least recently used entry is evicted
