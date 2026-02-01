## ADDED Requirements

### Requirement: Kademlia DHT for Tier 2 discovery
The AgentMesh client SHALL support Kademlia-based distributed hash table for decentralized agent discovery. DHT is used as fallback when registry is unavailable and as primary discovery for Tier 2 (Anonymous) agents who opt-in.

#### Scenario: DHT bootstrap on startup
- **WHEN** client starts with enable_dht=true
- **THEN** client connects to bootstrap nodes from config
- **AND** joins DHT network within 10 seconds

#### Scenario: DHT publish agent info
- **WHEN** Tier 2 agent enables DHT discovery
- **THEN** client publishes to DHT key sha256(amid) with value containing public_keys and relay_endpoint

#### Scenario: DHT lookup agent
- **WHEN** registry lookup fails or times out
- **THEN** client falls back to DHT lookup for same AMID
- **AND** returns result if found within 5 seconds

### Requirement: DHT data format
DHT values SHALL be JSON objects containing minimal discovery information: public_keys, relay_endpoint, and last_updated timestamp.

#### Scenario: DHT value structure
- **WHEN** agent publishes to DHT
- **THEN** value contains { signing_public_key, exchange_public_key, relay_endpoint, last_updated }

#### Scenario: DHT value signed
- **WHEN** agent publishes to DHT
- **THEN** value includes signature over content for verification

### Requirement: DHT refresh and expiry
DHT entries SHALL be refreshed every 4 hours by republishing. Entries not refreshed for 24 hours SHALL be considered stale.

#### Scenario: Automatic refresh
- **WHEN** agent is online for 4 hours
- **THEN** client republishes DHT entry automatically

#### Scenario: Stale entry handling
- **WHEN** DHT lookup returns entry older than 24 hours
- **THEN** client treats as potentially stale
- **AND** attempts registry lookup as verification

### Requirement: Bootstrap node configuration
The client SHALL include default bootstrap nodes and allow custom bootstrap node configuration.

#### Scenario: Default bootstrap nodes
- **WHEN** client starts DHT without custom config
- **THEN** client uses hardcoded bootstrap nodes (minimum 3)

#### Scenario: Custom bootstrap nodes
- **WHEN** config.dht_bootstrap_nodes is set
- **THEN** client uses only configured bootstrap nodes

### Requirement: DHT participation opt-in
Agents SHALL explicitly opt-in to DHT network participation. Non-participating agents can still perform lookups but don't route for others.

#### Scenario: Full DHT participation
- **WHEN** config.dht_participate=true
- **THEN** agent stores and routes DHT entries for other agents

#### Scenario: Lookup-only mode
- **WHEN** config.dht_participate=false
- **THEN** agent can lookup via DHT but does not store others' entries

### Requirement: DHT optional dependency
The kademlia library SHALL be an optional dependency. DHT features are disabled gracefully if not installed.

#### Scenario: kademlia not installed
- **WHEN** kademlia import fails
- **THEN** client disables DHT features
- **AND** logs warning "DHT disabled: kademlia not installed"
