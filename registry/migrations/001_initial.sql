-- AgentMesh Registry Schema
-- Version: 0.1

-- Custom enum types
CREATE TYPE trust_tier AS ENUM ('anonymous', 'verified', 'organization');
CREATE TYPE presence_status AS ENUM ('online', 'away', 'offline', 'dnd');

-- Organizations table (for Tier 1.5)
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    root_certificate TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Agents table
CREATE TABLE agents (
    id UUID PRIMARY KEY,
    amid VARCHAR(64) NOT NULL UNIQUE,
    signing_public_key VARCHAR(128) NOT NULL,
    exchange_public_key VARCHAR(128) NOT NULL,
    tier trust_tier NOT NULL DEFAULT 'anonymous',
    display_name VARCHAR(255),
    organization_id UUID REFERENCES organizations(id),
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    relay_endpoint VARCHAR(512) NOT NULL DEFAULT 'wss://relay.agentmesh.net/v1/connect',
    direct_endpoint VARCHAR(512),
    status presence_status NOT NULL DEFAULT 'offline',
    reputation_score REAL NOT NULL DEFAULT 0.5 CHECK (reputation_score >= 0 AND reputation_score <= 1),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reputation records
CREATE TABLE reputation_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_amid VARCHAR(64) NOT NULL REFERENCES agents(amid),
    from_amid VARCHAR(64) NOT NULL REFERENCES agents(amid),
    session_id UUID NOT NULL,
    score REAL NOT NULL CHECK (score >= 0 AND score <= 1),
    tags TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Session cache for KNOCK optimization
CREATE TABLE session_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    initiator_amid VARCHAR(64) NOT NULL,
    receiver_amid VARCHAR(64) NOT NULL,
    intent_category VARCHAR(64) NOT NULL,
    session_key_encrypted TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(initiator_amid, receiver_amid, intent_category)
);

-- Indexes
CREATE INDEX idx_agents_amid ON agents(amid);
CREATE INDEX idx_agents_tier ON agents(tier);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_capabilities ON agents USING GIN(capabilities);
CREATE INDEX idx_agents_reputation ON agents(reputation_score DESC);
CREATE INDEX idx_agents_last_seen ON agents(last_seen DESC);

CREATE INDEX idx_reputation_target ON reputation_records(target_amid);
CREATE INDEX idx_reputation_from ON reputation_records(from_amid);

CREATE INDEX idx_session_cache_initiator ON session_cache(initiator_amid);
CREATE INDEX idx_session_cache_receiver ON session_cache(receiver_amid);
CREATE INDEX idx_session_cache_expires ON session_cache(expires_at);

-- Function to update reputation score
CREATE OR REPLACE FUNCTION update_agent_reputation(target VARCHAR(64))
RETURNS VOID AS $$
DECLARE
    new_score REAL;
    completion_rate REAL;
    peer_avg REAL;
    age_factor REAL;
    tier_bonus REAL;
    agent_tier trust_tier;
    agent_created TIMESTAMPTZ;
BEGIN
    -- Get agent info
    SELECT tier, created_at INTO agent_tier, agent_created
    FROM agents WHERE amid = target;

    -- Calculate completion rate (placeholder - would need session tracking)
    completion_rate := 0.8;

    -- Calculate peer feedback average
    SELECT COALESCE(AVG(score), 0.5) INTO peer_avg
    FROM reputation_records
    WHERE target_amid = target
    AND created_at > NOW() - INTERVAL '30 days';

    -- Calculate age factor (max 1.0 after 30 days)
    age_factor := LEAST(1.0, EXTRACT(EPOCH FROM (NOW() - agent_created)) / (30 * 24 * 3600));

    -- Tier bonus
    tier_bonus := CASE agent_tier
        WHEN 'organization' THEN 0.2
        WHEN 'verified' THEN 0.1
        ELSE 0.0
    END;

    -- Calculate new score
    new_score := (0.3 * completion_rate) + (0.4 * peer_avg) + (0.1 * age_factor) + (0.2 * tier_bonus);

    -- Clamp to valid range
    new_score := GREATEST(0.0, LEAST(1.0, new_score));

    -- Update agent
    UPDATE agents SET reputation_score = new_score, updated_at = NOW()
    WHERE amid = target;
END;
$$ LANGUAGE plpgsql;

-- Cleanup function for expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM session_cache WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
