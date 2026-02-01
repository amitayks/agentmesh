-- Organizations table for Tier 1.5 registration
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    admin_amid VARCHAR(255) NOT NULL,
    dns_challenge VARCHAR(255),
    dns_verified BOOLEAN NOT NULL DEFAULT FALSE,
    root_certificate TEXT,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for domain lookups
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain);

-- Index for admin lookups
CREATE INDEX IF NOT EXISTS idx_organizations_admin ON organizations(admin_amid);

-- Add organization_id to agents table if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agents' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE agents ADD COLUMN organization_id UUID REFERENCES organizations(id);
    END IF;
END $$;

-- Index for looking up agents by organization
CREATE INDEX IF NOT EXISTS idx_agents_organization ON agents(organization_id);
