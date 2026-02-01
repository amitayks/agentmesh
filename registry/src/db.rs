use sqlx::{PgPool, Row};
use anyhow::Result;
use chrono::Utc;

use crate::models::*;

/// Create a new agent in the database
pub async fn create_agent(pool: &PgPool, agent: &Agent) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO agents (
            id, amid, signing_public_key, exchange_public_key, tier,
            display_name, organization_id, capabilities, relay_endpoint,
            direct_endpoint, status, reputation_score, last_seen,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
        )
        "#
    )
    .bind(&agent.id)
    .bind(&agent.amid)
    .bind(&agent.signing_public_key)
    .bind(&agent.exchange_public_key)
    .bind(&agent.tier)
    .bind(&agent.display_name)
    .bind(&agent.organization_id)
    .bind(&agent.capabilities)
    .bind(&agent.relay_endpoint)
    .bind(&agent.direct_endpoint)
    .bind(&agent.status)
    .bind(agent.reputation_score)
    .bind(&agent.last_seen)
    .bind(&agent.created_at)
    .bind(&agent.updated_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get an agent by AMID
pub async fn get_agent_by_amid(pool: &PgPool, amid: &str) -> Result<Option<Agent>> {
    let agent = sqlx::query_as::<_, Agent>(
        r#"
        SELECT id, amid, signing_public_key, exchange_public_key, tier,
               display_name, organization_id, capabilities, relay_endpoint,
               direct_endpoint, status, reputation_score, last_seen,
               created_at, updated_at
        FROM agents
        WHERE amid = $1
        "#
    )
    .bind(amid)
    .fetch_optional(pool)
    .await?;

    Ok(agent)
}

/// Search agents by capability
pub async fn search_by_capability(
    pool: &PgPool,
    req: &CapabilitySearchRequest,
) -> Result<(Vec<Agent>, u64)> {
    // Count total
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM agents
        WHERE $1 = ANY(capabilities)
        AND ($2 IS NULL OR
             CASE tier
                WHEN 'organization' THEN 1
                WHEN 'verified' THEN 1
                ELSE 2
             END <= $2)
        AND ($3 IS NULL OR reputation_score >= $3)
        AND ($4 IS NULL OR status = $4)
        "#
    )
    .bind(&req.capability)
    .bind(req.tier_min.map(|t| t as i32))
    .bind(req.reputation_min)
    .bind(&req.status)
    .fetch_one(pool)
    .await?;

    // Fetch page
    let agents = sqlx::query_as::<_, Agent>(
        r#"
        SELECT id, amid, signing_public_key, exchange_public_key, tier,
               display_name, organization_id, capabilities, relay_endpoint,
               direct_endpoint, status, reputation_score, last_seen,
               created_at, updated_at
        FROM agents
        WHERE $1 = ANY(capabilities)
        AND ($2 IS NULL OR
             CASE tier
                WHEN 'organization' THEN 1
                WHEN 'verified' THEN 1
                ELSE 2
             END <= $2)
        AND ($3 IS NULL OR reputation_score >= $3)
        AND ($4 IS NULL OR status = $4)
        ORDER BY reputation_score DESC, last_seen DESC
        LIMIT $5 OFFSET $6
        "#
    )
    .bind(&req.capability)
    .bind(req.tier_min.map(|t| t as i32))
    .bind(req.reputation_min)
    .bind(&req.status)
    .bind(req.limit as i64)
    .bind(req.offset as i64)
    .fetch_all(pool)
    .await?;

    Ok((agents, total as u64))
}

/// Update agent status
pub async fn update_agent_status(
    pool: &PgPool,
    amid: &str,
    status: PresenceStatus,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE agents
        SET status = $2, last_seen = $3, updated_at = $3
        WHERE amid = $1
        "#
    )
    .bind(amid)
    .bind(status)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Update agent capabilities
pub async fn update_agent_capabilities(
    pool: &PgPool,
    amid: &str,
    capabilities: &[String],
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE agents
        SET capabilities = $2, updated_at = $3
        WHERE amid = $1
        "#
    )
    .bind(amid)
    .bind(capabilities)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get basic stats (total agents, online agents)
pub async fn get_stats(pool: &PgPool) -> Result<(u64, u64)> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents")
        .fetch_one(pool)
        .await?;

    let online: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agents WHERE status = 'online'"
    )
    .fetch_one(pool)
    .await?;

    Ok((total as u64, online as u64))
}

/// Get detailed registry statistics
pub async fn get_detailed_stats(pool: &PgPool) -> Result<serde_json::Value> {
    let (total, online) = get_stats(pool).await?;

    let by_tier: Vec<(String, i64)> = sqlx::query_as(
        "SELECT tier::text, COUNT(*) FROM agents GROUP BY tier"
    )
    .fetch_all(pool)
    .await?;

    let by_status: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status::text, COUNT(*) FROM agents GROUP BY status"
    )
    .fetch_all(pool)
    .await?;

    let avg_reputation: f64 = sqlx::query_scalar(
        "SELECT COALESCE(AVG(reputation_score), 0.5) FROM agents"
    )
    .fetch_one(pool)
    .await?;

    Ok(serde_json::json!({
        "total_agents": total,
        "online_agents": online,
        "by_tier": by_tier.into_iter().collect::<std::collections::HashMap<_, _>>(),
        "by_status": by_status.into_iter().collect::<std::collections::HashMap<_, _>>(),
        "average_reputation": avg_reputation,
    }))
}

impl Default for (u64, u64) {
    fn default() -> Self {
        (0, 0)
    }
}
