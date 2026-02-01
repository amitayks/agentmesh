use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;
use chrono::Utc;
use uuid::Uuid;
use tracing::{info, warn, error};

use crate::models::*;
use crate::db;

/// Configure all routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            .route("/health", web::get().to(health_check))
            .route("/registry/register", web::post().to(register_agent))
            .route("/registry/lookup", web::get().to(lookup_agent))
            .route("/registry/search", web::get().to(search_capabilities))
            .route("/registry/status", web::post().to(update_status))
            .route("/registry/capabilities", web::post().to(update_capabilities))
            .route("/registry/reputation", web::post().to(submit_reputation))
            .route("/registry/stats", web::get().to(registry_stats))
    );
}

/// Health check endpoint
async fn health_check(pool: web::Data<PgPool>) -> impl Responder {
    let stats = db::get_stats(&pool).await.unwrap_or_default();

    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        version: "agentmesh/0.1".to_string(),
        agents_registered: stats.0,
        agents_online: stats.1,
    })
}

/// Register a new agent
async fn register_agent(
    pool: web::Data<PgPool>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    info!("Registration request for AMID: {}", req.amid);

    // Validate AMID matches public key
    // TODO: Full cryptographic verification

    // Check if already registered
    if let Ok(Some(_)) = db::get_agent_by_amid(&pool, &req.amid).await {
        return HttpResponse::Conflict().json(RegisterResponse {
            success: false,
            amid: req.amid.clone(),
            tier: TrustTier::Anonymous,
            certificate: None,
            error: Some("AMID already registered".to_string()),
        });
    }

    // Determine tier
    let tier = if req.verification_token.is_some() {
        // TODO: Verify OAuth token
        TrustTier::Verified
    } else {
        TrustTier::Anonymous
    };

    // Create agent record
    let agent = Agent {
        id: Uuid::new_v4(),
        amid: req.amid.clone(),
        signing_public_key: req.signing_public_key.clone(),
        exchange_public_key: req.exchange_public_key.clone(),
        tier,
        display_name: req.display_name.clone(),
        organization_id: None,
        capabilities: req.capabilities.clone(),
        relay_endpoint: req.relay_endpoint.clone(),
        direct_endpoint: req.direct_endpoint.clone(),
        status: PresenceStatus::Offline,
        reputation_score: match tier {
            TrustTier::Anonymous => 0.5,
            TrustTier::Verified => 0.6,
            TrustTier::Organization => 0.7,
        },
        last_seen: Utc::now(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    match db::create_agent(&pool, &agent).await {
        Ok(_) => {
            info!("Agent {} registered successfully (tier: {:?})", agent.amid, tier);
            HttpResponse::Created().json(RegisterResponse {
                success: true,
                amid: agent.amid,
                tier,
                certificate: None, // TODO: Generate certificate for verified agents
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to register agent: {}", e);
            HttpResponse::InternalServerError().json(RegisterResponse {
                success: false,
                amid: req.amid.clone(),
                tier: TrustTier::Anonymous,
                certificate: None,
                error: Some("Registration failed".to_string()),
            })
        }
    }
}

/// Lookup an agent by AMID
async fn lookup_agent(
    pool: web::Data<PgPool>,
    query: web::Query<AmidQuery>,
) -> impl Responder {
    match db::get_agent_by_amid(&pool, &query.amid).await {
        Ok(Some(agent)) => {
            HttpResponse::Ok().json(AgentLookup {
                amid: agent.amid,
                tier: agent.tier,
                display_name: agent.display_name,
                organization: None, // TODO: Lookup org name
                signing_public_key: agent.signing_public_key,
                exchange_public_key: agent.exchange_public_key,
                capabilities: agent.capabilities,
                relay_endpoint: agent.relay_endpoint,
                direct_endpoint: agent.direct_endpoint,
                status: agent.status,
                reputation_score: agent.reputation_score,
                last_seen: agent.last_seen,
            })
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Agent not found"
        })),
        Err(e) => {
            error!("Database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }))
        }
    }
}

#[derive(serde::Deserialize)]
struct AmidQuery {
    amid: String,
}

/// Search for agents by capability
async fn search_capabilities(
    pool: web::Data<PgPool>,
    query: web::Query<CapabilitySearchRequest>,
) -> impl Responder {
    match db::search_by_capability(&pool, &query).await {
        Ok((agents, total)) => {
            let results: Vec<AgentLookup> = agents.into_iter().map(|a| AgentLookup {
                amid: a.amid,
                tier: a.tier,
                display_name: a.display_name,
                organization: None,
                signing_public_key: a.signing_public_key,
                exchange_public_key: a.exchange_public_key,
                capabilities: a.capabilities,
                relay_endpoint: a.relay_endpoint,
                direct_endpoint: a.direct_endpoint,
                status: a.status,
                reputation_score: a.reputation_score,
                last_seen: a.last_seen,
            }).collect();

            HttpResponse::Ok().json(CapabilitySearchResponse {
                results,
                total,
                limit: query.limit,
                offset: query.offset,
            })
        }
        Err(e) => {
            error!("Search error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Search failed"
            }))
        }
    }
}

/// Update agent presence status
async fn update_status(
    pool: web::Data<PgPool>,
    req: web::Json<StatusUpdateRequest>,
) -> impl Responder {
    // TODO: Verify signature

    match db::update_agent_status(&pool, &req.amid, req.status).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "success": true
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Agent not found"
        })),
        Err(e) => {
            error!("Status update error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Update failed"
            }))
        }
    }
}

/// Update agent capabilities
async fn update_capabilities(
    pool: web::Data<PgPool>,
    req: web::Json<CapabilitiesUpdateRequest>,
) -> impl Responder {
    // TODO: Verify signature

    match db::update_agent_capabilities(&pool, &req.amid, &req.capabilities).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "success": true
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Agent not found"
        })),
        Err(e) => {
            error!("Capabilities update error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Update failed"
            }))
        }
    }
}

/// Submit reputation feedback
async fn submit_reputation(
    pool: web::Data<PgPool>,
    req: web::Json<ReputationUpdate>,
) -> impl Responder {
    // TODO: Verify signature and implement reputation calculation

    // Validate score
    if req.score < 0.0 || req.score > 1.0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Score must be between 0.0 and 1.0"
        }));
    }

    // For now, just acknowledge receipt
    // Full implementation would weight by tier, check for gaming, etc.
    info!("Reputation update: {} -> {} = {}", req.from_amid, req.target_amid, req.score);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Reputation feedback recorded"
    }))
}

/// Get registry statistics
async fn registry_stats(pool: web::Data<PgPool>) -> impl Responder {
    match db::get_detailed_stats(&pool).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            error!("Stats error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get stats"
            }))
        }
    }
}
