use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;
use chrono::Utc;
use uuid::Uuid;
use tracing::{info, warn, error};

use crate::auth;
use crate::models::*;
use crate::db;
use crate::oauth::{self, OAuthConfig};
use crate::org;
use crate::revocation;
use crate::reputation;
use crate::certs;

/// Configure all routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    // Load OAuth configuration from environment
    let oauth_config = OAuthConfig::from_env();

    cfg.service(
        web::scope("/v1")
            // Health check
            .route("/health", web::get().to(health_check))
            // Registry endpoints
            .route("/registry/register", web::post().to(register_agent))
            .route("/registry/lookup", web::get().to(lookup_agent))
            .route("/registry/search", web::get().to(search_capabilities))
            .route("/registry/status", web::post().to(update_status))
            .route("/registry/capabilities", web::post().to(update_capabilities))
            .route("/registry/reputation", web::post().to(submit_reputation))
            .route("/registry/stats", web::get().to(registry_stats))
            .route("/registry/prekeys/{amid}", web::get().to(get_prekeys))
            .route("/registry/prekeys", web::post().to(upload_prekeys))
            // OAuth endpoints for tier verification
            .app_data(web::Data::new(oauth_config))
            .route("/auth/oauth/providers", web::get().to(oauth::get_providers))
            .route("/auth/oauth/authorize", web::post().to(oauth::authorize))
            .route("/auth/oauth/callback", web::get().to(oauth::callback))
            // Organization endpoints
            .route("/org/register", web::post().to(org::register_org))
            .route("/org/verify", web::post().to(org::verify_dns))
            .route("/org/agents", web::post().to(org::register_org_agent))
            .route("/org/lookup", web::get().to(org::lookup_org))
            // Revocation endpoints
            .route("/registry/revoke", web::post().to(revocation::revoke_agent))
            .route("/registry/revocation", web::get().to(revocation::check_revocation))
            .route("/registry/revocations/bulk", web::post().to(revocation::bulk_check_revocation))
            .route("/registry/revocations", web::get().to(revocation::get_revocation_list))
            // Reputation endpoints
            .route("/registry/reputation/score", web::get().to(reputation::calculate_reputation))
            .route("/registry/reputation/feedback", web::post().to(reputation::submit_feedback))
            .route("/registry/reputation/session", web::post().to(reputation::record_session))
            .route("/registry/reputation/leaderboard", web::get().to(reputation::leaderboard))
            // DID resolution endpoint
            .route("/registry/did/{amid}", web::get().to(resolve_did))
    );
}

/// Issue an agent certificate for verified agents
fn issue_agent_certificate(amid: &str, signing_public_key: &str, tier: TrustTier) -> Result<String, String> {
    match tier {
        TrustTier::Verified | TrustTier::Organization => {
            certs::issue_agent_certificate(amid, signing_public_key, tier)
        }
        TrustTier::Anonymous => {
            Err("Certificates not issued for anonymous tier".to_string())
        }
    }
}

/// Resolve DID document for an agent
async fn resolve_did(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> impl Responder {
    let amid = path.into_inner();

    match db::get_agent_by_amid(&pool, &amid).await {
        Ok(Some(agent)) => {
            // Construct DID document
            let did = format!("did:agentmesh:{}", amid);
            let did_document = serde_json::json!({
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1",
                    "https://w3id.org/security/suites/x25519-2020/v1"
                ],
                "id": did,
                "controller": did,
                "verificationMethod": [
                    {
                        "id": format!("{}#signing-key", did),
                        "type": "Ed25519VerificationKey2020",
                        "controller": did,
                        "publicKeyMultibase": format!("z{}", agent.signing_public_key)
                    },
                    {
                        "id": format!("{}#key-agreement-key", did),
                        "type": "X25519KeyAgreementKey2020",
                        "controller": did,
                        "publicKeyMultibase": format!("z{}", agent.exchange_public_key)
                    }
                ],
                "authentication": [format!("{}#signing-key", did)],
                "keyAgreement": [format!("{}#key-agreement-key", did)],
                "service": [
                    {
                        "id": format!("{}#relay", did),
                        "type": "AgentMeshRelay",
                        "serviceEndpoint": agent.relay_endpoint
                    }
                ],
                "created": agent.created_at.to_rfc3339(),
                "updated": agent.updated_at.to_rfc3339()
            });

            HttpResponse::Ok()
                .content_type("application/did+ld+json")
                .json(did_document)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "DID not found"
        })),
        Err(e) => {
            error!("Database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }))
        }
    }
}

/// Health check endpoint
async fn health_check(pool: web::Data<PgPool>) -> impl Responder {
    let stats = db::get_stats(&pool).await.unwrap_or_default();

    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        version: "agentmesh/0.2".to_string(),
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

    // Verify signature proves ownership of AMID
    if let Err(auth_err) = auth::verify_registration_signature(
        &req.amid,
        &req.signing_public_key,
        &req.signature,
        req.timestamp,
    ) {
        warn!("Signature verification failed for {}: {:?}", req.amid, auth_err);
        return HttpResponse::Unauthorized().json(RegisterResponse {
            success: false,
            amid: req.amid.clone(),
            tier: TrustTier::Anonymous,
            certificate: None,
            error: Some(format!("Signature verification failed: {}", auth_err)),
        });
    }

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

    // Determine tier and validate OAuth token
    let (tier, certificate) = if let Some(ref token) = req.verification_token {
        // Verify OAuth token
        match oauth::validate_oauth_token(token).await {
            Ok(validated_user) => {
                info!("OAuth token validated for user: {:?}", validated_user);
                // Issue certificate for verified agent
                let cert = issue_agent_certificate(&req.amid, &req.signing_public_key, TrustTier::Verified);
                (TrustTier::Verified, cert.ok())
            }
            Err(e) => {
                warn!("OAuth token validation failed: {}", e);
                (TrustTier::Anonymous, None)
            }
        }
    } else {
        (TrustTier::Anonymous, None)
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
                certificate,
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
            // Get organization name if applicable
            let organization = if let Some(org_id) = agent.organization_id {
                db::get_organization_name(&pool, org_id).await.ok().flatten()
            } else {
                None
            };

            // Get reputation details
            let (ratings_count, flags) = db::get_agent_reputation_details(&pool, &agent.amid)
                .await
                .unwrap_or((0, vec![]));

            // Determine reputation status (rated if >= 5 ratings)
            let reputation_status = if ratings_count >= 5 {
                Some("rated".to_string())
            } else {
                Some("unrated".to_string())
            };

            // Get certificate if verified
            let certificate = db::get_agent_certificate(&pool, &agent.amid)
                .await
                .ok()
                .flatten();

            HttpResponse::Ok().json(AgentLookup {
                amid: agent.amid,
                tier: agent.tier,
                display_name: agent.display_name,
                organization,
                signing_public_key: agent.signing_public_key,
                exchange_public_key: agent.exchange_public_key,
                capabilities: agent.capabilities,
                relay_endpoint: agent.relay_endpoint,
                direct_endpoint: agent.direct_endpoint,
                status: agent.status,
                reputation_score: agent.reputation_score,
                last_seen: agent.last_seen,
                certificate,
                flags: if flags.is_empty() { None } else { Some(flags) },
                ratings_count: Some(ratings_count),
                reputation_status,
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
    // Look up agent to get public key
    let agent = match db::get_agent_by_amid(&pool, &req.amid).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Agent not found"
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }));
        }
    };

    // Verify signature using stored public key
    if let Err(auth_err) = auth::verify_update_signature(
        &agent.signing_public_key,
        req.timestamp,
        &req.signature,
    ) {
        warn!("Status update signature verification failed for {}: {:?}", req.amid, auth_err);
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": format!("Signature verification failed: {}", auth_err)
        }));
    }

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
    // Look up agent to get public key
    let agent = match db::get_agent_by_amid(&pool, &req.amid).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Agent not found"
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }));
        }
    };

    // Verify signature using stored public key
    if let Err(auth_err) = auth::verify_update_signature(
        &agent.signing_public_key,
        req.timestamp,
        &req.signature,
    ) {
        warn!("Capabilities update signature verification failed for {}: {:?}", req.amid, auth_err);
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": format!("Signature verification failed: {}", auth_err)
        }));
    }

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

/// Submit reputation feedback with anti-gaming measures
async fn submit_reputation(
    pool: web::Data<PgPool>,
    req: web::Json<ReputationUpdate>,
    http_req: actix_web::HttpRequest,
) -> impl Responder {
    // Validate score
    if req.score < 0.0 || req.score > 1.0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Score must be between 0.0 and 1.0"
        }));
    }

    // Validate tags if provided
    if let Some(ref tags) = req.tags {
        for tag in tags {
            if !db::RATING_TAGS.contains(&tag.as_str()) {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid tag: {}. Valid tags: {:?}", tag, db::RATING_TAGS)
                }));
            }
        }
    }

    // Get rater's tier from database
    let rater_tier = match db::get_agent_by_amid(&pool, &req.from_amid).await {
        Ok(Some(agent)) => agent.tier,
        Ok(None) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Rater agent not found"
            }));
        }
        Err(e) => {
            error!("Database error looking up rater: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // Get IP hash for anti-gaming (use SHA256 of IP + daily salt)
    let rater_ip_hash = http_req
        .connection_info()
        .realip_remote_addr()
        .map(|ip| {
            use sha2::{Sha256, Digest};
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}", ip, today).as_bytes());
            format!("{:x}", hasher.finalize())[..16].to_string()
        });

    // Submit rating with anti-gaming measures
    match db::submit_reputation_rating(
        &pool,
        &req.target_amid,
        &req.from_amid,
        rater_tier,
        req.session_id,
        req.score,
        req.tags.clone(),
        rater_ip_hash.as_deref(),
    ).await {
        Ok(()) => {
            info!("Reputation update: {} -> {} = {} (tier: {:?})",
                  req.from_amid, req.target_amid, req.score, rater_tier);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Reputation feedback recorded"
            }))
        }
        Err(e) => {
            error!("Failed to submit reputation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record feedback"
            }))
        }
    }
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

/// Get prekeys for an agent (consumes one one-time prekey)
async fn get_prekeys(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> impl Responder {
    let amid = path.into_inner();

    // Get agent to verify they exist and get identity key
    let agent = match db::get_agent_by_amid(&pool, &amid).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Agent not found"
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }));
        }
    };

    // Get signed prekey
    let signed_prekey = match db::get_signed_prekey(&pool, &amid).await {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "No prekeys available for this agent"
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }));
        }
    };

    // Consume one one-time prekey (if available)
    let one_time_prekey = match db::consume_one_time_prekey(&pool, &amid).await {
        Ok(pk) => pk.map(|(id, key)| OneTimePrekey { id, key }),
        Err(e) => {
            warn!("Failed to consume one-time prekey for {}: {}", amid, e);
            None
        }
    };

    HttpResponse::Ok().json(PrekeyResponse {
        identity_key: agent.exchange_public_key,
        signed_prekey: signed_prekey.1,
        signed_prekey_signature: signed_prekey.2,
        signed_prekey_id: signed_prekey.0,
        one_time_prekey,
    })
}

/// Upload prekeys for an agent
async fn upload_prekeys(
    pool: web::Data<PgPool>,
    req: web::Json<UploadPrekeysRequest>,
) -> impl Responder {
    // Look up agent to verify they exist and get their public key
    let agent = match db::get_agent_by_amid(&pool, &req.amid).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Agent not found"
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }));
        }
    };

    // Verify signature
    if let Err(auth_err) = auth::verify_update_signature(
        &agent.signing_public_key,
        req.timestamp,
        &req.signature,
    ) {
        warn!("Prekey upload signature verification failed for {}: {:?}", req.amid, auth_err);
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": format!("Signature verification failed: {}", auth_err)
        }));
    }

    // Store signed prekey
    if let Err(e) = db::upsert_signed_prekey(
        &pool,
        &req.amid,
        req.signed_prekey_id,
        &req.signed_prekey,
        &req.signed_prekey_signature,
    ).await {
        error!("Failed to store signed prekey: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to store signed prekey"
        }));
    }

    // Store one-time prekeys
    let one_time_keys: Vec<(i32, String)> = req.one_time_prekeys
        .iter()
        .map(|pk| (pk.id, pk.key.clone()))
        .collect();

    if let Err(e) = db::store_one_time_prekeys(&pool, &req.amid, &one_time_keys).await {
        error!("Failed to store one-time prekeys: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to store one-time prekeys"
        }));
    }

    info!("Uploaded {} one-time prekeys for {}", req.one_time_prekeys.len(), req.amid);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "signed_prekey_id": req.signed_prekey_id,
        "one_time_prekeys_stored": req.one_time_prekeys.len()
    }))
}
