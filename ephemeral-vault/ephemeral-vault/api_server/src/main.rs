use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;

// ==================== APPLICATION STATE ====================

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub session_manager: Arc<SessionManager>,
    pub deposit_calculator: Arc<AutoDepositCalculator>,
    pub delegation_manager: Arc<DelegationManager>,
    pub vault_monitor: Arc<VaultMonitor>,
    pub tx_signer: Arc<TransactionSigner>,
    pub event_tx: broadcast::Sender<VaultEvent>,
}

// ==================== REQUEST/RESPONSE MODELS ====================

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub parent_wallet: String,
    pub session_duration: i64,
    pub approved_amount: u64,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub ephemeral_wallet: String,
    pub vault_pda: String,
    pub expires_at: i64,
    pub approval_required: bool,
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub session_id: String,
    pub parent_signature: String,
}

#[derive(Serialize)]
pub struct ApproveResponse {
    pub success: bool,
    pub delegation_signature: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct DepositRequest {
    pub session_id: String,
    pub amount: Option<u64>,
    pub estimated_trades: Option<u32>,
}

#[derive(Serialize)]
pub struct DepositResponse {
    pub success: bool,
    pub deposit_amount: u64,
    pub transaction_signature: String,
    pub new_balance: u64,
}

#[derive(Serialize)]
pub struct SessionStatusResponse {
    pub session_id: String,
    pub parent_wallet: String,
    pub ephemeral_wallet: String,
    pub vault_pda: String,
    pub is_active: bool,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_activity: i64,
    pub total_deposited: u64,
    pub total_spent: u64,
    pub remaining_balance: u64,
    pub total_trades: i32,
    pub time_remaining: i64,
}

#[derive(Serialize)]
pub struct RevokeResponse {
    pub success: bool,
    pub returned_amount: u64,
    pub transaction_signature: String,
}

#[derive(Serialize, Clone)]
pub struct VaultEvent {
    pub event_type: String,
    pub session_id: String,
    pub timestamp: i64,
    pub data: serde_json::Value,
}

// ==================== API ROUTES ====================

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Session management
        .route("/session/create", post(create_session))
        .route("/session/approve", post(approve_delegation))
        .route("/session/:session_id", get(get_session_status))
        .route("/session/:session_id/revoke", delete(revoke_session))
        
        // Deposits
        .route("/session/deposit", post(trigger_deposit))
        
        // Monitoring
        .route("/session/active", get(list_active_sessions))
        .route("/session/:session_id/analytics", get(get_session_analytics))
        
        // WebSocket
        .route("/ws/:session_id", get(websocket_handler))
        
        // Health check
        .route("/health", get(health_check))
        
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ==================== HANDLER IMPLEMENTATIONS ====================

async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, ApiError> {
    // Validate request
    if req.session_duration <= 0 || req.session_duration > 86400 {
        return Err(ApiError::BadRequest("Invalid session duration".to_string()));
    }

    let parent_wallet = req.parent_wallet.parse()
        .map_err(|_| ApiError::BadRequest("Invalid parent wallet".to_string()))?;

    // Check rate limits
    check_rate_limit(&state.db, &req.parent_wallet, "session_create").await?;

    // Create session
    let session = state.session_manager
        .create_session(parent_wallet, req.session_duration, req.approved_amount)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Log audit event
    log_audit_event(
        &state.db,
        Some(&session.session_id),
        &req.parent_wallet,
        "session_create",
        &req.parent_wallet,
        true,
        None,
    ).await?;

    // Broadcast event
    let _ = state.event_tx.send(VaultEvent {
        event_type: "session_created".to_string(),
        session_id: session.session_id.clone(),
        timestamp: chrono::Utc::now().timestamp(),
        data: serde_json::json!({
            "parent_wallet": req.parent_wallet,
            "expires_at": session.expires_at,
        }),
    });

    Ok(Json(CreateSessionResponse {
        session_id: session.session_id,
        ephemeral_wallet: session.ephemeral_keypair.pubkey().to_string(),
        vault_pda: session.vault_pda.to_string(),
        expires_at: session.expires_at,
        approval_required: true,
    }))
}

async fn approve_delegation(
    State(state): State<AppState>,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    // Get session
    let session = state.session_manager
        .get_session(&req.session_id)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;

    // Verify signature (implementation needed)
    // verify_parent_signature(&req.parent_signature, &session)?;

    // Build delegation transaction
    let delegation_ix = state.delegation_manager.build_approve_delegation_ix(
        &session.parent_wallet,
        &session.ephemeral_keypair.pubkey(),
        &session.vault_pda,
    );

    // Sign and send transaction
    // let signature = state.tx_signer.sign_and_send_transaction(...).await?;

    // Record delegation
    sqlx::query(
        "INSERT INTO delegation_history 
        (session_id, vault_pda, delegate_wallet, approved_at, approval_signature)
        VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(&req.session_id)
    .bind(session.vault_pda.to_string())
    .bind(session.ephemeral_keypair.pubkey().to_string())
    .bind(chrono::Utc::now().timestamp())
    .bind(&req.parent_signature)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(e))?;

    // Broadcast event
    let _ = state.event_tx.send(VaultEvent {
        event_type: "delegation_approved".to_string(),
        session_id: req.session_id.clone(),
        timestamp: chrono::Utc::now().timestamp(),
        data: serde_json::json!({
            "delegate": session.ephemeral_keypair.pubkey().to_string(),
        }),
    });

    Ok(Json(ApproveResponse {
        success: true,
        delegation_signature: req.parent_signature,
        message: "Delegation approved successfully".to_string(),
    }))
}

async fn trigger_deposit(
    State(state): State<AppState>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, ApiError> {
    let session = state.session_manager
        .get_session(&req.session_id)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;

    // Calculate deposit amount
    let deposit_amount = if let Some(amount) = req.amount {
        amount
    } else {
        let trades = req.estimated_trades.unwrap_or(10);
        state.deposit_calculator.calculate_deposit_amount(trades)
    };

    // Check limits
    if deposit_amount > 10_000_000 {
        return Err(ApiError::BadRequest("Deposit amount exceeds limit".to_string()));
    }

    // Build and send deposit transaction
    // let signature = ...

    // Record transaction
    sqlx::query(
        "INSERT INTO vault_transactions 
        (session_id, transaction_signature, transaction_type, amount, status)
        VALUES ($1, $2, 'deposit', $3, 'confirmed')"
    )
    .bind(&req.session_id)
    .bind("mock_signature") // Replace with actual signature
    .bind(deposit_amount as i64)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(e))?;

    // Update session
    sqlx::query(
        "UPDATE ephemeral_sessions 
        SET total_deposited = total_deposited + $1 
        WHERE session_id = $2"
    )
    .bind(deposit_amount as i64)
    .bind(&req.session_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(e))?;

    // Broadcast event
    let _ = state.event_tx.send(VaultEvent {
        event_type: "deposit_completed".to_string(),
        session_id: req.session_id.clone(),
        timestamp: chrono::Utc::now().timestamp(),
        data: serde_json::json!({
            "amount": deposit_amount,
        }),
    });

    Ok(Json(DepositResponse {
        success: true,
        deposit_amount,
        transaction_signature: "mock_signature".to_string(),
        new_balance: session.total_deposited + deposit_amount,
    }))
}

async fn get_session_status(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, ApiError> {
    let session = state.session_manager
        .get_session(&session_id)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;

    // Get analytics
    let analytics = sqlx::query(
        "SELECT total_trades FROM session_analytics WHERE session_id = $1"
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(e))?;

    let total_trades = analytics
        .and_then(|r| r.get::<Option<i32>, _>("total_trades"))
        .unwrap_or(0);

    let now = chrono::Utc::now().timestamp();
    let time_remaining = if session.expires_at > now {
        session.expires_at - now
    } else {
        0
    };

    Ok(Json(SessionStatusResponse {
        session_id: session.session_id,
        parent_wallet: session.parent_wallet.to_string(),
        ephemeral_wallet: session.ephemeral_keypair.pubkey().to_string(),
        vault_pda: session.vault_pda.to_string(),
        is_active: session.is_active,
        created_at: session.created_at,
        expires_at: session.expires_at,
        last_activity: session.created_at, // Should fetch from DB
        total_deposited: session.total_deposited,
        total_spent: session.total_spent,
        remaining_balance: session.total_deposited - session.total_spent,
        total_trades,
        time_remaining,
    }))
}

async fn revoke_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<RevokeResponse>, ApiError> {
    let session = state.session_manager
        .get_session(&session_id)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;

    // Build revoke transaction
    // let signature = ...

    let returned = session.total_deposited - session.total_spent;

    // Revoke in database
    state.session_manager
        .revoke_session(&session_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Broadcast event
    let _ = state.event_tx.send(VaultEvent {
        event_type: "session_revoked".to_string(),
        session_id: session_id.clone(),
        timestamp: chrono::Utc::now().timestamp(),
        data: serde_json::json!({
            "returned_amount": returned,
        }),
    });

    Ok(Json(RevokeResponse {
        success: true,
        returned_amount: returned,
        transaction_signature: "mock_signature".to_string(),
    }))
}

async fn list_active_sessions(
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionStatusResponse>>, ApiError> {
    let rows = sqlx::query(
        "SELECT * FROM active_sessions_view LIMIT 100"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::Database(e))?;

    let sessions: Vec<SessionStatusResponse> = rows.iter().map(|row| {
        let expires_at: i64 = row.get("expires_at");
        let now = chrono::Utc::now().timestamp();
        
        SessionStatusResponse {
            session_id: row.get("session_id"),
            parent_wallet: row.get("parent_wallet"),
            ephemeral_wallet: String::new(), // Not in view
            vault_pda: row.get("vault_pda"),
            is_active: true,
            created_at: row.get("created_at"),
            expires_at,
            last_activity: 0,
            total_deposited: row.get::<i64, _>("total_deposited") as u64,
            total_spent: row.get::<i64, _>("total_spent") as u64,
            remaining_balance: row.get::<i64, _>("remaining_balance") as u64,
            total_trades: row.get::<Option<i32>, _>("total_trades").unwrap_or(0),
            time_remaining: if expires_at > now { expires_at - now } else { 0 },
        }
    }).collect();

    Ok(Json(sessions))
}

async fn get_session_analytics(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let analytics = sqlx::query(
        "SELECT * FROM session_analytics WHERE session_id = $1"
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(e))?
    .ok_or_else(|| ApiError::NotFound("Analytics not found".to_string()))?;

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "total_trades": analytics.get::<i32, _>("total_trades"),
        "successful_trades": analytics.get::<i32, _>("successful_trades"),
        "failed_trades": analytics.get::<i32, _>("failed_trades"),
        "total_volume": analytics.get::<i64, _>("total_volume"),
        "total_fees_paid": analytics.get::<i64, _>("total_fees_paid"),
    })))
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp(),
    }))
}

// ==================== WEBSOCKET HANDLER ====================

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Response {
    ws.on_upgrade(move |socket| handle_websocket(socket, state, session_id))
}

async fn handle_websocket(
    mut socket: axum::extract::ws::WebSocket,
    state: AppState,
    session_id: String,
) {
    use axum::extract::ws::Message;
    
    let mut event_rx = state.event_tx.subscribe();

    loop {
        tokio::select! {
            Ok(event) = event_rx.recv() => {
                if event.session_id == session_id {
                    let json = serde_json::to_string(&event).unwrap();
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            Some(msg) = socket.recv() => {
                if msg.is_err() {
                    break;
                }
            }
        }
    }
}

// ==================== HELPER FUNCTIONS ====================

async fn check_rate_limit(
    db: &PgPool,
    wallet: &str,
    action: &str,
) -> Result<(), ApiError> {
    // Rate limiting logic
    Ok(())
}

async fn log_audit_event(
    db: &PgPool,
    session_id: Option<&str>,
    parent_wallet: &str,
    action: &str,
    actor: &str,
    success: bool,
    error: Option<String>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_log 
        (session_id, parent_wallet, action, actor, success, error_message)
        VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(session_id)
    .bind(parent_wallet)
    .bind(action)
    .bind(actor)
    .bind(success)
    .bind(error)
    .execute(db)
    .await
    .map_err(|e| ApiError::Database(e))?;

    Ok(())
}

// ==================== ERROR HANDLING ====================

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
    Database(sqlx::Error),
    Unauthorized,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::Database(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
        };

        (status, Json(serde_json::json!({
            "error": message,
        }))).into_response()
    }
}

// Placeholder imports - need actual implementations
use crate::session_manager::{SessionManager, AutoDepositCalculator, DelegationManager, VaultMonitor, TransactionSigner};