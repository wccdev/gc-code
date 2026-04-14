mod config;
mod crypto;
mod handlers;
mod state;

use anyhow::Result;
use axum::{Router, routing::get};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::config::AdapterConfig;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "casdoor_adapter=info".into()),
        )
        .init();

    let config = AdapterConfig::from_env()?;
    let listen_addr = config.listen_addr.clone();
    let state = Arc::new(AppState::new(config));

    let app = Router::new()
        .route("/native_app_signin", get(handlers::native_app_signin))
        .route(
            "/native_app_signin_succeeded",
            get(handlers::signin_succeeded),
        )
        .route("/casdoor/callback", get(handlers::casdoor_callback))
        .route("/client/users/me", get(handlers::get_authenticated_user))
        .route("/rpc", get(handlers::rpc_redirect))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("Casdoor adapter listening on {listen_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
