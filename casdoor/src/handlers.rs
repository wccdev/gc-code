use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::state::{AppState, PendingSession, UserToken};

// ---------------------------------------------------------------------------
// GET /native_app_signin?native_app_port=PORT&native_app_public_key=KEY
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignInParams {
    native_app_port: u16,
    native_app_public_key: String,
}

pub async fn native_app_signin(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SignInParams>,
) -> Response {
    let session_state = crypto::random_token();

    state
        .pending_sessions
        .lock()
        .expect("pending_sessions lock poisoned")
        .insert(
            session_state.clone(),
            PendingSession {
                native_app_port: params.native_app_port,
                native_app_public_key: params.native_app_public_key,
            },
        );

    let redirect_uri = format!("{}/casdoor/callback", state.config.adapter_public_url);
    let authorize_url = state
        .config
        .casdoor_authorize_url(&redirect_uri, &session_state);

    Redirect::temporary(&authorize_url).into_response()
}

// ---------------------------------------------------------------------------
// GET /casdoor/callback?code=CODE&state=STATE
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct CasdoorUserInfo {
    #[serde(default)]
    sub: String,
    #[serde(default, alias = "preferred_username")]
    name: String,
    #[serde(default, alias = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, alias = "picture")]
    avatar: Option<String>,
}

pub async fn casdoor_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let session = {
        state
            .pending_sessions
            .lock()
            .expect("pending_sessions lock poisoned")
            .remove(&params.state)
    };
    let Some(session) = session else {
        return (StatusCode::BAD_REQUEST, "invalid or expired state parameter").into_response();
    };

    let redirect_uri = format!("{}/casdoor/callback", state.config.adapter_public_url);
    let token_result = state
        .http_client
        .post(&state.config.casdoor_token_url())
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &state.config.casdoor_client_id),
            ("client_secret", &state.config.casdoor_client_secret),
            ("code", &params.code),
            ("redirect_uri", &redirect_uri),
        ])
        .send()
        .await;

    let token_response = match token_result {
        Ok(resp) => match resp.json::<TokenResponse>().await {
            Ok(body) => body,
            Err(err) => {
                tracing::error!("failed to parse Casdoor token response: {err}");
                return (StatusCode::BAD_GATEWAY, "failed to exchange code for token")
                    .into_response();
            }
        },
        Err(err) => {
            tracing::error!("failed to request Casdoor token: {err}");
            return (StatusCode::BAD_GATEWAY, "failed to reach Casdoor").into_response();
        }
    };

    let userinfo_result = state
        .http_client
        .get(&state.config.casdoor_userinfo_url(&token_response.access_token))
        .send()
        .await;

    let user_info = match userinfo_result {
        Ok(resp) => match resp.json::<CasdoorUserInfo>().await {
            Ok(info) => info,
            Err(err) => {
                tracing::error!("failed to parse Casdoor userinfo: {err}");
                return (StatusCode::BAD_GATEWAY, "failed to get user info").into_response();
            }
        },
        Err(err) => {
            tracing::error!("failed to request Casdoor userinfo: {err}");
            return (StatusCode::BAD_GATEWAY, "failed to reach Casdoor").into_response();
        }
    };

    let user_id = state.get_or_create_user_id(&user_info.sub);
    let internal_token = crypto::random_token();

    state
        .tokens
        .lock()
        .expect("tokens lock poisoned")
        .insert(
            internal_token.clone(),
            UserToken {
                user_id,
                username: user_info.name.clone(),
                display_name: user_info.display_name.clone(),
                avatar_url: user_info.avatar.unwrap_or_default(),
                email: user_info.email.clone(),
            },
        );

    let encrypted_token =
        match crypto::encrypt_with_zed_public_key(&session.native_app_public_key, &internal_token)
        {
            Ok(t) => t,
            Err(err) => {
                tracing::error!("RSA encryption failed: {err}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "encryption failed").into_response();
            }
        };

    let redirect_url = format!(
        "http://127.0.0.1:{}/?user_id={}&access_token={}",
        session.native_app_port, user_id, encrypted_token,
    );

    Redirect::temporary(&redirect_url).into_response()
}

// ---------------------------------------------------------------------------
// GET /native_app_signin_succeeded
// ---------------------------------------------------------------------------

pub async fn signin_succeeded() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head><title>Sign In Succeeded</title></head>
<body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
  <div style="text-align: center;">
    <h1>Successfully signed in!</h1>
    <p>You can close this window and return to Zed.</p>
  </div>
</body>
</html>"#,
    )
}

// ---------------------------------------------------------------------------
// GET /client/users/me  (Authorization: <user_id> <access_token>)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct GetAuthenticatedUserResponse {
    user: AuthenticatedUser,
    feature_flags: Vec<String>,
    organizations: Vec<serde_json::Value>,
    default_organization_id: Option<String>,
    plans_by_organization: serde_json::Value,
    configuration_by_organization: serde_json::Value,
    plan: PlanInfo,
}

#[derive(Serialize)]
struct AuthenticatedUser {
    id: i64,
    metrics_id: String,
    avatar_url: String,
    github_login: String,
    name: Option<String>,
    is_staff: bool,
    accepted_tos_at: Option<String>,
}

#[derive(Serialize)]
struct PlanInfo {
    plan: String,
}

pub async fn get_authenticated_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth_header = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return (StatusCode::UNAUTHORIZED, "missing authorization header").into_response(),
    };

    let mut parts = auth_header.split_whitespace();
    let _user_id_str = parts.next().unwrap_or("");
    let access_token = match parts.next() {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, "malformed authorization header").into_response()
        }
    };

    let tokens = state.tokens.lock().expect("tokens lock poisoned");
    let Some(user_token) = tokens.get(access_token) else {
        return (StatusCode::UNAUTHORIZED, "invalid access token").into_response();
    };

    let response = GetAuthenticatedUserResponse {
        user: AuthenticatedUser {
            id: user_token.user_id,
            metrics_id: format!("casdoor-{}", user_token.user_id),
            avatar_url: user_token.avatar_url.clone(),
            github_login: user_token.username.clone(),
            name: user_token.display_name.clone(),
            is_staff: false,
            accepted_tos_at: None,
        },
        feature_flags: vec![],
        organizations: vec![],
        default_organization_id: None,
        plans_by_organization: serde_json::json!({}),
        configuration_by_organization: serde_json::json!({}),
        plan: PlanInfo {
            plan: "free".into(),
        },
    };

    Json(response).into_response()
}

// ---------------------------------------------------------------------------
// GET /rpc  →  302 to collab WebSocket
// ---------------------------------------------------------------------------

pub async fn rpc_redirect(State(state): State<Arc<AppState>>) -> Response {
    Redirect::temporary(&state.config.collab_rpc_url).into_response()
}
