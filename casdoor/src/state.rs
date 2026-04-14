use std::collections::HashMap;
use std::sync::Mutex;

use crate::config::AdapterConfig;

/// Pending OAuth sessions, keyed by the `state` parameter.
pub struct PendingSession {
    pub native_app_port: u16,
    pub native_app_public_key: String,
}

/// Issued access tokens, keyed by the token string.
pub struct UserToken {
    pub user_id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: String,
    #[allow(dead_code)]
    pub email: Option<String>,
}

pub struct AppState {
    pub config: AdapterConfig,
    pub http_client: reqwest::Client,
    pub pending_sessions: Mutex<HashMap<String, PendingSession>>,
    /// Maps access_token -> UserToken for validation.
    pub tokens: Mutex<HashMap<String, UserToken>>,
    /// Maps casdoor_user_id (string) -> internal numeric user_id.
    pub user_ids: Mutex<HashMap<String, i64>>,
    pub next_user_id: Mutex<i64>,
}

impl AppState {
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
            pending_sessions: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            user_ids: Mutex::new(HashMap::new()),
            next_user_id: Mutex::new(1),
        }
    }

    pub fn get_or_create_user_id(&self, casdoor_user_id: &str) -> i64 {
        let mut user_ids = self.user_ids.lock().expect("user_ids lock poisoned");
        if let Some(&id) = user_ids.get(casdoor_user_id) {
            return id;
        }
        let mut next = self.next_user_id.lock().expect("next_user_id lock poisoned");
        let id = *next;
        *next += 1;
        user_ids.insert(casdoor_user_id.to_string(), id);
        id
    }
}
