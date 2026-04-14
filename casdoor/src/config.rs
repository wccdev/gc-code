use anyhow::{Context, Result};

#[derive(Clone)]
pub struct AdapterConfig {
    pub listen_addr: String,
    pub casdoor_endpoint: String,
    pub casdoor_client_id: String,
    pub casdoor_client_secret: String,
    #[allow(dead_code)]
    pub casdoor_org_name: String,
    #[allow(dead_code)]
    pub casdoor_app_name: String,
    pub adapter_public_url: String,
    pub collab_rpc_url: String,
}

impl AdapterConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            listen_addr: std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".into()),
            casdoor_endpoint: required_env("CASDOOR_ENDPOINT")?,
            casdoor_client_id: required_env("CASDOOR_CLIENT_ID")?,
            casdoor_client_secret: required_env("CASDOOR_CLIENT_SECRET")?,
            casdoor_org_name: required_env("CASDOOR_ORG_NAME")?,
            casdoor_app_name: required_env("CASDOOR_APP_NAME")?,
            adapter_public_url: required_env("ADAPTER_PUBLIC_URL")?,
            collab_rpc_url: required_env("COLLAB_RPC_URL")?,
        })
    }

    pub fn casdoor_authorize_url(&self, redirect_uri: &str, state: &str) -> String {
        format!(
            "{}/login/oauth/authorize?client_id={}&response_type=code&redirect_uri={}&scope=read&state={}",
            self.casdoor_endpoint,
            urlencoded(&self.casdoor_client_id),
            urlencoded(redirect_uri),
            urlencoded(state),
        )
    }

    pub fn casdoor_token_url(&self) -> String {
        format!("{}/api/login/oauth/access_token", self.casdoor_endpoint)
    }

    pub fn casdoor_userinfo_url(&self, access_token: &str) -> String {
        format!(
            "{}/api/userinfo?accessToken={}",
            self.casdoor_endpoint, access_token
        )
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required environment variable: {name}"))
}

fn urlencoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
