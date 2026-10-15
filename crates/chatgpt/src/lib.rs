//! Sign in with ChatGPT for open-source GridCraft: browser OAuth (PKCE), local credential
//! storage, and the public Responses API using the user's ChatGPT plan.
//!
//! Native desktop only. See <https://developers.openai.com/siwc/>.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]
#![forbid(unsafe_code)]

mod api;
mod error;
mod jwt;
mod oauth;
mod store;

pub use api::{FunctionCall, ResponseOutput, agent_tools, complete_turn, list_models};
pub use error::Error;
pub use oauth::{AuthProgress, refresh_if_needed, sign_in};
pub use store::{
    Credentials, HostId, clear_credentials, clear_pending_client_id, load_credentials, load_host_id, load_pending_client_id,
    save_credentials, save_host_id, save_registration,
};

/// OpenAI issuer and endpoints for Sign in with ChatGPT.
pub const ISSUER: &str = "https://auth.openai.com";
pub const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
pub const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
pub const JWKS_URL: &str = "https://auth.openai.com/.well-known/jwks.json";
pub const RESOURCE: &str = "https://api.openai.com/v1";
pub const API_BASE: &str = "https://api.openai.com/v1";
pub const DYNAMIC_CLIENT: &str = "dynamic_agent_client";
pub const APP_NAME: &str = "GridCraft";
pub const SCOPE: &str = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
pub const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";

pub type Result<T> = std::result::Result<T, Error>;
