//! Error type for Sign in with ChatGPT and the Responses API.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error("sign-in cancelled or denied")]
    Denied,
    #[error("ChatGPT plan usage is not enabled for this account")]
    NoPlanUsage,
    #[error("not signed in")]
    NotSignedIn,
    #[error("network: {0}")]
    Network(String),
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }
}
