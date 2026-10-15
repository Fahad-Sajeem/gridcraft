//! Local credential and host-id storage (owner-only files under the app config dir).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Stable installation id (`urn:uuid:…`), reused across sign-ins.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostId(pub String);

impl HostId {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| Error::msg(format!("rng: {e}")))?;
        // RFC 4122 version 4
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("");
        let id = format!(
            "urn:uuid:{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        );
        Ok(HostId(id))
    }
}

/// Saved ChatGPT connection (one profile).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub email: Option<String>,
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub ext_agent_host_id: String,
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    pub saved_at: String,
}

impl Credentials {
    pub fn has_plan_usage(&self) -> bool {
        self.scopes.iter().any(|s| s == crate::PLAN_SCOPE)
    }

    pub fn access_expired(&self) -> bool {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        now >= self.expires_at.saturating_sub(60)
    }
}

fn chatgpt_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("chatgpt")
}

pub fn load_host_id(config_dir: &Path) -> Result<HostId> {
    let path = chatgpt_dir(config_dir).join("host.json");
    if let Ok(bytes) = fs::read(&path)
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(id) = v.get("extAgentHostId").and_then(|x| x.as_str()).filter(|s| !s.is_empty())
    {
        return Ok(HostId(id.to_string()));
    }
    let host = HostId::generate()?;
    save_host_id(config_dir, &host)?;
    Ok(host)
}

pub fn save_host_id(config_dir: &Path, host: &HostId) -> Result<()> {
    let dir = chatgpt_dir(config_dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join("host.json");
    let tmp = dir.join("host.json.tmp");
    let body = serde_json::to_vec_pretty(&serde_json::json!({"extAgentHostId": host.0}))?;
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_credentials(config_dir: &Path) -> Result<Option<Credentials>> {
    let path = chatgpt_dir(config_dir).join("credentials.json");
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn save_credentials(config_dir: &Path, creds: &Credentials) -> Result<()> {
    let dir = chatgpt_dir(config_dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join("credentials.json");
    let tmp = dir.join("credentials.json.tmp");
    let body = serde_json::to_vec_pretty(creds)?;
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn clear_credentials(config_dir: &Path) -> Result<()> {
    let path = chatgpt_dir(config_dir).join("credentials.json");
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Save the issued OAuth `client_id` after dynamic registration (before or after token exchange).
/// Lets the next sign-in skip `dynamic_agent_client` after an `invalid_grant` (OpenAI docs).
pub fn save_registration(config_dir: &Path, client_id: &str, host_id: &str) -> Result<()> {
    let dir = chatgpt_dir(config_dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join("registration.json");
    let tmp = dir.join("registration.json.tmp");
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "clientId": client_id,
        "extAgentHostId": host_id,
    }))?;
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn load_pending_client_id(config_dir: &Path) -> Result<Option<String>> {
    let path = chatgpt_dir(config_dir).join("registration.json");
    match fs::read(&path) {
        Ok(bytes) => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            Ok(v.get("clientId").and_then(|c| c.as_str()).filter(|s| !s.is_empty()).map(str::to_string))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn clear_pending_client_id(config_dir: &Path) -> Result<()> {
    let path = chatgpt_dir(config_dir).join("registration.json");
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_id_round_trip() {
        let dir = std::env::temp_dir().join(format!("gridcraft-chatgpt-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a = load_host_id(&dir).unwrap();
        let b = load_host_id(&dir).unwrap();
        assert_eq!(a, b);
        assert!(a.0.starts_with("urn:uuid:"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn credentials_plan_scope() {
        let mut c = Credentials {
            email: None,
            issuer: "https://auth.openai.com".into(),
            subject: "sub".into(),
            client_id: "oaiapp_x".into(),
            ext_agent_host_id: "urn:uuid:1".into(),
            id_token: String::new(),
            access_token: String::new(),
            refresh_token: None,
            token_type: "Bearer".into(),
            expires_at: 0,
            scopes: vec!["openid".into()],
            saved_at: String::new(),
        };
        assert!(!c.has_plan_usage());
        c.scopes.push(crate::PLAN_SCOPE.into());
        assert!(c.has_plan_usage());
    }
}
