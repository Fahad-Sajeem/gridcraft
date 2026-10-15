//! Browser OAuth with PKCE and a loopback callback (`http://127.0.0.1:<port>/auth/callback`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

use crate::jwt::verify_id_token;
use crate::store::{Credentials, load_credentials, load_host_id, save_credentials, save_registration};
use crate::{AUTHORIZE_URL, DYNAMIC_CLIENT, Error, RESOURCE, Result, SCOPE, TOKEN_URL};

/// Progress messages for the UI while the browser flow runs.
#[derive(Clone, Debug)]
pub enum AuthProgress {
    WaitingForBrowser,
    Exchanging,
    Done(Credentials),
    Failed(String),
}

fn random_urlsafe(n_bytes: usize) -> Result<String> {
    let mut bytes = vec![0u8; n_bytes];
    getrandom::fill(&mut bytes).map_err(|e| Error::msg(format!("rng: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn pkce_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn utc_now_string() -> String {
    format!("{}", now_unix())
}

/// Percent-decode without treating `+` as space (form decoding would corrupt OAuth codes).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(a), Some(b)) = (h(bytes[i + 1]), h(bytes[i + 2])) {
                out.push((a << 4) | b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

/// Start Sign in with ChatGPT. Opens the system browser via `open_url`, waits for the loopback
/// callback, exchanges the code, validates the ID token, and saves credentials under `config_dir`.
pub fn sign_in(config_dir: &Path, open_url: impl FnOnce(&str) + Send + 'static, progress: mpsc::Sender<AuthProgress>) {
    let config_dir = config_dir.to_path_buf();
    thread::spawn(move || {
        let send = |p: AuthProgress| {
            let _ = progress.send(p);
        };
        match sign_in_blocking(&config_dir, open_url, &send) {
            Ok(creds) => send(AuthProgress::Done(creds)),
            Err(Error::Denied) => send(AuthProgress::Failed("Sign-in cancelled.".into())),
            Err(e) => send(AuthProgress::Failed(e.to_string())),
        }
    });
}

fn sign_in_blocking(config_dir: &Path, open_url: impl FnOnce(&str), send: &dyn Fn(AuthProgress)) -> Result<Credentials> {
    let host = load_host_id(config_dir)?;
    let existing = load_credentials(config_dir).ok().flatten();
    // A previous exchange may have saved only the issued client id after invalid_grant.
    let pending = crate::store::load_pending_client_id(config_dir).ok().flatten();

    let (client_id, agent_name_hint, id_token_hint, login_hint) = match &existing {
        Some(c) => (c.client_id.clone(), None, Some(c.id_token.clone()), c.email.clone()),
        None => match pending {
            Some(id) => (id, None, None, None),
            None => (DYNAMIC_CLIENT.to_string(), Some(crate::APP_NAME.to_string()), None, None),
        },
    };

    let state = random_urlsafe(32)?;
    let nonce = random_urlsafe(32)?;
    // PKCE verifier: 32 bytes → ~43 chars (RFC 7636 minimum); keep under 128.
    let verifier = random_urlsafe(32)?;
    let challenge = pkce_challenge(&verifier);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/auth/callback");

    let mut auth = Url::parse(AUTHORIZE_URL).map_err(|e| Error::msg(e.to_string()))?;
    {
        let mut q = auth.query_pairs_mut();
        q.append_pair("client_id", &client_id);
        q.append_pair("response_type", "code");
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("scope", SCOPE);
        q.append_pair("resource", RESOURCE);
        q.append_pair("state", &state);
        q.append_pair("nonce", &nonce);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("code_challenge", &challenge);
        q.append_pair("ext_agent_host_id", &host.0);
        if let Some(hint) = &agent_name_hint {
            q.append_pair("agent_name_hint", hint);
        }
        if let Some(hint) = &id_token_hint {
            q.append_pair("id_token_hint", hint);
        }
        if let Some(hint) = &login_hint {
            q.append_pair("login_hint", hint);
        }
    }

    send(AuthProgress::WaitingForBrowser);
    open_url(auth.as_str());

    let (code, issued_client_id, granted_scope) = wait_for_callback(&listener, &state)?;
    send(AuthProgress::Exchanging);

    let issued = match issued_client_id {
        Some(id) if id != DYNAMIC_CLIENT => id,
        Some(_) => return Err(Error::msg("registration returned dynamic_agent_client as client_id")),
        None if client_id != DYNAMIC_CLIENT => client_id.clone(),
        None => return Err(Error::msg("registration did not return an issued client_id")),
    };

    // Persist issued id before exchange so a retry can skip dynamic registration (OpenAI docs).
    let _ = save_registration(config_dir, &issued, &host.0);

    let token = match exchange_code(&issued, &code, &verifier, &redirect_uri) {
        Ok(t) => t,
        Err(Error::Http { status: 400, body }) if body.contains("invalid_grant") => {
            return Err(Error::msg(
                "invalid_grant: authorization code rejected. Click Continue with ChatGPT again \
                 (the issued client id was saved for the next attempt).",
            ));
        }
        Err(e) => return Err(e),
    };

    let id_token = token.get("id_token").and_then(|v| v.as_str()).ok_or_else(|| Error::msg("token response missing id_token"))?;
    let access_token = token.get("access_token").and_then(|v| v.as_str()).ok_or_else(|| Error::msg("token response missing access_token"))?;
    let refresh_token = token.get("refresh_token").and_then(|v| v.as_str()).map(str::to_string);
    let expires_in = token.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(3600);
    let token_type = token.get("token_type").and_then(|v| v.as_str()).unwrap_or("Bearer").to_string();
    let scope_str = token.get("scope").and_then(|v| v.as_str()).or(granted_scope.as_deref()).unwrap_or("");
    let scopes: Vec<String> = scope_str.split_whitespace().map(str::to_string).filter(|s| !s.is_empty()).collect();

    let claims = verify_id_token(id_token, &issued, &nonce)?;
    if let Some(prev) = &existing
        && prev.subject != claims.sub
    {
        return Err(Error::msg("signed-in account does not match the saved profile"));
    }

    let creds = Credentials {
        email: claims.email.clone(),
        issuer: claims.iss,
        subject: claims.sub,
        client_id: issued,
        ext_agent_host_id: host.0,
        id_token: id_token.to_string(),
        access_token: access_token.to_string(),
        refresh_token,
        token_type,
        expires_at: now_unix().saturating_add(expires_in),
        scopes,
        saved_at: utc_now_string(),
    };
    save_credentials(config_dir, &creds)?;
    let _ = crate::store::clear_pending_client_id(config_dir);
    Ok(creds)
}

fn wait_for_callback(listener: &TcpListener, expected_state: &str) -> Result<(String, Option<String>, Option<String>)> {
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(Error::msg("sign-in timed out waiting for the browser"));
        }
        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        match handle_callback_connection(stream, expected_state) {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => continue, // favicon / junk — keep listening
            Err(e) => return Err(e),
        }
    }
}

fn handle_callback_connection(
    mut stream: TcpStream,
    expected_state: &str,
) -> Result<Option<(String, Option<String>, Option<String>)>> {
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    // Drain headers.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
    }

    let path = first.split_whitespace().nth(1).unwrap_or("/");
    if !path.starts_with("/auth/callback") {
        // Ignore probes (favicon, etc.).
        let _ = respond_html(&mut stream, "Not the OAuth callback.");
        return Ok(None);
    }

    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let params = parse_query(query);

    if params.get("error").map(String::as_str) == Some("access_denied") {
        respond_html(&mut stream, "Sign-in cancelled. You can close this tab.")?;
        return Err(Error::Denied);
    }
    if params.get("state").map(String::as_str) != Some(expected_state) {
        // Another tab / stale redirect — keep listening for the matching one.
        let _ = respond_html(&mut stream, "Stale or unknown sign-in. Return to GridCraft if a newer tab is open.");
        return Ok(None);
    }
    let Some(code) = params.get("code").filter(|c| !c.is_empty()).cloned() else {
        respond_html(&mut stream, "Missing authorization code. Close this tab and try again.")?;
        return Err(Error::msg("callback missing code"));
    };

    respond_html(&mut stream, "Signed in. You can close this tab and return to GridCraft.")?;
    Ok(Some((code, params.get("client_id").cloned(), params.get("scope").cloned())))
}

fn respond_html(stream: &mut TcpStream, message: &str) -> Result<()> {
    let body = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>GridCraft</title></head>\
         <body style=\"font-family:system-ui;padding:2rem\"><h1>GridCraft</h1><p>{message}</p></body></html>"
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn exchange_code(client_id: &str, code: &str, verifier: &str, redirect_uri: &str) -> Result<serde_json::Value> {
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", verifier),
        ("redirect_uri", redirect_uri),
        ("resource", RESOURCE),
    ];
    let body = form.iter().map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v))).collect::<Vec<_>>().join("&");
    crate::api::http_post_form(TOKEN_URL, &body)
}

/// Refresh the access token when expired. Updates the saved credentials file.
pub fn refresh_if_needed(config_dir: &Path, creds: &mut Credentials) -> Result<()> {
    if !creds.access_expired() {
        return Ok(());
    }
    let Some(refresh) = creds.refresh_token.clone() else {
        return Err(Error::msg("access token expired; sign in again"));
    };
    let form = [
        ("grant_type", "refresh_token"),
        ("client_id", creds.client_id.as_str()),
        ("refresh_token", refresh.as_str()),
        ("resource", RESOURCE),
    ];
    let body = form.iter().map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v))).collect::<Vec<_>>().join("&");
    let token = crate::api::http_post_form(TOKEN_URL, &body)?;
    let access = token.get("access_token").and_then(|v| v.as_str()).ok_or_else(|| Error::msg("refresh missing access_token"))?;
    let expires_in = token.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(3600);
    if let Some(rt) = token.get("refresh_token").and_then(|v| v.as_str()) {
        creds.refresh_token = Some(rt.to_string());
    }
    if let Some(id) = token.get("id_token").and_then(|v| v.as_str()) {
        creds.id_token = id.to_string();
    }
    if let Some(scope) = token.get("scope").and_then(|v| v.as_str()) {
        creds.scopes = scope.split_whitespace().map(str::to_string).collect();
    }
    creds.access_token = access.to_string();
    creds.expires_at = now_unix().saturating_add(expires_in);
    creds.saved_at = utc_now_string();
    save_credentials(config_dir, creds)?;
    Ok(())
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_preserves_plus_in_code() {
        let q = parse_query("code=abc+def&state=x");
        assert_eq!(q.get("code").map(String::as_str), Some("abc+def"));
    }

    #[test]
    fn query_percent_decodes() {
        let q = parse_query("code=a%2Bb&state=x");
        assert_eq!(q.get("code").map(String::as_str), Some("a+b"));
    }
}
