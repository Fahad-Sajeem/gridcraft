//! Validate OpenAI ID tokens against the published JWKS.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::{Error, ISSUER, JWKS_URL, Result};

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdClaims {
    pub sub: String,
    pub email: Option<String>,
    pub nonce: Option<String>,
    pub iss: String,
    #[allow(dead_code)]
    pub aud: Value,
}

pub fn verify_id_token(id_token: &str, client_id: &str, expected_nonce: &str) -> Result<IdClaims> {
    let header = decode_header(id_token).map_err(|e| Error::msg(format!("id_token header: {e}")))?;
    let kid = header.kid.ok_or_else(|| Error::msg("id_token missing kid"))?;
    let jwks_v = crate::api::http_get_json(JWKS_URL)?;
    let jwks: Jwks = serde_json::from_value(jwks_v)?;
    let jwk = jwks.keys.iter().find(|k| k.kid.as_deref() == Some(kid.as_str())).ok_or_else(|| Error::msg(format!("no JWKS key for kid {kid}")))?;
    if jwk.kty != "RSA" {
        return Err(Error::msg("unexpected JWK type"));
    }
    let n = jwk.n.as_deref().ok_or_else(|| Error::msg("JWK missing n"))?;
    let e = jwk.e.as_deref().ok_or_else(|| Error::msg("JWK missing e"))?;
    let key = DecodingKey::from_rsa_components(n, e).map_err(|e| Error::msg(format!("JWK key: {e}")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[client_id]);
    validation.validate_nbf = true;

    let data = decode::<IdClaims>(id_token, &key, &validation).map_err(|e| Error::msg(format!("id_token invalid: {e}")))?;
    if data.claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(Error::msg("id_token nonce mismatch"));
    }
    if data.claims.sub.is_empty() {
        return Err(Error::msg("id_token missing sub"));
    }
    Ok(data.claims)
}
