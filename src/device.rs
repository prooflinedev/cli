//! Browser-approved sign-in (RFC 8628). The person approves the code, the
//! organization, the scopes and the repositories in a signed-in browser; the
//! CLI never sees a password or a copied token.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::{ApiError, Http};
use crate::credentials::{Credential, Source};

const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const SLOW_DOWN_SECONDS: u64 = 5;

/// What the person needs to approve this sign-in.
#[derive(Debug)]
pub struct Challenge {
    device_code: SecretString,
    pub user_code: SecretString,
    pub verification_uri: String,
    /// The approval page with the code filled in, when the server offers it.
    pub verification_uri_complete: Option<SecretString>,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
struct ChallengeBody {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: String,
    expires_in: Option<u64>,
    scope: Option<String>,
    organization_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("the sign-in code expired before it was approved; run `proofline login` again")]
    Expired,
    #[error("the approval was refused: {0}")]
    Refused(String),
    #[error("{0} does not say which organization it approved; pass --org with the organization ID")]
    OrganizationUnknown(String),
}

/// Asks the server for a sign-in code with `scopes`, or its defaults when empty.
pub async fn start(http: &Http, scopes: &[String]) -> Result<Challenge, DeviceError> {
    let url = http.origin().join(["auth", "device", "code"]);
    let body = if scopes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::json!({ "scopes": scopes })
    };
    let (reply, _) = http.send(http.post(url).json(&body)).await?;
    if !reply.status.is_success() {
        return Err(http.problem(&reply).into());
    }
    let body: ChallengeBody =
        serde_json::from_slice(&reply.body).map_err(|error| http.protocol(error.to_string()))?;
    Ok(Challenge {
        device_code: SecretString::from(body.device_code),
        user_code: SecretString::from(body.user_code),
        verification_uri: body.verification_uri,
        verification_uri_complete: body.verification_uri_complete.map(SecretString::from),
        expires_in: body.expires_in,
        interval: body.interval.max(1),
    })
}

/// Polls until the person approves, refuses or the code expires.
/// `organization` names the organization when the server does not report it.
pub async fn finish(
    http: &Http,
    challenge: &Challenge,
    organization: Option<Uuid>,
) -> Result<Credential, DeviceError> {
    let url = http.origin().join(["auth", "device", "token"]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(challenge.expires_in);
    let mut interval = challenge.interval;
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if tokio::time::Instant::now() >= deadline {
            return Err(DeviceError::Expired);
        }
        let body = serde_json::json!({
            "grant_type": GRANT,
            "device_code": challenge.device_code.expose_secret(),
        });
        let (reply, _) = http.send(http.post(url.clone()).json(&body)).await?;
        if reply.status.is_success() {
            let token: TokenBody = serde_json::from_slice(&reply.body)
                .map_err(|_| http.protocol("the token response is malformed"))?;
            let organization_id = token
                .organization_id
                .or(organization)
                .ok_or_else(|| DeviceError::OrganizationUnknown(http.origin().to_string()))?;
            return Ok(Credential {
                token: SecretString::from(token.access_token),
                organization_id,
                scope: token.scope,
                expires_at: token.expires_in.map(|seconds| now() + seconds),
                source: Source::Keychain,
            });
        }
        let Ok(OAuthError { error }) = serde_json::from_slice::<OAuthError>(&reply.body) else {
            return Err(http.problem(&reply).into());
        };
        match error.as_str() {
            "authorization_pending" => {}
            "slow_down" => interval += SLOW_DOWN_SECONDS,
            "expired_token" => return Err(DeviceError::Expired),
            "access_denied" => {
                return Err(DeviceError::Refused(
                    "the approving user no longer has access to that organization".to_owned(),
                ));
            }
            _ => return Err(http.problem(&reply).into()),
        }
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
