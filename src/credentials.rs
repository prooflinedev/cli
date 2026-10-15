//! Where the CLI keeps its token: the operating system keychain, one entry per
//! console origin. `PROOFLINE_TOKEN` takes precedence and is never stored.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::origin::Origin;

const SERVICE: &str = "proofline";

/// A token and the organization it works in. A device token is bound to the
/// organization approved in the browser; an environment token names its
/// organization separately.
#[derive(Debug)]
pub struct Credential {
    pub token: SecretString,
    pub organization_id: Uuid,
    pub scope: Option<String>,
    pub expires_at: Option<u64>,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Environment,
    Keychain,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    token: String,
    organization_id: Uuid,
    scope: Option<String>,
    expires_at: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("not signed in to {0}; run `proofline login`, or set PROOFLINE_TOKEN")]
    Missing(String),
    #[error(
        "PROOFLINE_TOKEN is set, so name its organization with --org or PROOFLINE_ORGANIZATION_ID"
    )]
    OrganizationRequired,
    #[error(
        "this sign-in works in organization {0}; run `proofline login` and choose the other organization"
    )]
    OtherOrganization(Uuid),
    #[error(
        "the operating system keychain is unavailable ({0}); set PROOFLINE_TOKEN to a personal token instead"
    )]
    Keychain(String),
    #[error("the stored Proofline credential is unreadable; run `proofline login` again")]
    Corrupt,
}

fn entry(origin: &Origin) -> Result<keyring::Entry, CredentialError> {
    keyring::Entry::new(SERVICE, &origin.as_key()).map_err(keychain_error)
}

fn keychain_error(error: keyring::Error) -> CredentialError {
    // The keyring error's text names the platform failure and never the secret.
    CredentialError::Keychain(error.to_string())
}

/// Resolves the credential for `origin`. An environment token wins over the
/// keychain, and `organization` wins over the stored organization.
pub async fn load(
    origin: &Origin,
    environment_token: Option<SecretString>,
    organization: Option<Uuid>,
) -> Result<Credential, CredentialError> {
    if let Some(token) = environment_token {
        let organization_id = organization.ok_or(CredentialError::OrganizationRequired)?;
        return Ok(Credential {
            token,
            organization_id,
            scope: None,
            expires_at: None,
            source: Source::Environment,
        });
    }
    let stored = read(origin)
        .await?
        .ok_or_else(|| CredentialError::Missing(origin.to_string()))?;
    if let Some(requested) = organization
        && requested != stored.organization_id
    {
        return Err(CredentialError::OtherOrganization(stored.organization_id));
    }
    Ok(Credential {
        token: SecretString::from(stored.token),
        organization_id: stored.organization_id,
        scope: stored.scope,
        expires_at: stored.expires_at,
        source: Source::Keychain,
    })
}

async fn read(origin: &Origin) -> Result<Option<Stored>, CredentialError> {
    let entry = entry(origin)?;
    let secret = blocking(move || entry.get_password()).await;
    match secret {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|_| CredentialError::Corrupt),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(keychain_error(error)),
    }
}

/// Fails when the keychain cannot be read, so a sign-in can stop before the
/// person approves a token the CLI could not keep.
pub async fn probe(origin: &Origin) -> Result<(), CredentialError> {
    match read(origin).await {
        Ok(_) | Err(CredentialError::Corrupt) => Ok(()),
        Err(error) => Err(error),
    }
}

pub async fn store(origin: &Origin, credential: &Credential) -> Result<(), CredentialError> {
    let stored = Stored {
        token: credential.token.expose_secret().to_owned(),
        organization_id: credential.organization_id,
        scope: credential.scope.clone(),
        expires_at: credential.expires_at,
    };
    let raw = serde_json::to_string(&stored).map_err(|_| CredentialError::Corrupt)?;
    let entry = entry(origin)?;
    blocking(move || entry.set_password(&raw))
        .await
        .map_err(keychain_error)
}

/// Removes the stored credential. Returns whether one existed.
pub async fn remove(origin: &Origin) -> Result<bool, CredentialError> {
    let entry = entry(origin)?;
    match blocking(move || entry.delete_credential()).await {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(keychain_error(error)),
    }
}

/// Keychain calls block on the platform's IPC, so they run off the runtime.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> keyring::Result<T> + Send + 'static,
) -> keyring::Result<T> {
    tokio::task::spawn_blocking(call)
        .await
        .unwrap_or_else(|join| Err(keyring::Error::PlatformFailure(Box::new(join))))
}
