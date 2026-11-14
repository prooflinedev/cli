//! Where the CLI keeps its token: the operating system keychain, one entry per
//! console origin. `PROOFLINE_TOKEN` takes precedence and is never stored.

use std::sync::Arc;

use keyring_core::{CredentialStore, Entry, Error};
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

/// The keychain entry for a console origin. Opening the Linux Secret Service
/// connects to the session bus, so this runs inside [`blocking`].
fn entry(key: &str) -> keyring_core::Result<Entry> {
    platform_store()?.build(SERVICE, key, None)
}

// Each store files the entry where keyring 3 did, so existing sign-ins stay
// readable: the login keychain's generic password with service `proofline`
// and the origin as account on macOS, the generic credential
// `<origin>.proofline` on Windows, and the item whose `service` and
// `username` attributes match on the Secret Service.
#[cfg(target_os = "macos")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new()?;
    Ok(store)
}

#[cfg(windows)]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = windows_native_keyring_store::Store::new()?;
    Ok(store)
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = dbus_secret_service_keyring_store::Store::new()?;
    Ok(store)
}

fn keychain_error(error: Error) -> CredentialError {
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
    let key = origin.as_key();
    let secret = blocking(move || entry(&key)?.get_password()).await;
    match secret {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|_| CredentialError::Corrupt),
        Err(Error::NoEntry) => Ok(None),
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
    let key = origin.as_key();
    blocking(move || entry(&key)?.set_password(&raw))
        .await
        .map_err(keychain_error)
}

/// Removes the stored credential. Returns whether one existed.
pub async fn remove(origin: &Origin) -> Result<bool, CredentialError> {
    let key = origin.as_key();
    match blocking(move || entry(&key)?.delete_credential()).await {
        Ok(()) => Ok(true),
        Err(Error::NoEntry) => Ok(false),
        Err(error) => Err(keychain_error(error)),
    }
}

/// The session bus address for the Secret Service keychain when the
/// environment names no bus. The keychain library finds the bus only through
/// `DBUS_SESSION_BUS_ADDRESS` or `$XDG_RUNTIME_DIR/bus`, and some coding agents
/// start MCP servers with neither variable. systemd and elogind serve the user
/// bus at `/run/user/<uid>/bus`.
#[cfg(target_os = "linux")]
pub fn default_session_bus() -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;

    let named = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    let environment_names_bus = named("DBUS_SESSION_BUS_ADDRESS") || named("XDG_RUNTIME_DIR");
    // `/proc/self` belongs to the effective user, who owns the session bus.
    let uid = match std::fs::metadata("/proc/self") {
        Ok(metadata) => metadata.uid(),
        // Without the user identity, leave discovery to the keychain library.
        Err(_) => return None,
    };
    let bus = std::path::Path::new("/run/user")
        .join(uid.to_string())
        .join("bus");
    user_bus_address(environment_names_bus, &bus)
}

/// `unix:path=<bus>` when the environment names no bus and `bus` is a socket.
/// A numeric user bus path needs no D-Bus address escaping.
#[cfg(target_os = "linux")]
fn user_bus_address(environment_names_bus: bool, bus: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::FileTypeExt as _;

    if environment_names_bus {
        return None;
    }
    let socket = match std::fs::metadata(bus) {
        Ok(metadata) => metadata.file_type().is_socket(),
        // An unavailable path establishes no fallback; normal lookup still runs.
        Err(_) => return None,
    };
    socket.then(|| format!("unix:path={}", bus.display()))
}

/// Keychain calls block on the platform's IPC, so they run off the runtime.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> keyring_core::Result<T> + Send + 'static,
) -> keyring_core::Result<T> {
    tokio::task::spawn_blocking(call)
        .await
        .unwrap_or_else(|join| Err(Error::PlatformFailure(Box::new(join))))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn user_bus_is_used_only_when_the_environment_names_no_bus() {
        let directory = tempfile::tempdir().unwrap();
        let bus = directory.path().join("bus");
        let _listener = std::os::unix::net::UnixListener::bind(&bus).unwrap();

        assert_eq!(
            user_bus_address(false, &bus),
            Some(format!("unix:path={}", bus.display()))
        );
        // An address or runtime directory in the environment stays in charge.
        assert_eq!(user_bus_address(true, &bus), None);

        let file = directory.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(user_bus_address(false, &file), None);
        assert_eq!(
            user_bus_address(false, &directory.path().join("missing")),
            None
        );
    }
}
