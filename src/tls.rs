//! Extra root certificates the CLI trusts beside its bundled public roots.
//!
//! A TLS-inspecting proxy re-signs every connection with a private root that
//! the bundled roots do not contain. `--ca-cert` (or `PROOFLINE_CA_CERT`) names
//! a PEM file whose certificates are added to, never substituted for, the
//! bundled roots; certificate and hostname verification stay on.

use std::path::Path;
use std::sync::OnceLock;

use reqwest::{Certificate, ClientBuilder};

static EXTRA_ROOTS: OnceLock<Vec<Certificate>> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
pub enum CaCertError {
    #[error("could not read the CA certificate file {path}: {reason}")]
    Unreadable { path: String, reason: String },
    #[error("the CA certificate file {path} is not PEM: {reason}")]
    Invalid { path: String, reason: String },
    #[error("the CA certificate file {path} contains no PEM certificate")]
    Empty { path: String },
}

/// Reads every certificate in the PEM file at `path`.
pub fn read(path: &Path) -> Result<Vec<Certificate>, CaCertError> {
    let shown = path.display().to_string();
    let pem = std::fs::read(path).map_err(|error| CaCertError::Unreadable {
        path: shown.clone(),
        reason: error.to_string(),
    })?;
    let roots = Certificate::from_pem_bundle(&pem).map_err(|error| CaCertError::Invalid {
        path: shown.clone(),
        reason: error.to_string(),
    })?;
    if roots.is_empty() {
        return Err(CaCertError::Empty { path: shown });
    }
    Ok(roots)
}

/// Trusts the certificates in the PEM file at `path` for every client this
/// process builds afterwards. Called once, before the first request.
pub fn trust(path: &Path) -> Result<(), CaCertError> {
    let roots = read(path)?;
    if EXTRA_ROOTS.set(roots).is_err() {
        // Set once at start-up; a second call keeps the first file.
    }
    Ok(())
}

/// Adds the trusted extra roots, if any, to `builder`.
pub fn apply(builder: ClientBuilder) -> ClientBuilder {
    EXTRA_ROOTS
        .get()
        .into_iter()
        .flatten()
        .cloned()
        .fold(builder, ClientBuilder::add_root_certificate)
}

#[cfg(test)]
mod tests {
    use super::{CaCertError, read};

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ca-cert.pem");

    #[test]
    fn reads_a_pem_root() {
        assert_eq!(read(FIXTURE.as_ref()).unwrap().len(), 1);
    }

    #[test]
    fn a_built_client_accepts_the_root() {
        let builder = read(FIXTURE.as_ref()).unwrap().into_iter().fold(
            reqwest::Client::builder(),
            reqwest::ClientBuilder::add_root_certificate,
        );
        assert!(builder.build().is_ok());
    }

    #[test]
    fn refuses_a_missing_file() {
        let directory = tempfile::tempdir().unwrap();
        let error = read(&directory.path().join("absent.pem")).unwrap_err();
        assert!(matches!(error, CaCertError::Unreadable { .. }), "{error}");
        assert!(error.to_string().contains("absent.pem"), "{error}");
    }

    #[test]
    fn refuses_a_file_without_certificates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.pem");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let error = read(&path).unwrap_err();
        assert!(matches!(error, CaCertError::Empty { .. }), "{error}");
    }
}
