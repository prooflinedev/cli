//! Local refusals before any patch bytes leave the checkout.

use crate::git::{LocalChanges, PatchPaths};

#[derive(Debug, thiserror::Error)]
pub(crate) enum PreflightError {
    #[error(
        "--allow-path {0:?} is not an exact repository-relative path; use the path from the local refusal"
    )]
    InvalidAllowPath(String),
    #[error(
        "local patch includes the sensitive .env path {0:?}; remove it before upload, or pass --allow-path for that exact path"
    )]
    EnvironmentPath(String),
    #[error(
        "local patch contains {kind} at {path:?}:{line} ({coordinate}); remove it before upload, or pass --allow-path for that exact path"
    )]
    Secret {
        path: String,
        line: usize,
        coordinate: &'static str,
        kind: &'static str,
    },
    #[error("could not map the local patch to file paths and lines; no review was requested")]
    InvalidPatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Finding {
    EnvironmentPath {
        path: String,
    },
    Secret {
        path: String,
        line: usize,
        coordinate: &'static str,
        kind: &'static str,
    },
}

impl Finding {
    pub(crate) fn into_error(self) -> PreflightError {
        match self {
            Self::EnvironmentPath { path } => PreflightError::EnvironmentPath(path),
            Self::Secret {
                path,
                line,
                coordinate,
                kind,
            } => PreflightError::Secret {
                path,
                line,
                coordinate,
                kind,
            },
        }
    }

    pub(crate) fn message(&self) -> String {
        self.clone().into_error().to_string()
    }
}

#[derive(Debug)]
struct Lines {
    old: usize,
    new: usize,
}

pub(crate) fn patch_paths(changes: &LocalChanges) -> Vec<String> {
    changes
        .paths
        .iter()
        .filter_map(|file| file.new.as_deref().or(file.old.as_deref()))
        .map(str::to_owned)
        .collect()
}

pub(crate) fn check(changes: &LocalChanges, allowed: &[String]) -> Result<(), PreflightError> {
    if let Some(first) = scan(changes, allowed)?.into_iter().next() {
        return Err(first.into_error());
    }
    Ok(())
}

/// Inspects the entire local patch and returns every sensitive path or
/// credential-shaped finding without stopping at the first refusal.
pub(crate) fn scan(
    changes: &LocalChanges,
    allowed: &[String],
) -> Result<Vec<Finding>, PreflightError> {
    for path in allowed {
        if path.starts_with('/') || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
            return Err(PreflightError::InvalidAllowPath(path.clone()));
        }
    }
    let mut findings = Vec::new();
    let mut paths = changes.paths.iter();
    let mut current = None;
    let mut hunk = None;
    for (patch_line, line) in changes.patch.lines().enumerate() {
        if line.starts_with("diff --git ") {
            let file = paths.next().ok_or(PreflightError::InvalidPatch)?;
            environment_paths(file, allowed, &mut findings);
            current = Some(file);
            hunk = None;
            continue;
        }
        let file = current.ok_or(PreflightError::InvalidPatch)?;
        if line.starts_with("@@ ") {
            // A section heading can quote a line outside the hunk. Its exact
            // coordinate is a patch line, not a guessed source-file line.
            inspect(
                file.new.as_deref().or(file.old.as_deref()),
                patch_line + 1,
                "patch line",
                line,
                allowed,
                &mut findings,
            )?;
            hunk = Some(hunk_lines(line)?);
        } else if let Some(lines) = &mut hunk {
            inspect_hunk(file, lines, line, allowed, &mut findings)?;
        }
    }
    if paths.next().is_some() {
        return Err(PreflightError::InvalidPatch);
    }
    Ok(findings)
}

fn environment_paths(file: &PatchPaths, allowed: &[String], findings: &mut Vec<Finding>) {
    let mut reported: Option<&str> = None;
    for path in [&file.old, &file.new]
        .iter()
        .filter_map(|path| path.as_deref())
    {
        if reported == Some(path) {
            continue;
        }
        if !is_allowed(path, allowed)
            && path
                .split('/')
                .any(|part| part == ".env" || part.starts_with(".env."))
        {
            reported = Some(path);
            findings.push(Finding::EnvironmentPath {
                path: path.to_owned(),
            });
        }
    }
}

fn hunk_lines(line: &str) -> Result<Lines, PreflightError> {
    let mut fields = line.split_whitespace();
    if fields.next() != Some("@@") {
        return Err(PreflightError::InvalidPatch);
    }
    let old = hunk_start(fields.next(), '-')?;
    let new = hunk_start(fields.next(), '+')?;
    if fields.next() != Some("@@") {
        return Err(PreflightError::InvalidPatch);
    }
    Ok(Lines { old, new })
}

fn hunk_start(field: Option<&str>, prefix: char) -> Result<usize, PreflightError> {
    let range = field
        .and_then(|field| field.strip_prefix(prefix))
        .ok_or(PreflightError::InvalidPatch)?;
    range
        .split(',')
        .next()
        .ok_or(PreflightError::InvalidPatch)?
        .parse()
        .map_err(|_| PreflightError::InvalidPatch)
}

fn inspect_hunk(
    file: &PatchPaths,
    lines: &mut Lines,
    line: &str,
    allowed: &[String],
    findings: &mut Vec<Finding>,
) -> Result<(), PreflightError> {
    if let Some(text) = line.strip_prefix('+') {
        inspect(
            file.new.as_deref(),
            lines.new,
            "new line",
            text,
            allowed,
            findings,
        )?;
        lines.new = next_line(lines.new)?;
    } else if let Some(text) = line.strip_prefix('-') {
        inspect(
            file.old.as_deref(),
            lines.old,
            "base line",
            text,
            allowed,
            findings,
        )?;
        lines.old = next_line(lines.old)?;
    } else if let Some(text) = line.strip_prefix(' ') {
        inspect(
            file.new.as_deref().or(file.old.as_deref()),
            lines.new,
            "new line",
            text,
            allowed,
            findings,
        )?;
        lines.old = next_line(lines.old)?;
        lines.new = next_line(lines.new)?;
    } else if !line.starts_with("\\ No newline at end of file") {
        return Err(PreflightError::InvalidPatch);
    }
    Ok(())
}

fn next_line(line: usize) -> Result<usize, PreflightError> {
    line.checked_add(1).ok_or(PreflightError::InvalidPatch)
}

fn inspect(
    path: Option<&str>,
    line: usize,
    coordinate: &'static str,
    text: &str,
    allowed: &[String],
    findings: &mut Vec<Finding>,
) -> Result<(), PreflightError> {
    let path = path.ok_or(PreflightError::InvalidPatch)?;
    if !is_allowed(path, allowed)
        && let Some(kind) = secret_shape(text)
    {
        findings.push(Finding::Secret {
            path: path.to_owned(),
            line,
            coordinate,
            kind,
        });
    }
    Ok(())
}

fn is_allowed(path: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|candidate| candidate == path)
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn upper_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

/// The RFC 4648 base32 alphabet.
fn base32(byte: u8) -> bool {
    byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7')
}

/// Standard RFC 4648 base64 data byte (without padding).
fn base64_data(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

/// Azure Storage account keys are 64-byte secrets encoded as 88 base64
/// characters (86 base64 data bytes followed by `==`) after `AccountKey=`.
fn has_azure_storage_key(text: &str) -> bool {
    const PREFIX: &str = "AccountKey=";
    const DATA_LEN: usize = 86;
    const KEY_LEN: usize = DATA_LEN + 2;

    text.match_indices(PREFIX).any(|(start, prefix)| {
        let Some(suffix) = text.get(start + prefix.len()..) else {
            return false;
        };
        let bytes = suffix.as_bytes();
        if bytes.len() < KEY_LEN {
            return false;
        }
        bytes[..DATA_LEN].iter().all(|byte| base64_data(*byte))
            && bytes[DATA_LEN..KEY_LEN] == *b"=="
            && bytes
                .get(KEY_LEN)
                .is_none_or(|next| !base64_data(*next) && *next != b'=')
    })
}

fn has_token(text: &str, prefixes: &[&str], minimum: usize, body: fn(u8) -> bool) -> bool {
    prefixes.iter().any(|prefix| {
        text.match_indices(*prefix).any(|(start, prefix)| {
            text.get(start + prefix.len()..).is_some_and(|suffix| {
                suffix
                    .bytes()
                    .take(minimum)
                    .take_while(|byte| body(*byte))
                    .count()
                    == minimum
            })
        })
    })
}

/// A credential prefix followed by at least `minimum` bytes of `body`.
struct TokenShape {
    kind: &'static str,
    prefixes: &'static [&'static str],
    minimum: usize,
    body: fn(u8) -> bool,
}

/// Distinctive credential prefixes. When two rows match, the first names
/// the kind.
const TOKEN_SHAPES: &[TokenShape] = &[
    TokenShape {
        kind: "an AWS access-key ID",
        prefixes: &["AKIA", "ASIA"],
        minimum: 16,
        body: upper_or_digit,
    },
    TokenShape {
        kind: "a GitHub token",
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        minimum: 36,
        body: alphanumeric,
    },
    TokenShape {
        kind: "a GitHub token",
        prefixes: &["github_pat_"],
        minimum: 82,
        body: token_byte,
    },
    TokenShape {
        kind: "a GitHub token",
        prefixes: &["ghs_"],
        minimum: 36,
        body: token_byte,
    },
    TokenShape {
        kind: "a Slack token",
        prefixes: &[
            "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-", "xoxe.", "xapp-",
        ],
        minimum: 8,
        body: token_byte,
    },
    TokenShape {
        kind: "a Google API key",
        prefixes: &["AIza"],
        minimum: 35,
        body: token_byte,
    },
    TokenShape {
        kind: "a Stripe live key",
        prefixes: &["sk_live_", "rk_live_"],
        minimum: 24,
        body: alphanumeric,
    },
    TokenShape {
        kind: "a model-provider key",
        prefixes: &["sk-"],
        minimum: 48,
        body: alphanumeric,
    },
    TokenShape {
        kind: "a model-provider key",
        prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-"],
        minimum: 40,
        body: token_byte,
    },
    TokenShape {
        kind: "a Proofline token",
        prefixes: &["plp_", "plo_", "pld_"],
        minimum: 52,
        body: base32,
    },
    TokenShape {
        kind: "a GitLab personal access token",
        prefixes: &["glpat-"],
        minimum: 20,
        body: token_byte,
    },
    TokenShape {
        kind: "an npm access token",
        prefixes: &["npm_"],
        minimum: 36,
        body: alphanumeric,
    },
    TokenShape {
        kind: "a Hugging Face token",
        prefixes: &["hf_"],
        minimum: 34,
        body: alphanumeric,
    },
    TokenShape {
        kind: "a PyPI API token",
        prefixes: &["pypi-AgEIcHlwaS5vcmc"],
        minimum: 50,
        body: token_byte,
    },
];

/// Literal private-key markers and distinctive credential prefixes. This
/// check refuses the original bytes; it never rewrites the reviewed patch.
fn secret_shape(text: &str) -> Option<&'static str> {
    if (text.contains("-----BEGIN ") || text.contains("-----END "))
        && (text.contains("PRIVATE KEY-----") || text.contains("PRIVATE KEY BLOCK-----"))
    {
        return Some("a private-key marker");
    }
    if has_azure_storage_key(text) {
        return Some("an Azure Storage account key");
    }
    TOKEN_SHAPES
        .iter()
        .find(|shape| has_token(text, shape.prefixes, shape.minimum, shape.body))
        .map(|shape| shape.kind)
}

#[cfg(test)]
mod tests {
    use super::secret_shape;

    #[test]
    fn credential_families_refuse_minimum_bodies_but_accept_short_or_invalid_ones() {
        let cases = [
            (
                &["AKIA", "ASIA"][..],
                16,
                "AZ09",
                'a',
                "an AWS access-key ID",
            ),
            (
                &["ghp_", "gho_", "ghu_", "ghr_"][..],
                36,
                "Az09",
                '_',
                "a GitHub token",
            ),
            (&["ghs_"][..], 36, "Az09_.-", '!', "a GitHub token"),
            (&["github_pat_"][..], 82, "Az09_.-", '!', "a GitHub token"),
            (
                &[
                    "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-", "xoxe.", "xapp-",
                ][..],
                8,
                "Az09_.-",
                '!',
                "a Slack token",
            ),
            (&["AIza"][..], 35, "Az09_.-", '!', "a Google API key"),
            (
                &["sk_live_", "rk_live_"][..],
                24,
                "Az09",
                '_',
                "a Stripe live key",
            ),
            (&["sk-"][..], 48, "Az09", '_', "a model-provider key"),
            (
                &["sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-"][..],
                40,
                "Az09_.-",
                '!',
                "a model-provider key",
            ),
            (
                &["plp_", "plo_", "pld_"][..],
                52,
                "AZ27",
                '8',
                "a Proofline token",
            ),
            (
                &["glpat-"][..],
                20,
                "Az09_.-",
                '!',
                "a GitLab personal access token",
            ),
            (&["npm_"][..], 36, "Az09", '_', "an npm access token"),
            (&["hf_"][..], 34, "Az09", '_', "a Hugging Face token"),
            (
                &["pypi-AgEIcHlwaS5vcmc"][..],
                50,
                "Az09_.-",
                '!',
                "a PyPI API token",
            ),
        ];
        for (prefixes, minimum, alphabet, invalid, label) in cases {
            let body: String = alphabet.chars().cycle().take(minimum).collect();
            let short: String = alphabet.chars().cycle().take(minimum - 1).collect();
            for prefix in prefixes {
                assert_eq!(
                    secret_shape(&format!("{prefix}{body}")),
                    Some(label),
                    "minimum body for {prefix}"
                );
                assert_eq!(
                    secret_shape(&format!("{prefix}{short}")),
                    None,
                    "short body for {prefix}"
                );
                assert_eq!(
                    secret_shape(&format!("{prefix}{short}{invalid}")),
                    None,
                    "invalid final byte for {prefix}"
                );
            }
        }
    }

    #[test]
    fn private_key_markers_refuse_both_edges_and_suffixes_but_accept_certificates() {
        for edge in ["BEGIN", "END"] {
            for kind in ["PRIVATE KEY", "PGP PRIVATE KEY BLOCK"] {
                assert_eq!(
                    secret_shape(&format!("-----{edge} {kind}-----")),
                    Some("a private-key marker")
                );
            }
        }
        assert_eq!(secret_shape("-----BEGIN CERTIFICATE-----"), None);
    }

    #[test]
    fn ordinary_text_has_no_secret_shape() {
        assert_eq!(
            secret_shape("ordinary source text without credentials"),
            None
        );
    }

    #[test]
    fn azure_storage_account_keys_require_full_base64_key() {
        let key: String = "AZaz09+/".chars().cycle().take(86).collect();
        let connection = format!(
            "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey={key}==;EndpointSuffix=core.windows.net"
        );
        assert_eq!(
            secret_shape(&connection),
            Some("an Azure Storage account key")
        );
        assert_eq!(
            secret_shape(&format!("AccountKey={key}==")),
            Some("an Azure Storage account key")
        );
        // Short, missing padding, trailing extra base64 byte, or placeholder must pass.
        let short_key: String = key.chars().take(85).collect();
        assert_eq!(secret_shape(&format!("AccountKey={short_key}==;")), None);
        assert_eq!(secret_shape(&format!("AccountKey={key}=")), None);
        assert_eq!(secret_shape(&format!("AccountKey={key}==A")), None);
        assert_eq!(secret_shape("AccountKey=replace-me-in-env;"), None);
    }

    #[test]
    fn scan_collects_multiple_findings_across_files_and_respects_allow_path() {
        use super::{Finding, scan};
        use crate::git::{LocalChanges, PatchPaths};

        let azure_key = format!("{}==;", "A".repeat(86));
        let gitlab = format!("glpat-{}", "a".repeat(20));
        let patch = [
            "diff --git a/.env b/.env".to_owned(),
            "--- /dev/null".to_owned(),
            "+++ b/.env".to_owned(),
            "@@ -0,0 +1 @@".to_owned(),
            "+APP_ENV=local".to_owned(),
            "diff --git a/infra/storage.tf b/infra/storage.tf".to_owned(),
            "--- a/infra/storage.tf".to_owned(),
            "+++ b/infra/storage.tf".to_owned(),
            "@@ -1,1 +1,2 @@".to_owned(),
            " resource \"azurerm_storage_account\" \"main\" {}".to_owned(),
            format!("+AccountKey={azure_key}"),
            "diff --git a/scripts/release.sh b/scripts/release.sh".to_owned(),
            "--- a/scripts/release.sh".to_owned(),
            "+++ b/scripts/release.sh".to_owned(),
            "@@ -1,1 +1,2 @@".to_owned(),
            " #!/bin/sh".to_owned(),
            format!("+TOKEN={gitlab}"),
            String::new(),
        ]
        .join("\n");
        let changes = LocalChanges {
            base_commit_sha: "a".repeat(40),
            patch,
            paths: vec![
                PatchPaths {
                    old: None,
                    new: Some(".env".to_owned()),
                },
                PatchPaths {
                    old: Some("infra/storage.tf".to_owned()),
                    new: Some("infra/storage.tf".to_owned()),
                },
                PatchPaths {
                    old: Some("scripts/release.sh".to_owned()),
                    new: Some("scripts/release.sh".to_owned()),
                },
            ],
        };

        let findings = scan(&changes, &[]).expect("patch parses cleanly");
        assert_eq!(
            findings,
            vec![
                Finding::EnvironmentPath {
                    path: ".env".to_owned(),
                },
                Finding::Secret {
                    path: "infra/storage.tf".to_owned(),
                    line: 2,
                    coordinate: "new line",
                    kind: "an Azure Storage account key",
                },
                Finding::Secret {
                    path: "scripts/release.sh".to_owned(),
                    line: 2,
                    coordinate: "new line",
                    kind: "a GitLab personal access token",
                },
            ]
        );

        let allowed = vec!["infra/storage.tf".to_owned()];
        let filtered = scan(&changes, &allowed).expect("patch parses cleanly");
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|f| match f {
            Finding::EnvironmentPath { path } | Finding::Secret { path, .. } => {
                path != "infra/storage.tf"
            }
        }));
    }
}
