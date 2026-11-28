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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    First,
    All,
}

pub(crate) fn check(changes: &LocalChanges, allowed: &[String]) -> Result<(), PreflightError> {
    if let Some(first) = scan_with_mode(changes, allowed, ScanMode::First)?
        .into_iter()
        .next()
    {
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
    scan_with_mode(changes, allowed, ScanMode::All)
}

fn scan_with_mode(
    changes: &LocalChanges,
    allowed: &[String],
    mode: ScanMode,
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
            environment_paths(file, allowed, mode, &mut findings);
            if mode == ScanMode::First && !findings.is_empty() {
                return Ok(findings);
            }
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
                mode,
                &mut findings,
            )?;
            if mode == ScanMode::First && !findings.is_empty() {
                return Ok(findings);
            }
            hunk = Some(hunk_lines(line)?);
        } else if let Some(lines) = &mut hunk {
            inspect_hunk(file, lines, line, allowed, mode, &mut findings)?;
            if mode == ScanMode::First && !findings.is_empty() {
                return Ok(findings);
            }
        }
    }
    if paths.next().is_some() {
        return Err(PreflightError::InvalidPatch);
    }
    Ok(findings)
}

fn environment_paths(
    file: &PatchPaths,
    allowed: &[String],
    mode: ScanMode,
    findings: &mut Vec<Finding>,
) {
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
            if mode == ScanMode::First {
                return;
            }
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
    mode: ScanMode,
    findings: &mut Vec<Finding>,
) -> Result<(), PreflightError> {
    if let Some(text) = line.strip_prefix('+') {
        inspect(
            file.new.as_deref(),
            lines.new,
            "new line",
            text,
            allowed,
            mode,
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
            mode,
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
            mode,
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
    mode: ScanMode,
    findings: &mut Vec<Finding>,
) -> Result<(), PreflightError> {
    let path = path.ok_or(PreflightError::InvalidPatch)?;
    if !is_allowed(path, allowed) {
        for kind in secret_shapes(text) {
            findings.push(Finding::Secret {
                path: path.to_owned(),
                line,
                coordinate,
                kind,
            });
            if mode == ScanMode::First {
                break;
            }
        }
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
/// characters (86 base64 data bytes followed by `==`) after a case-insensitive
/// `AccountKey=` connection-string field.
fn has_azure_storage_key(text: &str) -> bool {
    const PREFIX: &[u8] = b"AccountKey=";
    const DATA_LEN: usize = 86;
    const KEY_LEN: usize = DATA_LEN + 2;

    let bytes = text.as_bytes();
    bytes
        .windows(PREFIX.len())
        .enumerate()
        .any(|(start, window)| {
            if !window.eq_ignore_ascii_case(PREFIX) {
                return false;
            }
            let Some(suffix) = bytes.get(start + PREFIX.len()..) else {
                return false;
            };
            if suffix.len() < KEY_LEN {
                return false;
            }
            suffix[..DATA_LEN].iter().all(|byte| base64_data(*byte))
                && suffix[DATA_LEN..KEY_LEN] == *b"=="
                && suffix
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
fn secret_shapes(text: &str) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    if (text.contains("-----BEGIN ") || text.contains("-----END "))
        && (text.contains("PRIVATE KEY-----") || text.contains("PRIVATE KEY BLOCK-----"))
    {
        kinds.push("a private-key marker");
    }
    if has_azure_storage_key(text) {
        kinds.push("an Azure Storage account key");
    }
    for shape in TOKEN_SHAPES {
        if has_token(text, shape.prefixes, shape.minimum, shape.body)
            && !kinds.contains(&shape.kind)
        {
            kinds.push(shape.kind);
        }
    }
    kinds
}

#[cfg(test)]
fn secret_shape(text: &str) -> Option<&'static str> {
    secret_shapes(text).into_iter().next()
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
        assert_eq!(
            secret_shape(&format!("accountkey={key}==;")),
            Some("an Azure Storage account key")
        );
        assert_eq!(
            secret_shape(&format!("ACCOUNTKEY={key}==;")),
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

    #[test]
    fn scan_reports_every_credential_family_on_a_single_line() {
        use super::{Finding, scan};
        use crate::git::{LocalChanges, PatchPaths};

        let gitlab = format!("glpat-{}", "a".repeat(20));
        let npm = format!("npm_{}", "b".repeat(36));
        let patch = [
            "diff --git a/ci.env.sh b/ci.env.sh".to_owned(),
            "--- /dev/null".to_owned(),
            "+++ b/ci.env.sh".to_owned(),
            "@@ -0,0 +1 @@".to_owned(),
            format!("+GL={gitlab} NPM={npm}"),
            String::new(),
        ]
        .join("\n");
        let changes = LocalChanges {
            base_commit_sha: "a".repeat(40),
            patch,
            paths: vec![PatchPaths {
                old: None,
                new: Some("ci.env.sh".to_owned()),
            }],
        };

        let findings = scan(&changes, &[]).expect("patch parses cleanly");
        assert_eq!(
            findings,
            vec![
                Finding::Secret {
                    path: "ci.env.sh".to_owned(),
                    line: 1,
                    coordinate: "new line",
                    kind: "a GitLab personal access token",
                },
                Finding::Secret {
                    path: "ci.env.sh".to_owned(),
                    line: 1,
                    coordinate: "new line",
                    kind: "an npm access token",
                },
            ]
        );
    }

    #[test]
    fn check_returns_earlier_refusal_before_later_patch_parse_error() {
        use super::{PreflightError, check};
        use crate::git::{LocalChanges, PatchPaths};

        let gitlab = format!("glpat-{}", "a".repeat(20));
        let patch = [
            "diff --git a/first.rs b/first.rs".to_owned(),
            "--- /dev/null".to_owned(),
            "+++ b/first.rs".to_owned(),
            "@@ -0,0 +1 @@".to_owned(),
            format!("+const TOKEN: &str = \"{gitlab}\";"),
            "diff --git a/second.rs b/second.rs".to_owned(),
            "@@ broken @@".to_owned(),
            String::new(),
        ]
        .join("\n");
        let changes = LocalChanges {
            base_commit_sha: "a".repeat(40),
            patch,
            paths: vec![
                PatchPaths {
                    old: None,
                    new: Some("first.rs".to_owned()),
                },
                PatchPaths {
                    old: None,
                    new: Some("second.rs".to_owned()),
                },
            ],
        };

        assert!(matches!(
            check(&changes, &[]),
            Err(PreflightError::Secret {
                ref path,
                line: 1,
                kind: "a GitLab personal access token",
                ..
            }) if path == "first.rs"
        ));
    }
}
