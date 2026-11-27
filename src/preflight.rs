//! Local refusals before any patch bytes leave the checkout.

use std::fmt;

use crate::git::{LocalChanges, PatchPaths};

/// How many refused lines the report prints before it counts the rest. A
/// patch may hold thousands of files, and a wall of lines hides the first
/// one the person must fix anyway.
const SHOWN: usize = 20;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PreflightError {
    #[error(
        "--allow-path {0:?} is not an exact repository-relative path; use the path from the local refusal"
    )]
    InvalidAllowPath(String),
    #[error("{0}")]
    Refused(Refusals),
    #[error("could not map the local patch to file paths and lines; no review was requested")]
    InvalidPatch,
}

/// Every problem in the patch, in patch order. One run names them all, so the
/// person removes them in one edit instead of one run per secret.
#[derive(Debug)]
pub(crate) struct Refusals(Vec<Issue>);

#[derive(Debug)]
enum Issue {
    /// A path Git tracks as an environment file, whatever its content.
    SensitivePath(String),
    /// A credential shape on one patch line.
    Secret {
        path: String,
        line: usize,
        coordinate: &'static str,
        kind: &'static str,
    },
}

impl fmt::Display for Refusals {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.0.len();
        write!(
            formatter,
            "local patch has {count} {}; remove {} before upload, or pass --allow-path for each exact path:",
            if count == 1 { "problem" } else { "problems" },
            if count == 1 { "it" } else { "them" },
        )?;
        for issue in self.0.iter().take(SHOWN) {
            write!(formatter, "\n  {issue}")?;
        }
        if count > SHOWN {
            write!(formatter, "\n  and {} more", count - SHOWN)?;
        }
        Ok(())
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SensitivePath(path) => write!(formatter, "{path:?}: a sensitive .env path"),
            Self::Secret {
                path,
                line,
                coordinate,
                kind,
            } => write!(formatter, "{path:?}:{line} ({coordinate}): {kind}"),
        }
    }
}

#[derive(Debug)]
struct Lines {
    old: usize,
    new: usize,
}

pub(crate) fn check(changes: &LocalChanges, allowed: &[String]) -> Result<(), PreflightError> {
    for path in allowed {
        if path.starts_with('/') || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
            return Err(PreflightError::InvalidAllowPath(path.clone()));
        }
    }
    let mut paths = changes.paths.iter();
    let mut current: Option<(&PatchPaths, bool)> = None;
    let mut hunk = None;
    let mut found = Vec::new();
    for (patch_line, line) in changes.patch.lines().enumerate() {
        if line.starts_with("diff --git ") {
            let file = paths.next().ok_or(PreflightError::InvalidPatch)?;
            // A refused path is not scanned line by line: every one of its
            // lines would repeat the same refusal.
            let refused = environment_paths(file, allowed, &mut found);
            current = Some((file, refused));
            hunk = None;
            continue;
        }
        let (file, refused) = *current.as_ref().ok_or(PreflightError::InvalidPatch)?;
        if line.starts_with("@@ ") {
            // A section heading can quote a line outside the hunk. Its exact
            // coordinate is a patch line, not a guessed source-file line.
            if !refused {
                inspect(
                    file.new.as_deref().or(file.old.as_deref()),
                    patch_line + 1,
                    "patch line",
                    line,
                    allowed,
                    &mut found,
                )?;
            }
            hunk = Some(hunk_lines(line)?);
        } else if let Some(lines) = &mut hunk {
            inspect_hunk(file, lines, line, allowed, refused, &mut found)?;
        }
    }
    if paths.next().is_some() {
        return Err(PreflightError::InvalidPatch);
    }
    if found.is_empty() {
        Ok(())
    } else {
        Err(PreflightError::Refused(Refusals(found)))
    }
}

/// Collects a refusal for each endpoint Git tracks as an environment file,
/// and reports whether the file's lines still need a scan.
fn environment_paths(file: &PatchPaths, allowed: &[String], found: &mut Vec<Issue>) -> bool {
    let mut refused = false;
    for path in [&file.old, &file.new]
        .iter()
        .filter_map(|path| path.as_deref())
    {
        if !is_allowed(path, allowed)
            && path
                .split('/')
                .any(|part| part == ".env" || part.starts_with(".env."))
        {
            found.push(Issue::SensitivePath(path.to_owned()));
            refused = true;
        }
    }
    refused
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
    refused: bool,
    found: &mut Vec<Issue>,
) -> Result<(), PreflightError> {
    if let Some(text) = line.strip_prefix('+') {
        if !refused {
            inspect(
                file.new.as_deref(),
                lines.new,
                "new line",
                text,
                allowed,
                found,
            )?;
        }
        lines.new = next_line(lines.new)?;
    } else if let Some(text) = line.strip_prefix('-') {
        if !refused {
            inspect(
                file.old.as_deref(),
                lines.old,
                "base line",
                text,
                allowed,
                found,
            )?;
        }
        lines.old = next_line(lines.old)?;
    } else if let Some(text) = line.strip_prefix(' ') {
        if !refused {
            inspect(
                file.new.as_deref().or(file.old.as_deref()),
                lines.new,
                "new line",
                text,
                allowed,
                found,
            )?;
        }
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
    found: &mut Vec<Issue>,
) -> Result<(), PreflightError> {
    let path = path.ok_or(PreflightError::InvalidPatch)?;
    if !is_allowed(path, allowed)
        && let Some(kind) = secret_shape(text)
    {
        found.push(Issue::Secret {
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
];

/// Literal private-key markers and distinctive credential prefixes. This
/// check refuses the original bytes; it never rewrites the reviewed patch.
fn secret_shape(text: &str) -> Option<&'static str> {
    if (text.contains("-----BEGIN ") || text.contains("-----END "))
        && (text.contains("PRIVATE KEY-----") || text.contains("PRIVATE KEY BLOCK-----"))
    {
        return Some("a private-key marker");
    }
    TOKEN_SHAPES
        .iter()
        .find(|shape| has_token(text, shape.prefixes, shape.minimum, shape.body))
        .map(|shape| shape.kind)
}

#[cfg(test)]
mod tests {
    use super::{Issue, Refusals, SHOWN, secret_shape};

    #[test]
    fn every_refusal_is_listed_once_and_the_tail_is_counted() {
        let one = Refusals(vec![Issue::SensitivePath(".env".to_owned())]);
        assert_eq!(
            one.to_string(),
            "local patch has 1 problem; remove it before upload, or pass --allow-path for each exact path:\n  \".env\": a sensitive .env path"
        );
        let many = Refusals(
            (1..=SHOWN + 2)
                .map(|line| Issue::Secret {
                    path: "src/a.rs".to_owned(),
                    line,
                    coordinate: "new line",
                    kind: "a GitHub token",
                })
                .collect(),
        );
        let text = many.to_string();
        assert!(text.starts_with("local patch has 22 problems;"), "{text}");
        assert!(text.ends_with("\n  and 2 more"), "{text}");
        assert_eq!(text.lines().count(), SHOWN + 2);
    }

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
}
