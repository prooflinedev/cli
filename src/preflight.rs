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
    let mut current = None;
    let mut hunk = None;
    for (patch_line, line) in changes.patch.lines().enumerate() {
        if line.starts_with("diff --git ") {
            let file = paths.next().ok_or(PreflightError::InvalidPatch)?;
            environment_paths(file, allowed)?;
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
            )?;
            hunk = Some(hunk_lines(line)?);
        } else if let Some(lines) = &mut hunk {
            inspect_hunk(file, lines, line, allowed)?;
        }
    }
    if paths.next().is_some() {
        return Err(PreflightError::InvalidPatch);
    }
    Ok(())
}

fn environment_paths(file: &PatchPaths, allowed: &[String]) -> Result<(), PreflightError> {
    for path in [&file.old, &file.new]
        .iter()
        .filter_map(|path| path.as_deref())
    {
        if !is_allowed(path, allowed)
            && path
                .split('/')
                .any(|part| part == ".env" || part.starts_with(".env."))
        {
            return Err(PreflightError::EnvironmentPath(path.to_owned()));
        }
    }
    Ok(())
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
) -> Result<(), PreflightError> {
    if let Some(text) = line.strip_prefix('+') {
        inspect(file.new.as_deref(), lines.new, "new line", text, allowed)?;
        lines.new = next_line(lines.new)?;
    } else if let Some(text) = line.strip_prefix('-') {
        inspect(file.old.as_deref(), lines.old, "base line", text, allowed)?;
        lines.old = next_line(lines.old)?;
    } else if let Some(text) = line.strip_prefix(' ') {
        inspect(
            file.new.as_deref().or(file.old.as_deref()),
            lines.new,
            "new line",
            text,
            allowed,
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
) -> Result<(), PreflightError> {
    let path = path.ok_or(PreflightError::InvalidPatch)?;
    if !is_allowed(path, allowed)
        && let Some(kind) = secret_shape(text)
    {
        return Err(PreflightError::Secret {
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

/// Literal private-key markers and distinctive credential prefixes. This
/// check refuses the original bytes; it never rewrites the reviewed patch.
fn secret_shape(text: &str) -> Option<&'static str> {
    if (text.contains("-----BEGIN ") || text.contains("-----END "))
        && (text.contains("PRIVATE KEY-----") || text.contains("PRIVATE KEY BLOCK-----"))
    {
        return Some("a private-key marker");
    }
    if has_token(text, &["AKIA", "ASIA"], 16, |byte| {
        byte.is_ascii_uppercase() || byte.is_ascii_digit()
    }) {
        return Some("an AWS access-key ID");
    }
    if has_token(
        text,
        &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        36,
        |byte| byte.is_ascii_alphanumeric(),
    ) || has_token(text, &["github_pat_"], 82, token_byte)
        || has_token(text, &["ghs_"], 36, token_byte)
    {
        return Some("a GitHub token");
    }
    if has_token(
        text,
        &[
            "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-", "xoxe.", "xapp-",
        ],
        8,
        token_byte,
    ) {
        return Some("a Slack token");
    }
    if has_token(text, &["AIza"], 35, token_byte) {
        return Some("a Google API key");
    }
    if has_token(text, &["sk_live_", "rk_live_"], 24, |byte| {
        byte.is_ascii_alphanumeric()
    }) {
        return Some("a Stripe live key");
    }
    if has_token(text, &["sk-"], 48, |byte| byte.is_ascii_alphanumeric())
        || has_token(
            text,
            &["sk-proj-", "sk-svcacct-", "sk-admin-"],
            40,
            token_byte,
        )
        || has_token(text, &["sk-ant-"], 40, token_byte)
    {
        return Some("a model-provider key");
    }
    if has_token(text, &["plp_", "plo_", "pld_"], 52, |byte| {
        byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7')
    }) {
        return Some("a Proofline token");
    }
    None
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
