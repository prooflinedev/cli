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

/// The RFC 4648 base64 alphabet, without `=` padding.
fn base64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

/// The RFC 4648 URL- and filename-safe base64 alphabet, without `=` padding.
fn base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
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
    // https://docs.gitlab.com/user/profile/personal_access_tokens/
    // A token is `glpat-` followed by 20 characters; the rule requires at least 20.
    TokenShape {
        kind: "a GitLab personal access token",
        prefixes: &["glpat-"],
        minimum: 20,
        body: base64url,
    },
    // https://docs.npmjs.com/about-access-tokens
    // A token is `npm_` followed by 36 alphanumerics; the rule requires at least 36.
    TokenShape {
        kind: "an npm access token",
        prefixes: &["npm_"],
        minimum: 36,
        body: alphanumeric,
    },
    // https://huggingface.co/docs/hub/security-tokens documents only the `hf_`
    // prefix. The length and alphabet are not vendor-documented: a measured
    // token had 34 letters after `hf_`, matching the gitleaks rule.
    // Alphanumeric keeps the rule a superset of that shape if the format adds
    // digits.
    TokenShape {
        kind: "a Hugging Face access token",
        prefixes: &["hf_"],
        minimum: 34,
        body: alphanumeric,
    },
    // https://docs.pypi.org/api/tokens/
    // `pypi-` followed by a base64url body.
    TokenShape {
        kind: "a PyPI API token",
        prefixes: &["pypi-"],
        minimum: 85,
        body: base64url,
    },
];

/// Azurite's well-known development account key for `devstoreaccount1`, which
/// Microsoft publishes under "Use a well-known storage account and key" at
/// <https://learn.microsoft.com/en-us/azure/storage/common/storage-connect-azurite>.
/// It authorizes only the local emulator, so an exact occurrence is no secret.
const AZURITE_ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// The connection-string keyword that names a storage account key. Keywords
/// are ASCII case-insensitive, so it is compared that way, in place.
const ACCOUNT_KEY_KEYWORD: &[u8] = b"accountkey=";

/// The base64 characters of a storage account key before its `==` padding.
const ACCOUNT_KEY_LENGTH: usize = 86;

/// An Azure Storage account key: the `AccountKey=` keyword in any ASCII case,
/// followed by at least 86 base64 characters. A real key is 88 characters
/// including its `==` padding, which is not checked. Every candidate but the
/// exact Azurite key counts. Source:
/// <https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string>.
fn has_account_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .windows(ACCOUNT_KEY_KEYWORD.len())
        .enumerate()
        .filter(|(_, window)| window.eq_ignore_ascii_case(ACCOUNT_KEY_KEYWORD))
        .map(|(start, _)| start + ACCOUNT_KEY_KEYWORD.len())
        .any(|key| {
            bytes
                .iter()
                .skip(key)
                .take(ACCOUNT_KEY_LENGTH)
                .take_while(|byte| base64(**byte))
                .count()
                == ACCOUNT_KEY_LENGTH
                && !is_azurite_key(bytes, key)
        })
}

/// Whether the key at `start` is exactly [`AZURITE_ACCOUNT_KEY`]: the same
/// bytes, not extended by a base64 or `=` byte after them. A candidate always
/// follows the keyword's `=`, so no left boundary check is needed.
fn is_azurite_key(bytes: &[u8], start: usize) -> bool {
    let end = start + AZURITE_ACCOUNT_KEY.len();
    let extended_after = bytes
        .get(end)
        .is_some_and(|byte| base64(*byte) || *byte == b'=');
    bytes.get(start..end) == Some(AZURITE_ACCOUNT_KEY.as_bytes()) && !extended_after
}

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
        // After every token shape, so their labels keep priority.
        .or_else(|| has_account_key(text).then_some("an Azure Storage account key"))
}

#[cfg(test)]
mod tests {
    use super::{AZURITE_ACCOUNT_KEY, secret_shape};

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
                &["AccountKey=", "accountkey=", "ACCOUNTKEY=", "accountKey="][..],
                86,
                "Az09+/",
                '!',
                "an Azure Storage account key",
            ),
            (
                &["glpat-"][..],
                20,
                "Az09_-",
                '.',
                "a GitLab personal access token",
            ),
            // As for `ghs_`, the other base64 alphabet's punctuation is
            // invalid in each base64 family.
            (
                &["AccountKey=", "accountkey=", "ACCOUNTKEY=", "accountKey="][..],
                86,
                "Az09+/",
                '-',
                "an Azure Storage account key",
            ),
            (
                &["AccountKey=", "accountkey=", "ACCOUNTKEY=", "accountKey="][..],
                86,
                "Az09+/",
                '_',
                "an Azure Storage account key",
            ),
            (
                &["glpat-"][..],
                20,
                "Az09_-",
                '+',
                "a GitLab personal access token",
            ),
            (
                &["glpat-"][..],
                20,
                "Az09_-",
                '/',
                "a GitLab personal access token",
            ),
            (&["npm_"][..], 36, "Az09", '_', "an npm access token"),
            (&["pypi-"][..], 85, "Az09_-", '.', "a PyPI API token"),
            (&["pypi-"][..], 85, "Az09_-", '+', "a PyPI API token"),
            (&["pypi-"][..], 85, "Az09_-", '/', "a PyPI API token"),
            (&["hf_"][..], 34, "Az09", '_', "a Hugging Face access token"),
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
    fn identifiers_and_placeholders_near_credential_prefixes_have_no_secret_shape() {
        for text in [
            "npm_config_registry",
            "self.hf_model",
            "AccountKey=<your-key>",
            "AccountKey=${STORAGE_KEY}",
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;",
        ] {
            assert_eq!(secret_shape(text), None, "{text}");
        }
    }

    #[test]
    fn the_azurite_exception_covers_only_the_exact_key() {
        let azurite = format!(
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey={AZURITE_ACCOUNT_KEY};BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
        );
        let github = format!("ghp_{}", "S".repeat(36));
        let real = format!(
            "{}==",
            "Az09+/".chars().cycle().take(86).collect::<String>()
        );
        let azure = Some("an Azure Storage account key");
        for (text, expected, case) in [
            (
                format!("AccountKey=X{AZURITE_ACCOUNT_KEY}"),
                azure,
                "a base64 byte before the key",
            ),
            (
                format!("AccountKey={AZURITE_ACCOUNT_KEY}A"),
                azure,
                "a base64 byte after the padding",
            ),
            (
                format!("AccountKey={AZURITE_ACCOUNT_KEY}="),
                azure,
                "a `=` byte after the padding",
            ),
            (
                format!("AccountKey={AZURITE_ACCOUNT_KEY};AccountKey={AZURITE_ACCOUNT_KEY};"),
                None,
                "two exact Azurite keys on one line",
            ),
            (
                format!("ghp_{AZURITE_ACCOUNT_KEY}"),
                Some("a GitHub token"),
                "a GitHub token that overlaps the key",
            ),
            (
                format!("{azurite} token={github}"),
                Some("a GitHub token"),
                "a GitHub token on the same line",
            ),
            (
                format!("{azurite} AccountName=acme;AccountKey={real};"),
                azure,
                "a real account key on the same line",
            ),
            (
                format!("AccountName=acme;AccountKey={real}; {azurite}"),
                azure,
                "a real account key before an Azurite key on the same line",
            ),
        ] {
            assert_eq!(secret_shape(&text), expected, "{case}");
        }
    }

    /// "Az09+/" cycled to 86 base64 characters, plus `==`: a non-Azurite key.
    fn real_account_key() -> String {
        format!(
            "{}==",
            "Az09+/".chars().cycle().take(86).collect::<String>()
        )
    }

    #[test]
    fn a_field_name_ending_in_account_key_holds_an_account_key() {
        // Suffix matching is deliberate: names such as `StorageAccountKey`
        // hold real keys, so no boundary is required before the keyword.
        let text = format!("StorageAccountKey={}", real_account_key());
        assert_eq!(secret_shape(&text), Some("an Azure Storage account key"));
    }

    #[test]
    fn a_token_label_takes_priority_over_an_account_key_on_the_same_line() {
        let text = format!(
            "AccountName=acme;AccountKey={}; token=ghp_{}",
            real_account_key(),
            "S".repeat(36)
        );
        assert_eq!(secret_shape(&text), Some("a GitHub token"));
    }

    #[test]
    fn ordinary_text_has_no_secret_shape() {
        assert_eq!(
            secret_shape("ordinary source text without credentials"),
            None
        );
    }
}
