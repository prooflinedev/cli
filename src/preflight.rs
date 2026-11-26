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

fn hexadecimal(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
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
    TokenShape {
        kind: "a GitLab token",
        prefixes: &["glpat-", "glrt-", "glptt-"],
        minimum: 20,
        body: token_byte,
    },
    TokenShape {
        kind: "an npm token",
        prefixes: &["npm_"],
        minimum: 36,
        body: token_byte,
    },
    TokenShape {
        kind: "a PyPI token",
        prefixes: &["pypi-AgEIcHlwaS5vcmc"],
        minimum: 40,
        body: token_byte,
    },
    TokenShape {
        kind: "a SendGrid API key",
        prefixes: &["SG."],
        minimum: 22,
        body: token_byte,
    },
    TokenShape {
        kind: "a Mailgun API key",
        prefixes: &["key-"],
        minimum: 32,
        body: token_byte,
    },
    TokenShape {
        kind: "a DigitalOcean token",
        prefixes: &["dop_v1_", "dosa_v1_"],
        minimum: 40,
        body: token_byte,
    },
    TokenShape {
        kind: "a Twilio API key",
        prefixes: &["SK"],
        minimum: 32,
        body: hexadecimal,
    },
];

/// A signed JWT: three base64url segments, the first two of which are JSON
/// objects and so start with `eyJ`. An `alg=none` token has no signature and
/// carries no credential, so it is deliberately not named.
fn has_jwt(text: &str) -> bool {
    text.match_indices("eyJ").any(|(start, _)| {
        let Some(tail) = text.get(start..) else {
            return false;
        };
        let Some(header_end) = tail.find('.') else {
            return false;
        };
        let Some(header) = tail.get(..header_end) else {
            return false;
        };
        if header.len() < 12 || !header.bytes().all(token_byte) {
            return false;
        }
        let Some(rest) = tail.get(header_end + 1..) else {
            return false;
        };
        if !rest.starts_with("eyJ") {
            return false;
        }
        let Some(payload_end) = rest.find('.') else {
            return false;
        };
        let Some(payload) = rest.get(..payload_end) else {
            return false;
        };
        if payload.len() < 12 || !payload.bytes().all(token_byte) {
            return false;
        }
        // Quotes and statement punctuation follow the signature in source;
        // only its leading base64url bytes are part of the token.
        let Some(signature) = rest.get(payload_end + 1..) else {
            return false;
        };
        signature
            .bytes()
            .take_while(|byte| token_byte(*byte))
            .count()
            >= 8
    })
}

/// A Telegram bot token: a numeric bot ID, a colon, and a 35-character secret.
fn has_telegram_bot_token(text: &str) -> bool {
    text.match_indices(':').any(|(colon, _)| {
        let (Some(before), Some(after)) = (text.get(..colon), text.get(colon + 1..)) else {
            return false;
        };
        let digits = before.bytes().rev().take_while(u8::is_ascii_digit).count();
        digits >= 8 && after.len() >= 35 && after.bytes().take(35).all(token_byte)
    })
}

/// The two sides of a credential assignment in source, JSON, YAML or a shell
/// file. Only one line is inspected, so a multi-line value is out of scope.
fn assignment(text: &str) -> Option<(&str, &str)> {
    let (name, value) = match text.split_once('=') {
        Some(parts) => parts,
        None => text.split_once(':')?,
    };
    let mut name = name.trim();
    for prefix in [
        "export ", "let ", "const ", "var ", "final ", "static ", "val ", "pub ",
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            name = rest.trim();
            break;
        }
    }
    let name = name.trim_matches(|character| matches!(character, '"' | '\'' | '`'));
    if name.is_empty() {
        return None;
    }
    let value = value
        .trim()
        .trim_end_matches([';', ','])
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\'' | '`'));
    Some((name, value))
}

/// Whether an assignment's name asks for a credential. Public keys and public
/// hashes are not credentials, even when their values are long and varied.
fn secret_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    if lowered.contains("public")
        || lowered.contains("certificate")
        || lowered.contains("fingerprint")
        || lowered.contains("checksum")
    {
        return false;
    }
    lowered
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| {
            matches!(
                part,
                "key"
                    | "secret"
                    | "token"
                    | "password"
                    | "passwd"
                    | "pwd"
                    | "credential"
                    | "credentials"
                    | "apikey"
                    | "authtoken"
                    | "authorization"
                    | "auth"
                    | "session"
                    | "cookie"
                    | "signature"
                    | "bearer"
                    | "encryptionkey"
                    | "masterkey"
            )
        })
}

/// Whether an opaque value looks like a credential rather than a placeholder:
/// long, ASCII, without spaces, with many distinct characters and no character
/// dominating it. Integer counts keep this rule independent of float rounding.
fn diverse(value: &str) -> bool {
    if value.len() < 20 || value.len() > 512 {
        return false;
    }
    let mut counts = [0usize; 128];
    let mut distinct = 0usize;
    let mut most = 0usize;
    for byte in value.bytes() {
        if byte >= 128 {
            return false;
        }
        let count = &mut counts[usize::from(byte)];
        if *count == 0 {
            distinct += 1;
        }
        *count += 1;
        most = most.max(*count);
    }
    distinct >= 12 && most * 2 <= value.len()
}

/// A credential in a named assignment catches providers without a distinctive
/// prefix, such as a 40-character AWS secret access key.
fn assigned_secret(text: &str) -> bool {
    let Some((name, value)) = assignment(text) else {
        return false;
    };
    secret_name(name)
        && !value.starts_with("${")
        && !value.starts_with('<')
        && !value.contains("://")
        && diverse(value)
}

/// Literal private-key markers, distinctive credential prefixes, structured
/// tokens and credential assignments. This check refuses the original bytes;
/// it never rewrites the reviewed patch.
fn secret_shape(text: &str) -> Option<&'static str> {
    if (text.contains("-----BEGIN ") || text.contains("-----END "))
        && (text.contains("PRIVATE KEY-----") || text.contains("PRIVATE KEY BLOCK-----"))
    {
        return Some("a private-key marker");
    }
    if let Some(shape) = TOKEN_SHAPES
        .iter()
        .find(|shape| has_token(text, shape.prefixes, shape.minimum, shape.body))
    {
        return Some(shape.kind);
    }
    if has_jwt(text) {
        return Some("a JSON Web Token");
    }
    if has_telegram_bot_token(text) {
        return Some("a Telegram bot token");
    }
    if assigned_secret(text) {
        return Some("a credential assignment");
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

    #[test]
    fn additional_credential_families_are_refused() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let cases = [
            (format!("glpat-{}", "A".repeat(20)), "a GitLab token"),
            (format!("npm_{}", "a".repeat(36)), "an npm token"),
            (
                format!("pypi-AgEIcHlwaS5vcmc{}", "a".repeat(48)),
                "a PyPI token",
            ),
            (format!("SG.{}", "a".repeat(22)), "a SendGrid API key"),
            (format!("key-{}", "a".repeat(32)), "a Mailgun API key"),
            (format!("dop_v1_{}", "a".repeat(40)), "a DigitalOcean token"),
            (format!("SK{}", "a".repeat(32)), "a Twilio API key"),
            (
                format!("123456789:{}", "A".repeat(35)),
                "a Telegram bot token",
            ),
            (jwt.to_owned(), "a JSON Web Token"),
        ];
        for (text, kind) in cases {
            assert_eq!(secret_shape(&text), Some(kind), "{text}");
        }
    }

    #[test]
    fn high_entropy_credential_assignments_are_refused() {
        let value = "aB3dE5gH7jK9mN2pQ4rS6tU8vW0xY1z";
        for line in [
            format!("AWS_SECRET_ACCESS_KEY={value}"),
            format!("\"api_key\": \"{value}\""),
            format!("export CLIENT_SECRET='{value}';"),
            format!("authToken: {value}"),
        ] {
            assert_eq!(
                secret_shape(&line),
                Some("a credential assignment"),
                "{line}"
            );
        }
    }

    #[test]
    fn ordinary_assignments_and_placeholders_are_allowed() {
        for line in [
            "version = \"1.2.3\"",
            "public_key = \"ssh-rsa AAAAB3NzaC1yc2EAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
            "api_key = \"${API_KEY}\"",
            "token = \"your_token_here\"",
            "author = \"Some Very Long Author Name Here\"",
            "checksum = \"0123456789abcdef0123456789abcdef\"",
        ] {
            assert_eq!(secret_shape(line), None, "{line}");
        }
    }
}
