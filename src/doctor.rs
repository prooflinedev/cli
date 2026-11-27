//! Environment and integration diagnostics for `proofline doctor`.

use std::io::Write as _;
use std::path::Path;

use clap::Args;
use secrecy::SecretString;
use serde::Serialize;
use uuid::Uuid;

use crate::agent::{self, ClientConfigStatus};
use crate::api::{Api, Http};
use crate::credentials::{self, Credential, Source};
use crate::origin::Origin;
use crate::{Verdict, device, git, hooks, text, tls};

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Print the diagnostic report as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
    /// Skip network requests (server authentication and reachability).
    #[arg(long)]
    offline: bool,
    /// Git remote that names the repository.
    #[arg(long, default_value = "origin")]
    remote: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl CheckStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CheckReport {
    pub(crate) id: &'static str,
    pub(crate) status: CheckStatus,
    pub(crate) summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct DoctorCounts {
    pub(crate) pass: usize,
    pub(crate) warn: usize,
    pub(crate) fail: usize,
    pub(crate) skip: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) ok: bool,
    pub(crate) offline: bool,
    pub(crate) checks: Vec<CheckReport>,
    pub(crate) counts: DoctorCounts,
}

impl DoctorReport {
    pub(crate) fn from_checks(offline: bool, checks: Vec<CheckReport>) -> Self {
        let mut counts = DoctorCounts::default();
        for check in &checks {
            match check.status {
                CheckStatus::Pass => counts.pass += 1,
                CheckStatus::Warn => counts.warn += 1,
                CheckStatus::Fail => counts.fail += 1,
                CheckStatus::Skip => counts.skip += 1,
            }
        }
        Self {
            ok: counts.fail == 0,
            offline,
            checks,
            counts,
        }
    }
}

pub(crate) async fn run(
    args: DoctorArgs,
    base_url: &str,
    ca_cert: Option<&Path>,
    token: Option<SecretString>,
    org: Option<Uuid>,
) -> anyhow::Result<Verdict> {
    let mut checks = Vec::with_capacity(7);

    let (origin_check, parsed_origin) = check_origin(base_url);
    checks.push(origin_check);

    let (tls_check, tls_ok) = check_tls_ca_cert(ca_cert, true);
    checks.push(tls_check);

    let (cred_check, loaded_cred) = check_credentials(parsed_origin.as_ref(), token, org).await;
    checks.push(cred_check);

    checks.push(
        check_server_auth(
            args.offline,
            parsed_origin.as_ref(),
            tls_ok,
            loaded_cred.as_ref(),
        )
        .await,
    );

    let (git_check, in_git_repo) = check_git_repository(Path::new("."), &args.remote).await;
    checks.push(git_check);

    checks.push(check_git_hooks(Path::new("."), in_git_repo).await);

    let inspect_origin = parsed_origin
        .clone()
        .unwrap_or_else(|| Origin::parse(crate::origin::DEFAULT_ORIGIN).expect("default origin"));
    checks.push(check_mcp_clients(None, &inspect_origin));

    let report = DoctorReport::from_checks(args.offline, checks);
    let mut stdout = std::io::stdout().lock();
    if args.json {
        writeln!(stdout, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        write_text(&report, &mut stdout)?;
    }

    Ok(if report.ok {
        Verdict::Done
    } else {
        Verdict::Blocked
    })
}

fn check_origin(base_url: &str) -> (CheckReport, Option<Origin>) {
    match Origin::parse(base_url) {
        Ok(origin) => (
            CheckReport {
                id: "origin",
                status: CheckStatus::Pass,
                summary: format!("Console origin is valid ({origin})"),
                remediation: None,
                details: Some(serde_json::json!({ "origin": origin.as_key() })),
            },
            Some(origin),
        ),
        Err(error) => (
            CheckReport {
                id: "origin",
                status: CheckStatus::Fail,
                summary: text::one_line(&error.to_string()),
                remediation: Some(
                    "Set an HTTPS origin or localhost HTTP URL via --base-url or PROOFLINE_BASE_URL."
                        .to_owned(),
                ),
                details: None,
            },
            None,
        ),
    }
}

fn check_tls_ca_cert(ca_cert: Option<&Path>, apply_trust: bool) -> (CheckReport, bool) {
    let Some(path) = ca_cert else {
        return (
            CheckReport {
                id: "tls_ca_cert",
                status: CheckStatus::Pass,
                summary: "Using bundled system and webpki root certificates".to_owned(),
                remediation: None,
                details: Some(serde_json::json!({ "configured": false })),
            },
            true,
        );
    };

    let read_result = if apply_trust {
        tls::read(path).and_then(|roots| {
            let count = roots.len();
            tls::trust(path).map(|()| count)
        })
    } else {
        tls::read(path).map(|roots| roots.len())
    };

    match read_result {
        Ok(count) => (
            CheckReport {
                id: "tls_ca_cert",
                status: CheckStatus::Pass,
                summary: format!(
                    "Loaded {count} extra CA certificate(s) from {}",
                    text::one_line(&path.display().to_string())
                ),
                remediation: None,
                details: Some(serde_json::json!({
                    "configured": true,
                    "path": path.display().to_string(),
                    "certificate_count": count,
                })),
            },
            true,
        ),
        Err(error) => (
            CheckReport {
                id: "tls_ca_cert",
                status: CheckStatus::Fail,
                summary: text::one_line(&error.to_string()),
                remediation: Some(
                    "Verify --ca-cert / PROOFLINE_CA_CERT points to a readable PEM certificate file."
                        .to_owned(),
                ),
                details: Some(serde_json::json!({
                    "configured": true,
                    "path": path.display().to_string(),
                })),
            },
            false,
        ),
    }
}

async fn check_credentials(
    origin: Option<&Origin>,
    token: Option<SecretString>,
    org: Option<Uuid>,
) -> (CheckReport, Option<Credential>) {
    if let Some(env_token) = token {
        if let Some(org_id) = org {
            return (
                CheckReport {
                    id: "credentials",
                    status: CheckStatus::Pass,
                    summary: format!("PROOFLINE_TOKEN is set with organization {org_id}"),
                    remediation: None,
                    details: Some(serde_json::json!({
                        "source": "PROOFLINE_TOKEN",
                        "organization_id": org_id,
                    })),
                },
                Some(Credential {
                    token: env_token,
                    organization_id: org_id,
                    scope: None,
                    expires_at: None,
                    source: Source::Environment,
                }),
            );
        }
        return (
            CheckReport {
                id: "credentials",
                status: CheckStatus::Warn,
                summary: "PROOFLINE_TOKEN is set, but no organization ID is selected".to_owned(),
                remediation: Some(
                    "Pass --org <UUID> or set PROOFLINE_ORGANIZATION_ID for REST and native MCP commands."
                        .to_owned(),
                ),
                details: Some(serde_json::json!({ "source": "PROOFLINE_TOKEN" })),
            },
            None,
        );
    }

    let Some(origin) = origin else {
        return (
            CheckReport {
                id: "credentials",
                status: CheckStatus::Skip,
                summary: "Skipped keychain lookup because console origin is invalid".to_owned(),
                remediation: None,
                details: None,
            },
            None,
        );
    };

    #[cfg(target_os = "linux")]
    let session_bus = credentials::default_session_bus();
    #[cfg(not(target_os = "linux"))]
    let session_bus: Option<String> = None;

    match credentials::load(origin, None, org).await {
        Ok(cred) => {
            let expired = cred
                .expires_at
                .is_some_and(|exp| exp.saturating_sub(device::now()) == 0);
            let mut details = serde_json::json!({
                "source": "OS keychain",
                "organization_id": cred.organization_id,
            });
            if let Some(scope) = &cred.scope {
                details["scopes"] = serde_json::json!(text::one_line(scope));
            }
            if let Some(exp) = cred.expires_at {
                details["expires_in_seconds"] =
                    serde_json::json!(exp.saturating_sub(device::now()));
            }
            if expired {
                return (
                    CheckReport {
                        id: "credentials",
                        status: CheckStatus::Warn,
                        summary: format!(
                            "Stored OS keychain credential for organization {} has expired",
                            cred.organization_id
                        ),
                        remediation: Some(
                            "Run `proofline login` to refresh your session.".to_owned(),
                        ),
                        details: Some(details),
                    },
                    Some(cred),
                );
            }
            (
                CheckReport {
                    id: "credentials",
                    status: CheckStatus::Pass,
                    summary: format!(
                        "Loaded OS keychain credential for organization {}",
                        cred.organization_id
                    ),
                    remediation: None,
                    details: Some(details),
                },
                Some(cred),
            )
        }
        Err(error) => {
            let mut remediation =
                "Run `proofline login` or set PROOFLINE_TOKEN and PROOFLINE_ORGANIZATION_ID."
                    .to_owned();
            if session_bus.is_some() {
                remediation.push_str(" (D-Bus user session socket detected.)");
            }
            (
                CheckReport {
                    id: "credentials",
                    status: CheckStatus::Fail,
                    summary: text::one_line(&error.to_string()),
                    remediation: Some(remediation),
                    details: Some(serde_json::json!({ "source": "OS keychain" })),
                },
                None,
            )
        }
    }
}

async fn check_server_auth(
    offline: bool,
    origin: Option<&Origin>,
    tls_ok: bool,
    cred: Option<&Credential>,
) -> CheckReport {
    if offline {
        return CheckReport {
            id: "server_auth",
            status: CheckStatus::Skip,
            summary: "Skipped server reachability and token check (--offline)".to_owned(),
            remediation: None,
            details: None,
        };
    }
    let (Some(origin), true, Some(cred)) = (origin, tls_ok, cred) else {
        return CheckReport {
            id: "server_auth",
            status: CheckStatus::Skip,
            summary: "Skipped server check due to missing origin, TLS, or credential prerequisites"
                .to_owned(),
            remediation: None,
            details: None,
        };
    };

    let http = match Http::new(origin.clone()) {
        Ok(http) => http,
        Err(error) => {
            return CheckReport {
                id: "server_auth",
                status: CheckStatus::Fail,
                summary: text::one_line(&error.to_string()),
                remediation: Some("Check TLS root certificates and console origin.".to_owned()),
                details: None,
            };
        }
    };

    let scans_only = cred.scope.as_deref().is_some_and(|scope| {
        let mut scopes = scope.split_whitespace();
        !scopes.clone().any(|s| s == "reviews:read") && scopes.any(|s| s == "scans:request")
    });
    let api = Api::new(http, cred.token.clone(), cred.organization_id);
    let result = if scans_only {
        api.scan_repository_names().await.map(drop)
    } else {
        api.review_filters().await.map(drop)
    };

    match result {
        Ok(()) => CheckReport {
            id: "server_auth",
            status: CheckStatus::Pass,
            summary: format!(
                "Authenticated with {origin} for organization {}",
                cred.organization_id
            ),
            remediation: None,
            details: Some(serde_json::json!({
                "origin": origin.as_key(),
                "organization_id": cred.organization_id,
            })),
        },
        Err(error) if error.status() == Some(401) => CheckReport {
            id: "server_auth",
            status: CheckStatus::Fail,
            summary: "Server rejected the token (HTTP 401): expired, revoked, or malformed"
                .to_owned(),
            remediation: Some("Run `proofline login` or update PROOFLINE_TOKEN.".to_owned()),
            details: Some(serde_json::json!({ "status": 401 })),
        },
        Err(error) => CheckReport {
            id: "server_auth",
            status: CheckStatus::Fail,
            summary: text::one_line(&error.to_string()),
            remediation: Some(
                "Verify network connectivity, --base-url, or corporate proxy --ca-cert.".to_owned(),
            ),
            details: error
                .status()
                .map(|status| serde_json::json!({ "status": status })),
        },
    }
}

async fn check_git_repository(dir: &Path, remote: &str) -> (CheckReport, bool) {
    let remote_key = format!("remote.{remote}.url");
    match git::config(dir, &remote_key).await {
        Ok(Some(url)) => {
            if let Some(full_name) = git::full_name(&url) {
                return (
                    CheckReport {
                        id: "git_repository",
                        status: CheckStatus::Pass,
                        summary: format!(
                            "Git remote `{}` resolves to {}",
                            text::one_line(remote),
                            text::one_line(&full_name)
                        ),
                        remediation: None,
                        details: Some(serde_json::json!({
                            "remote": remote,
                            "repository": full_name,
                        })),
                    },
                    true,
                );
            }
            (
                CheckReport {
                    id: "git_repository",
                    status: CheckStatus::Warn,
                    summary: format!(
                        "Git remote `{}` is configured, but does not resolve to a GitHub owner/name",
                        text::one_line(remote)
                    ),
                    remediation: Some(
                        "Pass --repo owner/name explicitly or configure a GitHub remote."
                            .to_owned(),
                    ),
                    details: Some(serde_json::json!({ "remote": remote })),
                },
                true,
            )
        }
        Ok(None) => {
            // Inside a git repo without the requested remote, or outside a git repo.
            let in_repo = git::hooks_dir(dir).await.is_ok();
            (
                CheckReport {
                    id: "git_repository",
                    status: CheckStatus::Warn,
                    summary: if in_repo {
                        format!(
                            "Git repository detected, but remote `{}` is not configured",
                            text::one_line(remote)
                        )
                    } else {
                        "Current directory is not inside a Git repository".to_owned()
                    },
                    remediation: Some(
                        "Run inside a Git checkout or pass --repo owner/name to review commands."
                            .to_owned(),
                    ),
                    details: Some(serde_json::json!({ "in_repo": in_repo, "remote": remote })),
                },
                in_repo,
            )
        }
        Err(git::GitError::Unavailable(reason)) => (
            CheckReport {
                id: "git_repository",
                status: CheckStatus::Fail,
                summary: format!("could not run `git`: {}", text::one_line(&reason)),
                remediation: Some("Install Git and ensure `git` is available on PATH.".to_owned()),
                details: None,
            },
            false,
        ),
        Err(error) => (
            CheckReport {
                id: "git_repository",
                status: CheckStatus::Warn,
                summary: text::one_line(&error.to_string()),
                remediation: Some(
                    "Run inside a Git checkout or pass --repo owner/name.".to_owned(),
                ),
                details: None,
            },
            false,
        ),
    }
}

async fn check_git_hooks(dir: &Path, in_git_repo: bool) -> CheckReport {
    if !in_git_repo {
        return CheckReport {
            id: "git_hooks",
            status: CheckStatus::Skip,
            summary: "Skipped Git hook check outside a Git repository".to_owned(),
            remediation: None,
            details: None,
        };
    }

    match hooks::inspect_hooks(dir).await {
        Ok(statuses) => {
            let installed: Vec<&'static str> = statuses
                .iter()
                .filter_map(|(name, present)| present.then_some(*name))
                .collect();
            if installed.is_empty() {
                CheckReport {
                    id: "git_hooks",
                    status: CheckStatus::Warn,
                    summary: "No Proofline Git hooks are installed in this repository".to_owned(),
                    remediation: Some(
                        "Run `proofline hooks install` to review commits/pushes automatically."
                            .to_owned(),
                    ),
                    details: Some(serde_json::json!({ "installed": [] })),
                }
            } else {
                CheckReport {
                    id: "git_hooks",
                    status: CheckStatus::Pass,
                    summary: format!("Installed Proofline Git hooks: {}", installed.join(", ")),
                    remediation: None,
                    details: Some(serde_json::json!({ "installed": installed })),
                }
            }
        }
        Err(error) => CheckReport {
            id: "git_hooks",
            status: CheckStatus::Warn,
            summary: text::one_line(&error.to_string()),
            remediation: Some("Check `git rev-parse --git-path hooks` permissions.".to_owned()),
            details: None,
        },
    }
}

fn check_mcp_clients(home: Option<&Path>, origin: &Origin) -> CheckReport {
    let registrations = agent::inspect_clients(home, origin);
    if registrations.is_empty() {
        return CheckReport {
            id: "mcp_clients",
            status: CheckStatus::Warn,
            summary: "Could not resolve user home directory to inspect MCP client configs"
                .to_owned(),
            remediation: Some("Ensure HOME / USERPROFILE is set.".to_owned()),
            details: None,
        };
    }

    let registered: Vec<&'static str> = registrations
        .iter()
        .filter(|item| item.status == ClientConfigStatus::Registered)
        .map(|item| item.client)
        .collect();
    let errors: Vec<String> = registrations
        .iter()
        .filter_map(|item| match &item.status {
            ClientConfigStatus::Error(err) => Some(format!("{}: {err}", item.client)),
            _ => None,
        })
        .collect();

    let details = serde_json::json!({
        "registered": registered,
        "errors": errors,
    });

    if registered.is_empty() {
        return CheckReport {
            id: "mcp_clients",
            status: CheckStatus::Warn,
            summary: "No coding-agent MCP client has Proofline registered".to_owned(),
            remediation: Some(
                "Run `proofline agent install <claude-code|cursor|codex|gemini|kiro>` to register."
                    .to_owned(),
            ),
            details: Some(details),
        };
    }

    CheckReport {
        id: "mcp_clients",
        status: CheckStatus::Pass,
        summary: format!("Proofline MCP registered in: {}", registered.join(", ")),
        remediation: None,
        details: Some(details),
    }
}

fn write_text(report: &DoctorReport, out: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(
        out,
        "Proofline Doctor ({} mode)",
        if report.offline { "offline" } else { "online" }
    )?;
    for check in &report.checks {
        writeln!(
            out,
            "[{}] {}: {}",
            check.status.label(),
            check.id,
            check.summary
        )?;
        if let Some(remediation) = &check.remediation {
            writeln!(out, "       -> {remediation}")?;
        }
    }
    writeln!(
        out,
        "Summary: {} passed, {} warnings, {} failed, {} skipped",
        report.counts.pass, report.counts.warn, report.counts.fail, report.counts.skip
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_check_accepts_https_and_rejects_insecure_http() {
        let (ok_report, parsed) = check_origin("https://proofline.sh");
        assert_eq!(ok_report.status, CheckStatus::Pass);
        assert!(parsed.is_some());

        let (bad_report, parsed_bad) = check_origin("http://example.com");
        assert_eq!(bad_report.status, CheckStatus::Fail);
        assert!(parsed_bad.is_none());
        assert!(bad_report.remediation.is_some());
    }

    #[test]
    fn tls_ca_cert_check_validates_pem_and_missing_files() {
        let (default_report, ok) = check_tls_ca_cert(None, false);
        assert_eq!(default_report.status, CheckStatus::Pass);
        assert!(ok);

        let fixture = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca-cert.pem"
        ));
        let (pem_report, pem_ok) = check_tls_ca_cert(Some(fixture), false);
        assert_eq!(pem_report.status, CheckStatus::Pass);
        assert!(pem_ok);

        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.pem");
        let (missing_report, missing_ok) = check_tls_ca_cert(Some(&missing), false);
        assert_eq!(missing_report.status, CheckStatus::Fail);
        assert!(!missing_ok);
    }

    #[tokio::test]
    async fn credentials_check_never_exposes_token_and_warns_without_org() {
        let secret = "pl_secret_token_should_never_appear_in_output";
        let origin = Origin::parse("https://proofline.sh").unwrap();
        let (warn_report, cred_none) = check_credentials(
            Some(&origin),
            Some(SecretString::from(secret.to_owned())),
            None,
        )
        .await;
        assert_eq!(warn_report.status, CheckStatus::Warn);
        assert!(cred_none.is_none());
        let serialized_warn = serde_json::to_string(&warn_report).unwrap();
        assert!(!serialized_warn.contains(secret));

        let org = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
        let (pass_report, cred_some) = check_credentials(
            Some(&origin),
            Some(SecretString::from(secret.to_owned())),
            Some(org),
        )
        .await;
        assert_eq!(pass_report.status, CheckStatus::Pass);
        assert!(cred_some.is_some());
        let serialized_pass = serde_json::to_string(&pass_report).unwrap();
        assert!(!serialized_pass.contains(secret));
    }

    #[test]
    fn mcp_clients_check_detects_registered_cursor_config() {
        let dir = tempfile::tempdir().unwrap();
        let origin = Origin::parse("https://proofline.sh").unwrap();

        let warn_report = check_mcp_clients(Some(dir.path()), &origin);
        assert_eq!(warn_report.status, CheckStatus::Warn);

        let cursor_dir = dir.path().join(".cursor");
        std::fs::create_dir_all(&cursor_dir).unwrap();
        std::fs::write(
            cursor_dir.join("mcp.json"),
            r#"{"mcpServers":{"proofline":{"command":"/usr/local/bin/proofline","args":["--base-url","https://proofline.sh","mcp"]}}}"#,
        )
        .unwrap();

        let pass_report = check_mcp_clients(Some(dir.path()), &origin);
        assert_eq!(pass_report.status, CheckStatus::Pass);
        assert!(pass_report.summary.contains("Cursor"));
    }

    #[tokio::test]
    async fn git_hooks_check_detects_installed_and_missing_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(status.success());

        let missing = check_git_hooks(dir.path(), true).await;
        assert_eq!(missing.status, CheckStatus::Warn);

        let hooks_dir = dir.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        std::fs::write(
            hooks_dir.join("pre-commit"),
            "#!/bin/sh\n# Installed by `proofline hooks install`; `proofline hooks uninstall` removes it.\nexec proofline hook run pre-commit \"$@\"\n",
        )
        .unwrap();

        let installed = check_git_hooks(dir.path(), true).await;
        assert_eq!(installed.status, CheckStatus::Pass);
        assert!(installed.summary.contains("pre-commit"));
    }

    #[test]
    fn doctor_report_counts_and_ok_reflect_failures() {
        let report_ok = DoctorReport::from_checks(
            true,
            vec![
                CheckReport {
                    id: "a",
                    status: CheckStatus::Pass,
                    summary: "ok".to_owned(),
                    remediation: None,
                    details: None,
                },
                CheckReport {
                    id: "b",
                    status: CheckStatus::Warn,
                    summary: "warn".to_owned(),
                    remediation: None,
                    details: None,
                },
                CheckReport {
                    id: "c",
                    status: CheckStatus::Skip,
                    summary: "skip".to_owned(),
                    remediation: None,
                    details: None,
                },
            ],
        );
        assert!(report_ok.ok);
        assert_eq!(
            report_ok.counts,
            DoctorCounts {
                pass: 1,
                warn: 1,
                fail: 0,
                skip: 1
            }
        );

        let report_fail = DoctorReport::from_checks(
            false,
            vec![CheckReport {
                id: "x",
                status: CheckStatus::Fail,
                summary: "bad".to_owned(),
                remediation: Some("fix".to_owned()),
                details: None,
            }],
        );
        assert!(!report_fail.ok);
        assert_eq!(report_fail.counts.fail, 1);
    }
}
