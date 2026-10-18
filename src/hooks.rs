//! Git hooks that review a commit or a push as it leaves the checkout.
//! `hooks install` writes one small script per hook. Git runs it, and it calls
//! `hook run`, which reviews exactly what the commit or push adds and applies
//! the developer's exit policy. A review that did not complete is printed as
//! not reviewed, never as clean.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand, ValueEnum};
use secrecy::SecretString;
use tokio::io::AsyncReadExt as _;
use url::Url;
use uuid::Uuid;

use crate::api::{Api, Http};
use crate::git::{self, LocalChanges, LocalSelection};
use crate::model::{Finding, PatchReviewRequest, ReviewDetail, TriggerSource};
use crate::origin::Origin;
use crate::outcome::{self, Outcome};
use crate::render::location;
use crate::severity::Severity;
use crate::text::one_line;
use crate::{RepositoryArgs, Verdict, connect, connected_repository, preflight, read_review, say};

/// Identifies a script this CLI wrote. Uninstall removes a hook only when its
/// whole text is the script this version writes, so an edited hook stays.
const MARKER: &str =
    "# Installed by `proofline hooks install`; `proofline hooks uninstall` removes it.";
/// The most refs one push reviews; the rest print as not reviewed.
const MAX_PUSH_REFS: usize = 3;
const MAX_TIMEOUT_SECONDS: u64 = 1_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Hook {
    PreCommit,
    PrePush,
}

impl Hook {
    const ALL: [Self; 2] = [Self::PreCommit, Self::PrePush];

    const fn name(self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::PrePush => "pre-push",
        }
    }

    const fn action(self) -> &'static str {
        match self {
            Self::PreCommit => "commit",
            Self::PrePush => "push",
        }
    }

    const fn trigger_source(self) -> TriggerSource {
        match self {
            Self::PreCommit => TriggerSource::HookPreCommit,
            Self::PrePush => TriggerSource::HookPrePush,
        }
    }

    const fn default_timeout_seconds(self) -> u64 {
        match self {
            Self::PreCommit => 60,
            Self::PrePush => 300,
        }
    }

    /// The line a hook managed by another tool needs.
    fn line(self) -> String {
        format!("proofline hook run {} \"$@\"", self.name())
    }

    fn script(self) -> String {
        let (name, action) = (self.name(), self.action());
        format!(
            "#!/bin/sh\n\
             {MARKER}\n\
             if ! command -v proofline >/dev/null 2>&1; then\n\
             \x20 echo 'proofline is not on PATH, so Proofline did not review this {action}.' >&2\n\
             \x20 [ \"$(git config --get proofline.hook.{name}.onIncomplete)\" = block ] && exit 1\n\
             \x20 exit 0\n\
             fi\n\
             exec {}\n",
            self.line()
        )
    }
}

#[derive(Debug, Args)]
pub(crate) struct HooksArgs {
    #[command(subcommand)]
    action: HooksAction,
}

#[derive(Debug, Subcommand)]
enum HooksAction {
    /// Write hook scripts into this repository's hooks directory.
    Install(Selection),
    /// Remove the hook scripts `hooks install` wrote.
    Uninstall(Selection),
}

/// Which hooks to act on; neither flag means both.
#[derive(Debug, Args)]
struct Selection {
    #[arg(long)]
    pre_commit: bool,
    #[arg(long)]
    pre_push: bool,
}

impl Selection {
    fn hooks(&self) -> Vec<Hook> {
        Hook::ALL
            .into_iter()
            .filter(|hook| match hook {
                _ if !self.pre_commit && !self.pre_push => true,
                Hook::PreCommit => self.pre_commit,
                Hook::PrePush => self.pre_push,
            })
            .collect()
    }
}

#[derive(Debug, Args)]
pub(crate) struct HookArgs {
    #[command(subcommand)]
    action: HookAction,
}

#[derive(Debug, Subcommand)]
enum HookAction {
    /// Review what the commit or push adds and apply the hook's exit policy.
    Run {
        hook: Hook,
        /// The arguments Git passes to the hook.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

pub(crate) async fn manage(args: HooksArgs) -> anyhow::Result<()> {
    let here = Path::new(".");
    match args.action {
        HooksAction::Install(selection) => {
            // Husky, lefthook and shared hook directories own their scripts.
            if let Some(path) = git::config(here, "core.hooksPath").await? {
                for hook in selection.hooks() {
                    say(&format!(
                        "core.hooksPath is {}, so nothing was written. Add this line to its {} hook: {}",
                        one_line(&path),
                        hook.name(),
                        hook.line()
                    ));
                }
                return Ok(());
            }
            let dir = git::hooks_dir(here).await?;
            for hook in selection.hooks() {
                install(&dir, hook).await?;
            }
        }
        HooksAction::Uninstall(selection) => {
            let dir = git::hooks_dir(here).await?;
            for hook in selection.hooks() {
                uninstall(&dir, hook).await?;
            }
        }
    }
    Ok(())
}

async fn install(dir: &Path, hook: Hook) -> anyhow::Result<()> {
    let path = dir.join(hook.name());
    let script = hook.script();
    match tokio::fs::read(&path).await {
        Ok(existing) if existing == script.as_bytes() => say(&format!(
            "The {} hook at {} is already installed.",
            hook.name(),
            path.display()
        )),
        Ok(_) => say(&format!(
            "{} already exists, so it was left unchanged. Add this line to it: {}",
            path.display(),
            hook.line()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_executable(&path, &script).await?;
            say(&format!(
                "Installed the {} hook at {}.",
                hook.name(),
                path.display()
            ));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {}", path.display()));
        }
    }
    Ok(())
}

async fn write_executable(path: &Path, script: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let mut options = tokio::fs::OpenOptions::new();
    // Never replace a hook that appeared since it was read.
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o755);
    let mut file = options
        .open(path)
        .await
        .with_context(|| format!("could not create {}", path.display()))?;
    tokio::io::AsyncWriteExt::write_all(&mut file, script.as_bytes())
        .await
        .with_context(|| format!("could not write {}", path.display()))
}

async fn uninstall(dir: &Path, hook: Hook) -> anyhow::Result<()> {
    let path = dir.join(hook.name());
    match tokio::fs::read(&path).await {
        Ok(existing) if existing == hook.script().as_bytes() => {
            tokio::fs::remove_file(&path)
                .await
                .with_context(|| format!("could not remove {}", path.display()))?;
            say(&format!(
                "Removed the {} hook at {}.",
                hook.name(),
                path.display()
            ));
        }
        Ok(_) => say(&format!(
            "{} is not the script `proofline hooks install` writes, so it was left unchanged.",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => say(&format!(
            "No {} hook is installed at {}.",
            hook.name(),
            path.display()
        )),
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {}", path.display()));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Warn,
    Block,
}

/// The developer's choices for one hook, from `git config`.
#[derive(Debug)]
struct Settings {
    mode: Mode,
    /// The severity at or above which `block` refuses.
    fail_on: Severity,
    on_incomplete: Mode,
    timeout: Duration,
}

async fn settings(dir: &Path, hook: Hook) -> anyhow::Result<Settings> {
    let value = async |name: &str| {
        let key = format!("proofline.hook.{}.{name}", hook.name());
        git::config(dir, &key).await.map(|value| (key, value))
    };
    let mode = |(key, value): (String, Option<String>)| match value.as_deref() {
        None | Some("warn") => Ok(Mode::Warn),
        Some("block") => Ok(Mode::Block),
        Some(other) => bail!("{key} is {:?}; set it to warn or block", one_line(other)),
    };
    let (key_fail_on, fail_on) = value("failOn").await?;
    let fail_on = match fail_on {
        None => Severity::Serious,
        Some(raw) => Severity::parse(&raw).with_context(|| {
            format!(
                "{key_fail_on} is {:?}; set it to SERIOUS or WARNING",
                one_line(&raw)
            )
        })?,
    };
    let (key_timeout, timeout) = value("timeout").await?;
    let seconds = match timeout {
        None => hook.default_timeout_seconds(),
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds <= MAX_TIMEOUT_SECONDS)
            .with_context(|| {
                format!(
                    "{key_timeout} is {:?}; set it to a number of seconds up to {MAX_TIMEOUT_SECONDS}",
                    one_line(&raw)
                )
            })?,
    };
    Ok(Settings {
        mode: mode(value("mode").await?)?,
        fail_on,
        on_incomplete: mode(value("onIncomplete").await?)?,
        timeout: Duration::from_secs(seconds),
    })
}

/// One ref line of Git's pre-push input that a push creates or updates.
#[derive(Debug, PartialEq, Eq)]
struct PushedRef {
    local_ref: String,
    local_sha: String,
    remote_sha: String,
}

fn is_zero(sha: &str) -> bool {
    !sha.is_empty() && sha.bytes().all(|byte| byte == b'0')
}

/// The branches a push sends, from `<local ref> <local sha> <remote ref>
/// <remote sha>` lines. Deletions and tags carry no change to review.
fn pushed_refs(input: &str) -> anyhow::Result<Vec<PushedRef>> {
    let mut refs = Vec::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split(' ').collect();
        let [local_ref, local_sha, _, remote_sha] = fields.as_slice() else {
            bail!(
                "Git's pre-push input has a line Proofline cannot read: {:?}",
                one_line(line)
            );
        };
        if is_zero(local_sha) || local_ref.starts_with("refs/tags/") {
            continue;
        }
        refs.push(PushedRef {
            local_ref: (*local_ref).to_owned(),
            local_sha: (*local_sha).to_owned(),
            remote_sha: (*remote_sha).to_owned(),
        });
    }
    Ok(refs)
}

/// What one hook reviews: the staged patch, or one pushed branch.
#[derive(Debug)]
struct Subject {
    label: String,
    changes: Result<LocalChanges, git::GitError>,
}

/// What one subject came to.
#[derive(Debug)]
enum Report {
    /// The selection matches its base.
    Nothing,
    /// No review result, and why.
    Unreviewed(String),
    /// The review as last read; `state` is `None` while it runs.
    Read {
        review_id: Uuid,
        url: Url,
        detail: Box<ReviewDetail>,
        state: Option<Outcome>,
    },
}

/// The subjects to review, and how many pushed branches were left out.
async fn subjects(hook: Hook, here: &Path, remote: &str) -> anyhow::Result<(Vec<Subject>, usize)> {
    match hook {
        Hook::PreCommit => Ok((
            vec![Subject {
                label: "the staged changes".to_owned(),
                changes: git::local_changes(here, remote, LocalSelection::Staged).await,
            }],
            0,
        )),
        Hook::PrePush => {
            let mut input = String::new();
            tokio::io::stdin()
                .read_to_string(&mut input)
                .await
                .context("could not read Git's pre-push input")?;
            let pushed = pushed_refs(&input)?;
            let skipped = pushed.len().saturating_sub(MAX_PUSH_REFS);
            let mut subjects = Vec::new();
            for pushed in pushed.into_iter().take(MAX_PUSH_REFS) {
                let base = if is_zero(&pushed.remote_sha) {
                    git::new_branch_base(here, remote, &pushed.local_sha).await
                } else {
                    Ok(pushed.remote_sha)
                };
                let changes = match base {
                    Ok(base) => git::range_changes(here, &base, &pushed.local_sha).await,
                    Err(error) => Err(error),
                };
                subjects.push(Subject {
                    label: pushed
                        .local_ref
                        .strip_prefix("refs/heads/")
                        .unwrap_or(&pushed.local_ref)
                        .to_owned(),
                    changes,
                });
            }
            Ok((subjects, skipped))
        }
    }
}

pub(crate) async fn run(
    args: HookArgs,
    origin: Origin,
    token: Option<SecretString>,
    org: Option<Uuid>,
) -> anyhow::Result<Verdict> {
    let HookAction::Run { hook, args } = args.action;
    let action = hook.action();
    if std::env::var("PROOFLINE_HOOK").is_ok_and(|value| value == "off") {
        say(&format!(
            "PROOFLINE_HOOK=off, so Proofline did not review this {action}."
        ));
        return Ok(Verdict::Done);
    }
    let here = Path::new(".");
    let settings = settings(here, hook).await?;
    let deadline = tokio::time::Instant::now() + settings.timeout;
    // Git passes a pre-push hook the remote's name and URL; the URL names the
    // repository even when the push goes to a URL rather than a remote.
    let remote = args.first().map_or("origin", String::as_str);
    let repository = RepositoryArgs {
        repo: args.get(1).and_then(|url| git::full_name(url)),
        remote: remote.to_owned(),
    };
    let (subjects, skipped) = subjects(hook, here, remote).await?;
    let mut reports = Vec::new();
    let mut api: Option<Result<Api, String>> = None;
    for subject in subjects {
        let report = match ready(subject.changes) {
            Err(report) => report,
            Ok(changes) => {
                // Connect once, and only when something needs a review.
                let connection = match api.take() {
                    Some(connection) => connection,
                    None => match Http::new(origin.clone()) {
                        Ok(http) => connect(http, token.clone(), org)
                            .await
                            .map_err(|error| format!("{error:#}")),
                        Err(error) => Err(error.to_string()),
                    },
                };
                let report = match &connection {
                    Ok(api) => request(api, &repository, hook, changes, deadline).await,
                    Err(error) => Report::Unreviewed(error.clone()),
                };
                api = Some(connection);
                report
            }
        };
        reports.push((subject.label, report));
    }
    Ok(conclude(hook, &settings, &reports, skipped))
}

/// The changes, once they are known to need a review and pass the local
/// refusals that run before any upload.
fn ready(changes: Result<LocalChanges, git::GitError>) -> Result<LocalChanges, Report> {
    let changes = changes.map_err(|error| Report::Unreviewed(error.to_string()))?;
    if changes.files() == 0 {
        return Err(Report::Nothing);
    }
    preflight::check(&changes, &[]).map_err(|error| Report::Unreviewed(error.to_string()))?;
    Ok(changes)
}

async fn request(
    api: &Api,
    repository: &RepositoryArgs,
    hook: Hook,
    changes: LocalChanges,
    deadline: tokio::time::Instant,
) -> Report {
    let requested = async {
        let (_, repository_id) = connected_repository(api, repository).await?;
        let request = PatchReviewRequest {
            base_commit_sha: changes.base_commit_sha,
            patch: changes.patch,
            trigger_source: Some(hook.trigger_source()),
            verify_finding_ids: Vec::new(),
        };
        let requested = api.request_patch_review(repository_id, &request).await?;
        let (_, detail, state) =
            read_review(api, requested.review_id, Some(deadline), false).await?;
        anyhow::Ok((requested.review_id, detail, state))
    };
    match requested.await {
        Ok((review_id, detail, state)) => Report::Read {
            review_id,
            url: api.review_url(review_id),
            detail: Box::new(detail),
            state,
        },
        Err(error) => Report::Unreviewed(format!("{error:#}")),
    }
}

/// The first sentence of model text, on one line.
fn first_sentence(text: &str) -> String {
    let line = one_line(text);
    line.split_inclusive(". ")
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_owned()
}

fn print_findings(findings: &[Finding]) {
    for finding in findings {
        say(&format!(
            "    {:<8} {}  {}",
            one_line(&finding.severity),
            location(finding).first().map_or("", String::as_str),
            first_sentence(&finding.claim)
        ));
    }
}

/// Prints each report and applies the exit policy: `block` refuses a finding
/// at or above `failOn`, and `onIncomplete=block` refuses anything short of
/// a complete review. As in `ci review`, a CODE finding counts only in a
/// complete review and while it is not `RESOLVED`. No answer from a model
/// sets the exit code.
fn conclude(
    hook: Hook,
    settings: &Settings,
    reports: &[(String, Report)],
    skipped: usize,
) -> Verdict {
    let action = hook.action();
    let mut gap = skipped > 0;
    let mut failing = false;
    for (label, report) in reports {
        match report {
            Report::Nothing => say(&format!("Proofline: nothing to review in {label}.")),
            Report::Unreviewed(reason) => {
                gap = true;
                say(&format!(
                    "Proofline could not review {label}: {}",
                    one_line(reason)
                ));
            }
            Report::Read {
                review_id,
                url,
                detail,
                state,
            } => {
                let complete = *state == Some(Outcome::Completed);
                gap |= !complete;
                match state {
                    None => say(&format!(
                        "Review of {label} still running: {url}. Read it later with `proofline findings --review {review_id}`."
                    )),
                    Some(state) => say(&format!(
                        "Proofline reviewed {label}: {} {url}",
                        state.as_str()
                    )),
                }
                if let Some(code) = outcome::code_assessment(detail) {
                    say(&match outcome::code_gap(code) {
                        Some(reason) => format!(
                            "  Code-only: {} (incomplete: {})",
                            code.status.as_str(),
                            one_line(reason)
                        ),
                        None if code.findings.is_empty() && !complete => {
                            "  Code-only: COMPLETED".to_owned()
                        }
                        None if code.findings.is_empty() => {
                            "  Code-only: COMPLETED, no findings".to_owned()
                        }
                        None => format!("  Code-only: COMPLETED, {} findings", code.findings.len()),
                    });
                    print_findings(&code.findings);
                    failing |= complete && outcome::code_reaches(code, settings.fail_on);
                } else if outcome::code_unavailable(detail) {
                    say("  Code-only: incomplete (CODE_ASSESSMENT_UNAVAILABLE)");
                }
                for assessment in &detail.assessments {
                    let name = one_line(&assessment.environment_display_name);
                    say(&match outcome::gap(assessment) {
                        Some(reasons) => format!(
                            "  {name}: {} (incomplete: {})",
                            one_line(&assessment.status),
                            one_line(&reasons.join(", "))
                        ),
                        // One finished environment says nothing about a review
                        // that is still running, failed or lacks an assessment.
                        None if assessment.findings.is_empty() && !complete => {
                            format!("  {name}: COMPLETED")
                        }
                        None if assessment.findings.is_empty() => {
                            format!("  {name}: COMPLETED, no findings")
                        }
                        None => format!(
                            "  {name}: COMPLETED, {} findings",
                            assessment.findings.len()
                        ),
                    });
                    print_findings(&assessment.findings);
                    failing |= assessment
                        .findings
                        .iter()
                        .any(|finding| settings.fail_on.reached_by(&finding.severity));
                }
            }
        }
    }
    if skipped > 0 {
        say(&format!(
            "Proofline reviews at most {MAX_PUSH_REFS} branches per push, so {skipped} more were not reviewed."
        ));
    }
    let mut reasons = Vec::new();
    if settings.mode == Mode::Block && failing {
        reasons.push(format!(
            "a finding at or above {}",
            settings.fail_on.as_str()
        ));
    }
    if settings.on_incomplete == Mode::Block && gap {
        reasons.push("no complete review".to_owned());
    }
    if !reasons.is_empty() {
        say(&format!(
            "Proofline blocked this {action}: {}. Bypass it once with `git {action} --no-verify`.",
            reasons.join(" and ")
        ));
        return Verdict::Blocked;
    }
    if gap {
        say(&format!("The {action} proceeds without a complete review."));
    }
    Verdict::Done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_reviews_created_and_updated_branches_only() {
        let zero = "0".repeat(40);
        let (a, b) = ("a".repeat(40), "b".repeat(40));
        let input = format!(
            "refs/heads/new {a} refs/heads/new {zero}\n\
             refs/heads/main {b} refs/heads/main {a}\n\
             (delete) {zero} refs/heads/old {b}\n\
             refs/tags/v1 {a} refs/tags/v1 {zero}\n"
        );
        assert_eq!(
            pushed_refs(&input).unwrap(),
            vec![
                PushedRef {
                    local_ref: "refs/heads/new".to_owned(),
                    local_sha: a.clone(),
                    remote_sha: zero,
                },
                PushedRef {
                    local_ref: "refs/heads/main".to_owned(),
                    local_sha: b,
                    remote_sha: a,
                },
            ]
        );
        assert!(pushed_refs("refs/heads/main abc\n").is_err());
    }
}
