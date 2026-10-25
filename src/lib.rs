//! The `proofline` command-line client. It signs in through the browser, keeps
//! its token in the operating system keychain, and reads and requests reviews
//! through the public review API. It shares no code with the server crate.

mod agent;
pub mod api;
pub mod credentials;
pub mod device;
pub mod git;
mod github_actions;
mod hooks;
mod mcp;
pub mod model;
pub mod origin;
pub mod outcome;
mod preflight;
pub mod render;
mod result;
mod sarif;
mod severity;
pub mod text;
pub mod update;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;

use crate::api::{Api, ApiError, Http};
use crate::credentials::{Credential, Source};
mod tools;

use crate::model::{
    CodeAssessment, CommitReviewRequest, FileReviewRequest, OpenItems, PatchReviewRequest,
    ReviewDetail, ReviewSummary,
};
use crate::origin::{DEFAULT_ORIGIN, Origin};
use crate::outcome::Outcome;
use crate::severity::Severity;

const FIRST_POLL_SECONDS: u64 = 5;
const LONGEST_POLL_SECONDS: u64 = 60;
const SEARCH_PAGES: usize = 10;
/// What `findings`, `review` and `stop` need. The approval page shows each one
/// and can narrow them.
const DEFAULT_SCOPES: [&str; 3] = ["reviews:read", "findings:read", "reviews:request"];

#[derive(Debug, Parser)]
#[command(
    name = "proofline",
    version,
    about = "Read, request and stop Proofline reviews from a terminal"
)]
pub struct Cli {
    /// Proofline console origin.
    #[arg(long, global = true, env = "PROOFLINE_BASE_URL", default_value = DEFAULT_ORIGIN)]
    base_url: String,

    /// Organization ID. Required for a token from the environment; a browser sign-in
    /// already names its organization. MCP uses the token's server-side tenant;
    /// an environment organization ID is local metadata, not a tenant assertion.
    #[arg(long, global = true, env = "PROOFLINE_ORGANIZATION_ID")]
    org: Option<Uuid>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Rerun the original immutable review subject.
    Rerun(tools::RerunArgs),
    /// List the recorded runs of a pull request.
    History(tools::HistoryArgs),
    /// Read the repository review guidance as JSON.
    Guidance(RepositoryArgs),
    /// Read a bounded, untrusted finding fix prompt as JSON.
    FixPrompt { finding_id: Uuid },
    /// Export one page of analytics as CSV or NDJSON.
    Export(tools::ExportArgs),
    /// Install the newest official release over this installer-managed binary.
    Update,
    #[command(name = "__update-check", hide = true)]
    UpdateCheck,
    /// Configure a coding agent to use the existing local MCP bridge.
    Agent(agent::AgentArgs),
    /// Sign in through the browser and keep the token in the OS keychain.
    Login(LoginArgs),
    /// Remove the stored token from the OS keychain.
    Logout,
    /// Show which organization and token the CLI uses.
    Status,
    /// Review the checkout's local changes, pushed commits, or an open pull
    /// request's current head.
    Review(ReviewArgs),
    /// Stop your own pending or running local patch, pushed-commit or named-file review.
    Stop(StopArgs),
    /// Show the findings of the latest review of a commit or pull request.
    Findings(FindingsArgs),
    /// Forward a coding agent's stdio messages to this console's MCP server.
    Mcp,
    /// Commands for a CI job.
    #[command(subcommand)]
    Ci(CiCommand),
    /// Install or remove Git hooks that review each commit and push.
    Hooks(hooks::HooksArgs),
    /// Run an installed Git hook. Git calls this from the hook script.
    Hook(hooks::HookArgs),
}

#[derive(Debug, Subcommand)]
enum CiCommand {
    /// Wait for the pull-request review of the commit under test and report it.
    ///
    /// The job authenticates with `PROOFLINE_TOKEN`. Without it, a GitHub Actions
    /// job that grants `id-token: write` exchanges its OIDC token for a one-hour
    /// token that reads its repository's reviews, and needs no organization ID.
    /// Such a job on a `pull_request` event that finds no review after two
    /// minutes asks once for a withheld review of its head.
    Review(CiReviewArgs),
}

#[derive(Debug, Args)]
struct CiReviewArgs {
    /// Full commit SHA under test. Defaults to `COMMIT_SHA`, then the pull
    /// request's head on a GitHub Actions pull-request event, then `GITHUB_SHA`.
    #[arg(long, value_name = "SHA")]
    commit: Option<String>,
    /// Also write the review as SARIF 2.1.0 to this file.
    #[arg(long, value_name = "FILE")]
    sarif: Option<PathBuf>,
    /// Print JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Minutes to wait for the review to appear and finish.
    #[arg(long, default_value_t = 30, value_name = "MINUTES")]
    timeout: u64,
    /// Exit 3 when the completed review has an open finding at or above this
    /// severity. A finding that is dismissed or accepted as a risk does not
    /// count. Without this flag, findings never fail the job. An incomplete
    /// review exits 2 whatever it found.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<Severity>,
    #[command(flatten)]
    repository: RepositoryArgs,
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Review API scope to ask for; repeat for several. The approval page can
    /// narrow them.
    #[arg(long = "scope", value_name = "SCOPE", default_values_t = DEFAULT_SCOPES.map(str::to_owned))]
    scopes: Vec<String>,
    /// Print the approval address instead of opening a browser.
    #[arg(long)]
    no_browser: bool,
}

#[derive(Debug, Args)]
struct RepositoryArgs {
    /// GitHub repository as owner/name. Defaults to the checkout's remote.
    #[arg(long, value_name = "OWNER/NAME")]
    repo: Option<String>,
    /// Git remote that names the repository.
    #[arg(long, default_value = "origin")]
    remote: String,
}

#[derive(Debug, Args)]
struct OutputArgs {
    /// Print JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Minutes to wait for a running review.
    #[arg(long, default_value_t = 20, value_name = "MINUTES")]
    timeout: u64,
}

#[derive(Debug, Args)]
struct StopArgs {
    /// The review ID returned by `review --no-wait`.
    review_id: Uuid,
    /// Print the server's stop acknowledgment as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LocalSelectionArgs {
    /// Review the original index against the base, excluding unstaged changes.
    #[arg(long, conflicts_with_all = ["pr", "include_untracked"])]
    staged: bool,
    /// Add untracked files that Git does not ignore to the working-tree review.
    #[arg(long, conflicts_with_all = ["pr", "staged"])]
    include_untracked: bool,
}

#[derive(Debug, Args)]
struct ReviewArgs {
    /// Print the JSON result schema without requesting or reading a review.
    #[arg(long)]
    schema: bool,
    /// Pull request number. Without it, the checkout's local changes are
    /// reviewed against the commit they build on.
    #[arg(long, value_name = "NUMBER")]
    pr: Option<u64>,
    #[command(flatten)]
    local_selection: LocalSelectionArgs,
    /// Review the change this pushed commit makes against its first parent.
    /// The name is resolved once in the checkout; GitHub must have both commits.
    /// With --files, review complete selected files at that commit instead.
    #[arg(
        long,
        value_name = "REVISION",
        conflicts_with_all = ["pr", "range", "staged", "include_untracked", "allow_path"]
    )]
    commit: Option<String>,
    /// Review the complete contents of up to twenty tracked files at --commit.
    #[arg(long, value_name = "PATH", num_args = 1..=20, requires = "commit",
        conflicts_with_all = ["pr", "range", "staged", "include_untracked", "allow_path"])]
    files: Vec<String>,
    /// Review the change from BASE to HEAD, both pushed, BASE an ancestor of
    /// HEAD. The names are resolved once in the checkout.
    #[arg(
        long,
        value_name = "BASE..HEAD",
        conflicts_with_all = ["pr", "staged", "include_untracked", "allow_path"]
    )]
    range: Option<String>,
    /// Re-verify these open findings of one pull request against the local
    /// changes, and print each one's outcome. The outcome is local: the pull
    /// request's findings are unchanged. Needs an API token.
    #[arg(
        long,
        value_name = "FINDING_ID",
        num_args = 1..,
        conflicts_with_all = ["pr", "commit", "range"]
    )]
    verify: Vec<Uuid>,
    /// Request a fresh full review of the pull request after settlement. An
    /// active review is reused with its recorded scope unchanged.
    #[arg(long, requires = "pr")]
    full: bool,
    /// Return once the review is requested instead of waiting for its result.
    #[arg(long)]
    no_wait: bool,
    /// Include secret-shaped patch content from this exact repository-relative
    /// path. Repeat for more paths; each override applies only to local review.
    #[arg(long, value_name = "PATH", conflicts_with = "pr")]
    allow_path: Vec<String>,
    #[command(flatten)]
    repository: RepositoryArgs,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
#[group(multiple = false)]
struct Selector {
    /// Latest review of this pull request.
    #[arg(long, value_name = "NUMBER")]
    pr: Option<u64>,
    /// Latest review whose head is exactly this pushed commit. Defaults to
    /// the checkout's HEAD.
    #[arg(long, value_name = "SHA")]
    head: Option<String>,
    /// This review.
    #[arg(long, value_name = "ID")]
    review: Option<Uuid>,
}

#[derive(Debug, Args)]
struct FindingsArgs {
    #[command(flatten)]
    selector: Selector,
    /// Wait for a running review to finish.
    #[arg(long)]
    wait: bool,
    /// Export this retained pull-request review as SARIF 2.1.0.
    #[arg(long, requires = "review", conflicts_with_all = ["json", "pr", "head"])]
    sarif: bool,
    #[command(flatten)]
    repository: RepositoryArgs,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

impl OutputFormat {
    const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

/// How a command that shows a review ended. Anything short of a complete
/// result is not success, so a script cannot read a gap as a clean review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Done,
    NotComplete,
    /// Proofline did not answer: it was unreachable, failed on its side, or
    /// had no finished review before the deadline.
    Unavailable,
    /// A complete review has an open finding at or above `ci review --fail-on`.
    ThresholdReached,
    /// A Git hook's exit policy refuses the commit or push.
    Blocked,
}

/// Runs one command. `token` is `PROOFLINE_TOKEN`, read by the caller.
pub async fn run(cli: Cli, token: Option<SecretString>) -> anyhow::Result<Verdict> {
    if let Command::Review(args) = &cli.command
        && args.schema
    {
        let document = result::schema()?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", serde_json::to_string_pretty(&document)?)?;
        return Ok(Verdict::Done);
    }
    match &cli.command {
        Command::Update => return update::install().await.map(|()| Verdict::Done),
        Command::UpdateCheck => {
            update::check().await;
            return Ok(Verdict::Done);
        }
        _ => {}
    }
    let origin = Origin::parse(&cli.base_url)?;
    match cli.command {
        Command::Update => update::install().await.map(|()| Verdict::Done),
        Command::UpdateCheck => {
            update::check().await;
            Ok(Verdict::Done)
        }
        Command::Agent(args) => agent::run(args, origin).await.map(|()| Verdict::Done),
        Command::Login(args) => {
            let http = Http::new(origin)?;
            login(&http, &args, cli.org, token.is_some())
                .await
                .map(|()| Verdict::Done)
        }
        Command::Logout => logout(&origin, token.is_some())
            .await
            .map(|()| Verdict::Done),
        Command::Status => status(Http::new(origin)?, token, cli.org)
            .await
            .map(|()| Verdict::Done),
        Command::Review(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            review(&api, &args).await
        }
        Command::Stop(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            let (raw, stopped) = api.stop_review(args.review_id).await?;
            let mut stdout = std::io::stdout().lock();
            if args.json {
                writeln!(stdout, "{}", serde_json::to_string(&raw)?)?;
            } else {
                writeln!(stdout, "Stopped review {}.", stopped.review_id)?;
            }
            Ok(Verdict::Done)
        }
        Command::Rerun(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::rerun(&api, &args).await
        }
        Command::History(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            let name = repository_name(&args.repository).await?;
            tools::json(&api.history(&name, args.pr).await?)
        }
        Command::Guidance(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            let (_, repository) = connected_repository(&api, &args).await?;
            tools::json(&api.guidance(repository).await?)
        }
        Command::FixPrompt { finding_id } => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::json(&api.fix_prompt(finding_id).await?)
        }
        Command::Export(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::export(&api, &args).await
        }
        Command::Findings(args) => {
            if let Some(head) = &args.selector.head {
                git::commit_sha(head)?;
            }
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            findings(&api, &args).await
        }
        Command::Mcp => {
            let http = Http::new(origin)?;
            let credential = credentials::load(http.origin(), token, cli.org).await?;
            mcp::run(&http, &credential.token).await?;
            Ok(Verdict::Done)
        }
        Command::Ci(CiCommand::Review(args)) => {
            let commit = ci_commit(args.commit.as_deref())?;
            let http = Http::new(origin)?;
            let event = std::env::var(github_actions::EVENT_NAME).unwrap_or_default();
            let issuer = github_actions::Issuer::from_environment();
            let result = ci_job(http, token, issuer, &event, cli.org, &args, &commit).await;
            match result {
                Err(error) if unavailable(&error) => {
                    say(&format!("proofline: {error:#}"));
                    Ok(Verdict::Unavailable)
                }
                result => result,
            }
        }
        Command::Hooks(args) => hooks::manage(args).await.map(|()| Verdict::Done),
        Command::Hook(args) => hooks::run(args, origin, token, cli.org).await,
    }
}

async fn connect(
    http: Http,
    token: Option<SecretString>,
    org: Option<Uuid>,
) -> anyhow::Result<Api> {
    let credential = credentials::load(http.origin(), token, org).await?;
    Ok(Api::new(http, credential.token, credential.organization_id))
}

fn say(line: &str) {
    // Progress goes to standard error so standard output stays the result.
    let mut stderr = std::io::stderr().lock();
    if writeln!(stderr, "{line}").is_err() {
        // A closed standard error leaves nothing to report the failure to.
    }
}

async fn login(
    http: &Http,
    args: &LoginArgs,
    org: Option<Uuid>,
    environment: bool,
) -> anyhow::Result<()> {
    if environment {
        bail!("PROOFLINE_TOKEN is set, and it takes precedence over a sign-in; unset it first");
    }
    // Refuse before the person approves anything if the token cannot be kept.
    credentials::probe(http.origin())
        .await
        .context("could not read the OS keychain, so a sign-in could not be kept")?;
    let challenge = device::start(http, &args.scopes).await?;
    let code = challenge.user_code.expose_secret();
    say(&format!("Your sign-in code is {code}."));
    let opened = !args.no_browser
        && challenge
            .verification_uri_complete
            .as_ref()
            .map_or(challenge.verification_uri.as_str(), |complete| {
                complete.expose_secret()
            })
            .parse::<url::Url>()
            .is_ok_and(|address| webbrowser::open(address.as_str()).is_ok());
    if opened {
        say(&format!(
            "Approve it in the browser window that opened. If none did, open {} and enter the code.",
            challenge.verification_uri
        ));
    } else {
        say(&format!(
            "Open {} in a browser and enter the code.",
            challenge.verification_uri
        ));
    }
    say("Choose the organization, scopes and repositories there. Waiting for approval...");
    let credential = device::finish(http, &challenge, org).await?;
    credentials::store(http.origin(), &credential).await?;
    say(&format!(
        "Signed in to {} for organization {}{}.",
        http.origin(),
        credential.organization_id,
        credential
            .scope
            .as_deref()
            .map(|scope| format!(" with {}", text::one_line(scope)))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn logout(origin: &Origin, environment: bool) -> anyhow::Result<()> {
    if credentials::remove(origin).await? {
        say(&format!(
            "Removed the {origin} token from this computer. It stays valid until it expires unless you revoke it under Personal tokens in the console."
        ));
    } else {
        say(&format!("No {origin} token is stored on this computer."));
    }
    if environment {
        say("PROOFLINE_TOKEN is still set in this shell.");
    }
    Ok(())
}

async fn status(http: Http, token: Option<SecretString>, org: Option<Uuid>) -> anyhow::Result<()> {
    let Credential {
        token,
        organization_id,
        scope,
        expires_at,
        source,
    } = credentials::load(http.origin(), token, org).await?;
    let origin = http.origin().clone();
    let mut lines = vec![
        format!("console: {origin}"),
        format!("organization: {organization_id}"),
        format!(
            "token: {}",
            match source {
                Source::Environment => "PROOFLINE_TOKEN",
                Source::Keychain => "OS keychain",
            }
        ),
    ];
    if let Some(scope) = scope {
        lines.push(format!("scopes: {}", text::one_line(&scope)));
    }
    if let Some(expires_at) = expires_at {
        let left = expires_at.saturating_sub(device::now());
        lines.push(if left == 0 {
            "expires: expired; run `proofline login`".to_owned()
        } else {
            format!("expires: in {} hours", left.div_ceil(3600))
        });
    }
    let api = Api::new(http, token, organization_id);
    let result = api.reviews(None, None, None).await;
    lines.push(match &result {
        Ok(_) => "server: accepted the token".to_owned(),
        Err(error) if error.status() == Some(401) => {
            "server: the token is expired, revoked or malformed; run `proofline login`".to_owned()
        }
        Err(error) => format!("server: {error}"),
    });
    writeln!(std::io::stdout().lock(), "{}", lines.join("\n"))?;
    result?;
    Ok(())
}

async fn repository_name(args: &RepositoryArgs) -> anyhow::Result<String> {
    match &args.repo {
        Some(name) => Ok(name.clone()),
        None => Ok(git::repository(&args.remote).await?),
    }
}

/// The one ID among `candidates` whose name is `name`, ignoring case. A name
/// shared by two IDs is refused rather than guessed.
fn unique(
    api: &Api,
    name: &str,
    candidates: impl Iterator<Item = (Uuid, String)>,
    absent: impl FnOnce() -> anyhow::Error,
) -> anyhow::Result<Uuid> {
    let mut found = candidates.filter(|(_, candidate)| candidate.eq_ignore_ascii_case(name));
    match (found.next(), found.next()) {
        (Some((id, _)), None) => Ok(id),
        (None, _) => Err(absent()),
        (Some(_), Some(_)) => bail!(
            "{} lists more than one repository named {name}, so the CLI cannot tell which one to use",
            api.origin()
        ),
    }
}

/// A connected repository, for requesting a review: it need not have one yet.
async fn connected_repository(api: &Api, args: &RepositoryArgs) -> anyhow::Result<(String, Uuid)> {
    let name = repository_name(args).await?;
    let names = api.repository_names().await?;
    let candidates = names
        .repositories
        .into_iter()
        .map(|repository| (repository.id, repository.full_name));
    let id = unique(api, &name, candidates, || {
        anyhow::anyhow!(
            "{name} is not a repository in organization {} that this token can read; check the repository name and the token's repositories",
            api.organization_id()
        )
    })?;
    Ok((name, id))
}

/// A repository with reviews the token can read, for finding one of them. A
/// repository that has since left the installation keeps its reviews, so this
/// reads the review collection's repositories, not the connected ones.
async fn reviewed_repository(api: &Api, args: &RepositoryArgs) -> anyhow::Result<(String, Uuid)> {
    let name = repository_name(args).await?;
    let page = api.reviews(None, None, None).await?;
    let candidates = page
        .filters
        .repositories
        .into_iter()
        .map(|choice| (choice.id, choice.name));
    let id = unique(api, &name, candidates, || {
        anyhow::anyhow!(
            "{name} has no reviews in organization {} that this token can read; check the repository name and the token's repositories",
            api.organization_id()
        )
    })?;
    Ok((name, id))
}

/// The newest review in `repository` that `matches`, searching with `search`.
async fn latest(
    api: &Api,
    repository: Uuid,
    search: &str,
    matches: impl Fn(&ReviewSummary) -> bool,
) -> anyhow::Result<Option<Uuid>> {
    let mut cursor: Option<String> = None;
    for _ in 0..SEARCH_PAGES {
        let page = api
            .reviews(Some(repository), Some(search), cursor.as_deref())
            .await?;
        if let Some(found) = page.items.iter().find(|item| matches(item)) {
            return Ok(Some(found.id));
        }
        match page.next_cursor {
            Some(next) if cursor.as_ref() != Some(&next) => cursor = Some(next),
            _ => return Ok(None),
        }
    }
    Ok(None)
}

async fn review(api: &Api, args: &ReviewArgs) -> anyhow::Result<Verdict> {
    let Some(number) = args.pr else {
        if !args.files.is_empty() {
            return review_files(api, args).await;
        }
        if args.commit.is_some() || args.range.is_some() {
            return review_pushed(api, args).await;
        }
        return review_local(api, args).await;
    };
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let request = if args.full {
        api.request_full_review(repository_id, number).await
    } else {
        api.request_review(repository_id, number).await
    };
    let requested = match request {
        Ok(requested) => requested,
        Err(error) if error.status() == Some(403) => {
            return Err(anyhow::Error::new(error).context(
                "this sign-in cannot request reviews; run `proofline login` and keep the reviews:request permission",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    say(&format!(
        "{} review run {} of {name} #{}{}.",
        match (requested.existing, args.full) {
            (true, _) => "Found the existing",
            (false, true) => "Requested a full",
            (false, false) => "Requested",
        },
        requested.run_number,
        number,
        if requested.automatic_reviews_paused {
            "; automatic reviews are paused for this organization"
        } else {
            ""
        }
    ));
    finish(api, requested.review_id, args).await
}

/// Reviews the checkout's local changes against the commit they build on.
/// Nothing is pushed: GitHub needs only the base commit.
async fn review_local(api: &Api, args: &ReviewArgs) -> anyhow::Result<Verdict> {
    let selection = if args.local_selection.staged {
        git::LocalSelection::Staged
    } else if args.local_selection.include_untracked {
        git::LocalSelection::IncludeUntracked
    } else {
        git::LocalSelection::Tracked
    };
    let changes = git::local_changes(
        std::path::Path::new("."),
        &args.repository.remote,
        selection,
    )
    .await?;
    let files = changes.files();
    if files == 0 && !args.verify.is_empty() {
        bail!(
            "nothing to re-verify against: the selected local changes match {}; --verify re-verifies findings against uncommitted changes",
            changes.base_commit_sha
        );
    }
    if files == 0 {
        say(&format!(
            "Nothing to review: the selected local changes match {}.",
            changes.base_commit_sha
        ));
        return Ok(Verdict::Done);
    }
    preflight::check(&changes, &args.allow_path)?;
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let request = PatchReviewRequest {
        base_commit_sha: changes.base_commit_sha,
        patch: changes.patch,
        trigger_source: None,
        verify_finding_ids: args.verify.clone(),
    };
    let requested = api.request_patch_review(repository_id, &request).await?;
    say(&format!(
        "{} review of {files} changed {} in {name} on {}.",
        if requested.existing {
            "Found the existing"
        } else {
            "Requested a"
        },
        if files == 1 { "file" } else { "files" },
        request.base_commit_sha
    ));
    for verifying in &requested.verify {
        say(&format!(
            "Re-verifying finding {} against the local changes (request {} of 3).",
            verifying.finding_id, verifying.iteration
        ));
    }
    finish(api, requested.review_id, args).await
}

async fn review_files(api: &Api, args: &ReviewArgs) -> anyhow::Result<Verdict> {
    let revision = args
        .commit
        .as_deref()
        .context("--files requires --commit")?;
    let (commit_sha, paths) =
        git::named_files(std::path::Path::new("."), revision, &args.files).await?;
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let request = FileReviewRequest { commit_sha, paths };
    let requested = api.request_file_review(repository_id, &request).await?;
    say(&format!(
        "{} whole-file review of {} selected files in {name} at {}.",
        if requested.existing {
            "Found the existing"
        } else {
            "Requested a"
        },
        request.paths.len(),
        request.commit_sha
    ));
    finish(api, requested.review_id, args).await
}

/// Reviews pushed commits: one commit against its parent, or a range. The
/// names are resolved to exact commits once, here; nothing leaves the
/// machine but the two SHAs, because GitHub already has the code.
async fn review_pushed(api: &Api, args: &ReviewArgs) -> anyhow::Result<Verdict> {
    let checkout = std::path::Path::new(".");
    let change = match (&args.commit, &args.range) {
        (Some(revision), _) => git::pushed_commit(checkout, revision).await?,
        (None, Some(range)) => git::pushed_range(checkout, range).await?,
        (None, None) => bail!("name the pushed commits with --commit or --range"),
    };
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let request = CommitReviewRequest {
        base_commit_sha: change.base_commit_sha,
        head_commit_sha: change.head_commit_sha,
    };
    let requested = api.request_commit_review(repository_id, &request).await?;
    say(&format!(
        "{} review of {name} {}..{}.",
        if requested.existing {
            "Found the existing"
        } else {
            "Requested a"
        },
        request.base_commit_sha,
        request.head_commit_sha
    ));
    finish(api, requested.review_id, args).await
}

/// Prints the requested review's link, or waits for it and prints its result.
async fn finish(api: &Api, review_id: Uuid, args: &ReviewArgs) -> anyhow::Result<Verdict> {
    if args.no_wait {
        let mut stdout = std::io::stdout().lock();
        let url = api.review_url(review_id);
        if args.output.json {
            let acknowledgment = serde_json::json!({
                "review_id": review_id,
                "review_url": url.as_str(),
            });
            writeln!(stdout, "{}", serde_json::to_string_pretty(&acknowledgment)?)?;
        } else {
            writeln!(stdout, "{url}")?;
        }
        return Ok(Verdict::Done);
    }
    show(
        api,
        review_id,
        true,
        &args.output,
        OutputFormat::from_json(args.output.json),
    )
    .await
}

async fn findings(api: &Api, args: &FindingsArgs) -> anyhow::Result<Verdict> {
    let review_id = match (&args.selector.review, args.selector.pr) {
        (Some(id), _) => *id,
        (None, Some(number)) => {
            let (name, repository_id) = reviewed_repository(api, &args.repository).await?;
            latest(api, repository_id, &number.to_string(), |item| {
                item.kind == "PULL_REQUEST"
                    && item.pull_request_number == i64::try_from(number).ok()
            })
            .await?
            .with_context(|| format!("{name} #{number} has no review"))?
        }
        (None, None) => {
            let sha = match &args.selector.head {
                Some(raw) => git::commit_sha(raw)?,
                None => git::head().await?,
            };
            let (name, repository_id) = reviewed_repository(api, &args.repository).await?;
            latest(api, repository_id, &sha, |item| item.head_commit_sha.as_deref() == Some(sha.as_str()))
                .await?
                .with_context(|| format!("no review of {name} has head commit {sha}; push it and open a pull request, or name one with --pr"))?
        }
    };
    let format = if args.sarif {
        OutputFormat::Sarif
    } else {
        OutputFormat::from_json(args.output.json)
    };
    show(api, review_id, args.wait, &args.output, format).await
}

#[derive(Debug, thiserror::Error)]
#[error("--timeout {minutes} minutes is too large to wait; choose a shorter timeout")]
struct PollTimeoutTooLarge {
    minutes: u64,
}

fn poll_deadline(minutes: u64) -> Result<tokio::time::Instant, PollTimeoutTooLarge> {
    let seconds = minutes
        .checked_mul(60)
        .ok_or(PollTimeoutTooLarge { minutes })?;
    tokio::time::Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .ok_or(PollTimeoutTooLarge { minutes })
}

/// Reads the review, polling until it finishes or `deadline` passes. Without
/// a deadline it reads once.
async fn read_review(
    api: &Api,
    review_id: Uuid,
    deadline: Option<tokio::time::Instant>,
    sarif: bool,
) -> anyhow::Result<(serde_json::Value, ReviewDetail, Option<Outcome>)> {
    let mut delay = FIRST_POLL_SECONDS;
    loop {
        let (raw, detail) = api.review(review_id).await?;
        if sarif {
            sarif::validate_subject(&detail, review_id)?;
        }
        let state = outcome::terminal(&detail);
        let Some(deadline) = deadline else {
            return Ok((raw, detail, state));
        };
        let now = tokio::time::Instant::now();
        if state.is_some() || now >= deadline {
            return Ok((raw, detail, state));
        }
        say(&format!(
            "Review is {}; checking again in {delay} seconds.",
            text::one_line(&detail.status)
        ));
        let pause = Duration::from_secs(delay).min(deadline.saturating_duration_since(now));
        tokio::time::sleep(pause).await;
        delay = (delay * 2).min(LONGEST_POLL_SECONDS);
    }
}

/// Prints the review, after waiting for it to finish when `wait` is set.
async fn show(
    api: &Api,
    review_id: Uuid,
    wait: bool,
    output: &OutputArgs,
    format: OutputFormat,
) -> anyhow::Result<Verdict> {
    let deadline = if wait {
        Some(poll_deadline(output.timeout)?)
    } else {
        None
    };
    let sarif = matches!(format, OutputFormat::Sarif);
    let (raw, detail, state) = read_review(api, review_id, deadline, sarif).await?;
    print_review(api, review_id, raw, &detail, state, format)?;
    match state {
        Some(Outcome::Completed) => return Ok(Verdict::Done),
        Some(ended) => say_not_complete(ended),
        None if wait => say(&format!(
            "The review was still {} after {} minutes; it continues at {}",
            text::one_line(&detail.status),
            output.timeout,
            api.review_url(review_id)
        )),
        None => say("The review has not finished; pass --wait to wait for its result."),
    }
    Ok(Verdict::NotComplete)
}

fn say_not_complete(ended: Outcome) {
    say(if ended == Outcome::Incomplete {
        "The result is incomplete: a code or environment assessment is unavailable or incomplete."
    } else {
        "The review did not finish, so it has no complete result."
    });
}

/// The commit a CI job tests: `--commit`, else the runner's `COMMIT_SHA`
/// (Cloud Build), else the GitHub Actions job's commit: the pull request's head
/// on a pull-request event, `GITHUB_SHA` otherwise. Only a full SHA is
/// accepted, never a ref.
fn ci_commit(flag: Option<&str>) -> anyhow::Result<String> {
    let cloud_build = std::env::var("COMMIT_SHA")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let raw = match (flag, cloud_build) {
        (Some(raw), _) => raw.to_owned(),
        (None, Some(raw)) => raw,
        (None, None) => github_actions::commit_under_test()?
            .context("name the commit under test with --commit, COMMIT_SHA or GITHUB_SHA")?,
    };
    Ok(git::commit_sha(&raw)?)
}

/// Whether a failure is Proofline's rather than the caller's: the console
/// could not be reached or failed on its side.
fn unavailable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|error| match error {
            ApiError::Transport { .. } => true,
            ApiError::Problem { status, .. } => *status >= 500,
            ApiError::Protocol { .. } => false,
        })
}

/// `ci review` once its inputs are read. In GitHub Actions without
/// `PROOFLINE_TOKEN`, the job's signed identity is the credential, and only
/// then, on a `pull_request` event, may the job ask for a review itself.
async fn ci_job(
    http: Http,
    token: Option<SecretString>,
    issuer: Option<github_actions::Issuer>,
    event: &str,
    org: Option<Uuid>,
    args: &CiReviewArgs,
    commit: &str,
) -> anyhow::Result<Verdict> {
    let (api, request) = match (token, issuer) {
        (None, Some(issuer)) => {
            let head = github_actions::pull_request_head(event, commit);
            let api = github_actions::api(http.clone(), &issuer, org, head).await?;
            let request = github_actions::ReviewRequest::for_event(event, http, issuer, commit);
            (api, request)
        }
        (token, _) => (connect(http, token, org).await?, None),
    };
    ci_review(&api, args, commit, request.as_ref()).await
}

/// How long a pull-request job waits for the App's review of its head before
/// it asks for one.
const REQUEST_AFTER: Duration = Duration::from_secs(120);

/// Waits for the review the App runs for the pull request whose head is
/// `commit`, then reports it. With `request`, a job that has found no review
/// after [`REQUEST_AFTER`] asks once for one and reports the review it gets;
/// a refusal is reported and the wait goes on. Without it nothing is
/// requested, so the job never starts a second review of the head.
async fn ci_review(
    api: &Api,
    args: &CiReviewArgs,
    commit: &str,
    mut request: Option<&github_actions::ReviewRequest>,
) -> anyhow::Result<Verdict> {
    let started = tokio::time::Instant::now();
    let deadline = poll_deadline(args.timeout)?;
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let mut delay = FIRST_POLL_SECONDS;
    let review_id = loop {
        let found = latest(api, repository_id, commit, |item| {
            item.kind == "PULL_REQUEST" && item.head_commit_sha.as_deref() == Some(commit)
        })
        .await?;
        if let Some(id) = found {
            break id;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            say(&format!(
                "No pull-request review of {name} has head commit {commit} after {} minutes. Proofline reviews a commit once it is the head of an open pull request.",
                args.timeout
            ));
            return Ok(Verdict::Unavailable);
        }
        let request_at = started + REQUEST_AFTER;
        if now >= request_at
            && let Some(asking) = request.take()
        {
            match asking.send().await {
                Ok(id) => {
                    say(&format!(
                        "No review of {name} at {commit} appeared, so this job requested one."
                    ));
                    break id;
                }
                Err(error) => say(&format!(
                    "proofline: this job could not request a review: {error:#}"
                )),
            }
        }
        say(&format!(
            "No review of {name} at {commit} yet; checking again in {delay} seconds."
        ));
        let wake = if request.is_some() {
            deadline.min(request_at)
        } else {
            deadline
        };
        let pause = Duration::from_secs(delay).min(wake.saturating_duration_since(now));
        tokio::time::sleep(pause).await;
        delay = (delay * 2).min(LONGEST_POLL_SECONDS);
    };
    let sarif_path = args.sarif.as_deref();
    let (raw, detail, state) =
        read_review(api, review_id, Some(deadline), sarif_path.is_some()).await?;
    if let Some(path) = sarif_path {
        let document = sarif::review(
            &detail,
            review_id,
            api.organization_id(),
            api.review_url(review_id).as_str(),
        )?;
        tokio::fs::write(path, serde_json::to_vec_pretty(&document)?)
            .await
            .with_context(|| format!("could not write SARIF to {}", path.display()))?;
    }
    print_review(
        api,
        review_id,
        raw,
        &detail,
        state,
        OutputFormat::from_json(args.json),
    )?;
    let verdict = ci_verdict(
        state,
        detail.open_items.as_ref(),
        outcome::code_assessment(&detail),
        args.fail_on,
    );
    match state {
        None => say(&format!(
            "The review was still {} after {} minutes; it continues at {}",
            text::one_line(&detail.status),
            args.timeout,
            api.review_url(review_id)
        )),
        Some(Outcome::Completed) => match verdict {
            Verdict::ThresholdReached => {
                say("The review has an open finding at or above the --fail-on severity.");
            }
            Verdict::Unavailable => say(
                "Proofline returned the completed review without `open_items`, so --fail-on could not be measured. It is not a pass.",
            ),
            Verdict::Done | Verdict::NotComplete | Verdict::Blocked => {}
        },
        Some(ended) => say_not_complete(ended),
    }
    Ok(verdict)
}

/// How `ci review` ends for a review read as `state`. Completeness decides
/// first: only a complete review is measured against `fail_on`, because the
/// findings of a review that did not finish are not its whole result. The
/// server counts open ENV findings and their current decisions. CODE findings
/// have no projected decisions. Those of a complete CODE assessment are
/// measured by their recorded severity and lifecycle. Without the ENV counts
/// the threshold cannot be measured, which is never a pass.
fn ci_verdict(
    state: Option<Outcome>,
    open_items: Option<&OpenItems>,
    code_assessment: Option<&CodeAssessment>,
    fail_on: Option<Severity>,
) -> Verdict {
    match state {
        None => Verdict::Unavailable,
        Some(Outcome::Incomplete | Outcome::Failed | Outcome::Stopped) => Verdict::NotComplete,
        Some(Outcome::Completed) => match (fail_on, open_items) {
            (None, _) => Verdict::Done,
            (Some(_), None) => Verdict::Unavailable,
            (Some(threshold), Some(open)) => {
                let count = match threshold {
                    Severity::Warning => open.open_findings,
                    Severity::Serious => open.serious_findings,
                };
                let code_reaches =
                    code_assessment.is_some_and(|code| outcome::code_reaches(code, threshold));
                if count > 0 || code_reaches {
                    Verdict::ThresholdReached
                } else {
                    Verdict::Done
                }
            }
        },
    }
}

fn print_review(
    api: &Api,
    requested_review: Uuid,
    raw: serde_json::Value,
    detail: &ReviewDetail,
    state: Option<Outcome>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    match format {
        OutputFormat::Json => {
            // `outcome` is the CLI's reading of completeness, null while the
            // review runs; `review` is the API's document, every field included.
            let document = serde_json::json!({
                "schema": result::FORMAT,
                "outcome": state.map(Outcome::as_str),
                "review_url": api.review_url(detail.id).as_str(),
                "review": raw,
            });
            writeln!(stdout, "{}", serde_json::to_string_pretty(&document)?)?;
        }
        OutputFormat::Sarif => {
            let document = sarif::review(
                detail,
                requested_review,
                api.organization_id(),
                api.review_url(requested_review).as_str(),
            )?;
            writeln!(stdout, "{}", serde_json::to_string_pretty(&document)?)?;
        }
        OutputFormat::Text => {
            write!(
                stdout,
                "{}",
                render::review(detail, state, &api.review_url(detail.id))
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::{RawQuery, Request};
    use axum::http::{HeaderMap, header};
    use axum::middleware::Next;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;

    use super::*;

    const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
    const REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000f0";
    const REQUESTED: &str = "0190f3a0-0000-7000-8000-0000000000f1";
    const HEAD: &str = "89abcdef0123456789abcdef0123456789abcdef";

    /// One request the stand-in console received: method and path, when on
    /// the test's clock, its bearer and its query.
    type Received = (String, Duration, String, String);

    /// A runner that issues numbered OIDC tokens and a console on which no
    /// review of `HEAD` ever appears, except the one a job requests.
    async fn console(start: tokio::time::Instant) -> (String, Arc<Mutex<Vec<Received>>>) {
        let issued = Arc::new(Mutex::new(0_u32));
        let app = Router::new()
            .route(
                "/github/token",
                get(move || {
                    let issued = Arc::clone(&issued);
                    async move {
                        let number = {
                            let mut issued = issued.lock().unwrap();
                            *issued += 1;
                            *issued
                        };
                        Json(json!({ "value": format!("job-identity-{number}") }))
                    }
                }),
            )
            .route(
                "/api/v1/ci/github-actions/credentials",
                post(|| async {
                    Json(json!({
                        "organization_id": ORG,
                        "repository_id": REPOSITORY,
                        "token": "plj_job",
                        "expires_at": "2026-10-11T01:00:00Z",
                    }))
                }),
            )
            .route(
                "/api/v1/ci/github-actions/review",
                post(|| async {
                    Json(json!({
                        "review_id": REQUESTED,
                        "run_number": 1,
                        "existing": false,
                        "automatic_reviews_paused": false,
                    }))
                }),
            )
            .route(
                &format!("/api/v1/organizations/{ORG}/repository-names"),
                get(|| async {
                    Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/app" }] }))
                }),
            )
            .route(
                &format!("/api/v1/organizations/{ORG}/reviews"),
                get(|| async {
                    Json(json!({
                        "items": [], "next_cursor": null, "truncated": false,
                        "filters": { "repositories": [], "environments": [], "authors": [] },
                    }))
                }),
            )
            .route(
                &format!("/api/v1/organizations/{ORG}/reviews/{REQUESTED}"),
                get(|| async {
                    Json(json!({
                        "id": REQUESTED,
                        "kind": "PULL_REQUEST",
                        "status": "COMPLETED",
                        "head_commit_sha": HEAD,
                        "pull_request_number": 12,
                        "run_number": 1,
                        "assessment_count": 1,
                        "open_items": {
                            "open_findings": 0, "serious_findings": 0,
                            "accepted_risks": 0, "not_assessed": [],
                        },
                        "assessments": [{
                            "id": "0190f3a0-0000-7000-8000-0000000000f2",
                            "environment_display_name": "production",
                            "status": "COMPLETED",
                            "findings": [],
                            "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
                        }],
                    }))
                }),
            );
        let received = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&received);
        let app = app.layer(axum::middleware::from_fn(
            move |headers: HeaderMap, RawQuery(query): RawQuery, request: Request, next: Next| {
                let observed = Arc::clone(&observed);
                async move {
                    let bearer = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    observed.lock().unwrap().push((
                        format!("{} {}", request.method(), request.uri().path()),
                        tokio::time::Instant::now().duration_since(start),
                        bearer,
                        query.unwrap_or_default(),
                    ));
                    next.run(request).await
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (origin, received)
    }

    /// The job asks for a review once, two minutes in, with an OIDC token
    /// issued for that request, and only when its own signed identity on a
    /// `pull_request` event is the credential. The clock is paused, so the
    /// waits take no time.
    #[tokio::test(start_paused = true)]
    async fn only_a_pull_request_job_on_its_own_identity_asks_once_after_two_minutes() {
        // A paused clock jumps to the next timer whenever the runtime waits,
        // even on a loopback socket about to answer, which would fire the
        // client's request timeout. A 10 ms ticker bounds each jump.
        let ticker = tokio::spawn(async {
            for _ in 0..1_000_000 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let review = "POST /api/v1/ci/github-actions/review".to_owned();
        let token_requests = "GET /github/token".to_owned();
        // Whether the job holds `PROOFLINE_TOKEN`, its event, and the verdict.
        for (stored_token, event, verdict) in [
            (false, "pull_request", Verdict::Done),
            (true, "pull_request", Verdict::Unavailable),
            (false, "push", Verdict::Unavailable),
        ] {
            let case = format!("token {stored_token}, {event}");
            let start = tokio::time::Instant::now();
            let (origin, received) = console(start).await;
            let http = Http::new(Origin::parse(&origin).unwrap()).unwrap();
            let issuer = github_actions::Issuer::new(
                format!("{origin}/github/token").parse().unwrap(),
                SecretString::from("runner-secret"),
            );
            let args = CiReviewArgs {
                commit: None,
                sarif: None,
                json: false,
                timeout: 3,
                fail_on: None,
                repository: RepositoryArgs {
                    repo: Some("acme/app".to_owned()),
                    remote: "origin".to_owned(),
                },
            };
            let token = stored_token.then(|| SecretString::from("plp_stored"));
            let org = stored_token.then(|| ORG.parse().unwrap());
            let ended = ci_job(http, token, Some(issuer), event, org, &args, HEAD)
                .await
                .unwrap();
            assert_eq!(ended, verdict, "{case}");

            let received = received.lock().unwrap().clone();
            let requests: Vec<_> = received
                .iter()
                .filter(|(request, ..)| *request == review)
                .collect();
            let issued = received
                .iter()
                .filter(|(request, ..)| *request == token_requests)
                .count();
            if verdict == Verdict::Done {
                let [(_, at, bearer, query)] = requests.as_slice() else {
                    panic!("{case}: {received:?}");
                };
                assert!(
                    (REQUEST_AFTER..REQUEST_AFTER + Duration::from_secs(1)).contains(at),
                    "{case}: {at:?}"
                );
                // The exchange spent the first token; the request has its own.
                assert_eq!(issued, 2, "{case}");
                assert_eq!(bearer, "Bearer job-identity-2", "{case}");
                assert_eq!(*query, format!("pull_request_head={HEAD}"), "{case}");
            } else {
                assert!(requests.is_empty(), "{case}: {received:?}");
                // The wait ran past two minutes to its deadline.
                let last = received.iter().map(|(_, at, ..)| *at).max().unwrap();
                assert!(last >= Duration::from_secs(180), "{case}: {last:?}");
                assert_eq!(issued, usize::from(!stored_token), "{case}");
            }
        }
        ticker.abort();
    }

    #[test]
    fn ci_measures_only_a_complete_review_against_the_open_finding_counts() {
        let open = |open_findings, serious_findings| OpenItems {
            open_findings,
            serious_findings,
        };
        let (warning, serious) = (Some(Severity::Warning), Some(Severity::Serious));
        let complete = Some(Outcome::Completed);
        for (state, verdict) in [
            (complete, Verdict::ThresholdReached),
            (Some(Outcome::Incomplete), Verdict::NotComplete),
            (Some(Outcome::Failed), Verdict::NotComplete),
            (Some(Outcome::Stopped), Verdict::NotComplete),
            (None, Verdict::Unavailable),
        ] {
            assert_eq!(
                ci_verdict(state, Some(&open(1, 1)), None, serious),
                verdict,
                "{state:?}"
            );
        }
        for (counts, fail_on, verdict) in [
            (Some(open(1, 1)), warning, Verdict::ThresholdReached),
            (Some(open(1, 0)), warning, Verdict::ThresholdReached),
            (Some(open(1, 0)), serious, Verdict::Done),
            (Some(open(0, 0)), warning, Verdict::Done),
            (Some(open(0, 0)), serious, Verdict::Done),
            // Without the flag, open findings never fail the job.
            (Some(open(1, 1)), None, Verdict::Done),
            (None, None, Verdict::Done),
            // A threshold that cannot be measured is never a pass.
            (None, warning, Verdict::Unavailable),
            (None, serious, Verdict::Unavailable),
        ] {
            assert_eq!(
                ci_verdict(complete, counts.as_ref(), None, fail_on),
                verdict,
                "{counts:?} {fail_on:?}"
            );
        }
        // A gap decides before the missing counts do.
        assert_eq!(
            ci_verdict(Some(Outcome::Incomplete), None, None, serious),
            Verdict::NotComplete
        );
    }
}
