//! The `proofline` command-line client. It signs in through the browser, keeps
//! its token in the operating system keychain, and reads and requests reviews
//! through the public review API. It shares no code with the server crate.

mod agent;
mod annotations;
pub mod api;
mod config;
mod coverage;
pub mod credentials;
mod deploy;
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
mod scan;
mod setup;
mod severity;
pub mod text;
mod tls;
pub mod update;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;

use crate::api::{Api, ApiError, DelegationState, Http};
use crate::credentials::{Credential, Source};
mod fixes;
mod knowledge;
mod tools;

use crate::model::{
    CodeAssessment, CommitReviewRequest, FileReviewRequest, OpenItems, PatchReviewRequest,
    RepositoryNames, ReviewDetail, ReviewFilters, ReviewSummary,
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
    /// already names its organization. Native knowledge, fix and config commands
    /// send this target per MCP call; the server authorizes it. The raw mcp bridge
    /// preserves the caller's per-call target.
    #[arg(long, global = true, env = "PROOFLINE_ORGANIZATION_ID")]
    org: Option<Uuid>,

    /// PEM file of extra root certificates to trust beside the existing
    /// roots, such as the root of a TLS-inspecting corporate proxy.
    #[arg(long, global = true, env = "PROOFLINE_CA_CERT", value_name = "FILE")]
    ca_cert: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read, propose and apply configuration through the hosted tools.
    #[command(subcommand)]
    Config(config::Command),
    /// Read fix context and verify fixes at an explicitly pushed commit.
    #[command(subcommand)]
    Fix(fixes::FixCommand),
    /// List one page of reviews, retaining its continuation cursor.
    Reviews(tools::ListArgs),
    /// Read the routing decisions of a review as JSON.
    Routing { review_id: Uuid },
    /// Read a specific recorded pull-request run.
    Run(tools::RunArgs),
    /// Preview, start or inspect a vendor coding-agent session.
    #[command(subcommand)]
    Session(tools::SessionCommand),
    /// Read published wiki pages.
    #[command(subcommand)]
    Wiki(knowledge::WikiCommand),
    /// Ask a codebase question at an optional indexed commit.
    Ask(knowledge::AskArgs),
    /// Read an environment's published architecture document.
    Architecture { environment_id: Uuid },
    /// Read a plan or start and inspect its approved implementation.
    #[command(subcommand)]
    Plan(knowledge::PlanCommand),
    /// Open browser onboarding, or read setup and its instructions from a shell.
    ///
    /// Without a subcommand, opens the GitHub App installation in a browser;
    /// cloud trust requires browser sign-in.
    #[command(args_conflicts_with_subcommands = true)]
    Setup {
        /// Print the address instead of opening a browser.
        #[arg(long)]
        print: bool,
        /// GitHub organization slug; omit to open the authorized organization selector.
        #[arg(long)]
        organization: Option<String>,
        #[command(subcommand)]
        command: Option<setup::Command>,
    },
    /// Rerun the original immutable review subject.
    Rerun(tools::RerunArgs),
    /// Scan the whole repository at one ref or commit, within a credit budget.
    Scan(scan::ScanArgs),
    /// List the recorded runs of a pull request.
    History(tools::HistoryArgs),
    /// Read the repository review guidance as JSON.
    Guidance(RepositoryArgs),
    /// Read a bounded, untrusted finding fix prompt as JSON.
    FixPrompt { finding_id: Uuid },
    /// Export one page of analytics as CSV or NDJSON.
    Export(tools::ExportArgs),
    /// Print a shell completion script to standard output.
    ///
    /// For example, add `source <(proofline completions zsh)` to `~/.zshrc`,
    /// `proofline completions bash > ~/.local/share/bash-completion/completions/proofline`,
    /// `proofline completions fish > ~/.config/fish/completions/proofline.fish`, or
    /// `proofline completions powershell | Out-String | Invoke-Expression` to a
    /// PowerShell profile.
    Completions {
        /// The shell to complete for.
        shell: clap_complete::Shell,
    },
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
    /// Upload coverage reports produced by your CI.
    #[command(subcommand)]
    Coverage(coverage::Command),
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
    /// Wait for Proofline to record a check of the deploys of the commit
    /// under test and exit by what the checks recorded.
    ///
    /// It reads the deploys of the commit in the repository, keeps those that
    /// `--environment`, `--task`, `--run` and `--attempt` select, and waits
    /// until each has recorded the `--until` check. It then prints one line for
    /// each deploy and check through `--until`: the checkpoint, its result, the
    /// checkpoint's gap codes and the deploy's page. Older servers supply
    /// the deploy-wide gaps for every check. Authentication is as for
    /// `ci review`, so a GitHub Actions job granted `id-token: write` needs no
    /// stored secret.
    ///
    /// Exit codes:
    ///   0  each check through `--until` recorded HEALTHY with no gap
    ///      on every selected deploy: no regression observed
    ///   3  a selected deploy failed or recorded REGRESSED
    ///   2  not established: a check through `--until` is INCOMPLETE,
    ///      SUPERSEDED or names a gap, the check is not recorded by `--timeout`, or no
    ///      selected deploy is recorded
    ///   1  a usage, authentication or authorization error
    ///   4  Proofline could not be reached or failed
    #[command(verbatim_doc_comment)]
    Deploy(deploy::CiDeployArgs),
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
    /// Also print each finding that is not resolved as a GitHub Actions
    /// annotation on stderr, so it shows on the pull request's diff. Unlike
    /// uploading `--sarif` to code scanning, this works on every GitHub plan.
    #[arg(long)]
    annotations: bool,
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
    /// Review only this literal repository-relative file in the local patch.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["pr", "commit", "range", "files"])]
    path: Option<String>,
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
    /// Exit 3 when the completed review has an open finding at or above this
    /// severity, as `ci review --fail-on` does.
    #[arg(long, value_enum, value_name = "SEVERITY", conflicts_with = "no_wait")]
    fail_on: Option<Severity>,
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
    /// A complete review has an open finding at or above `--fail-on`.
    ThresholdReached,
    /// A Git hook's exit policy refuses the commit or push.
    Blocked,
    /// A deploy failed or one of its checks recorded a regression.
    Regressed,
}

/// Runs one command. `token` is `PROOFLINE_TOKEN`, read by the caller.
pub async fn run(cli: Cli, token: Option<SecretString>) -> anyhow::Result<Verdict> {
    if let Some(path) = &cli.ca_cert {
        tls::trust(path)?;
    }
    if let Command::Review(args) = &cli.command
        && args.schema
    {
        let document = result::schema()?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", serde_json::to_string_pretty(&document)?)?;
        return Ok(Verdict::Done);
    }
    match &cli.command {
        Command::Completions { shell } => {
            completions(*shell, &mut std::io::stdout().lock())?;
            return Ok(Verdict::Done);
        }
        Command::Update => return update::install().await.map(|()| Verdict::Done),
        Command::UpdateCheck => {
            update::check().await;
            return Ok(Verdict::Done);
        }
        _ => {}
    }
    let origin = Origin::parse(&cli.base_url)?;
    match cli.command {
        Command::Completions { shell } => {
            completions(shell, &mut std::io::stdout().lock())?;
            Ok(Verdict::Done)
        }
        Command::Update => update::install().await.map(|()| Verdict::Done),
        Command::UpdateCheck => {
            update::check().await;
            Ok(Verdict::Done)
        }
        Command::Setup {
            command: Some(command),
            ..
        } => {
            if let Some((name, arguments)) = command.request() {
                config::call(origin, token, cli.org, name, arguments).await
            } else {
                write!(std::io::stdout().lock(), "{}", setup::GUIDE)?;
                Ok(Verdict::Done)
            }
        }
        Command::Setup {
            print,
            organization,
            command: None,
        } => {
            let url = organization.as_deref().map_or_else(
                || origin.join(["orgs"]),
                |slug| origin.join(["orgs", "github", slug, "settings", "installation"]),
            );
            writeln!(std::io::stdout().lock(), "{url}")?;
            if !print {
                webbrowser::open(url.as_str())?;
            }
            Ok(Verdict::Done)
        }
        Command::Config(command) => config::run(origin, token, cli.org, command).await,
        Command::Fix(command) => knowledge::run(origin, token, cli.org, command.request()?).await,
        Command::Wiki(command) => knowledge::run(origin, token, cli.org, command.request()?).await,
        Command::Ask(args) => knowledge::run(origin, token, cli.org, args.request()?).await,
        Command::Architecture { environment_id } => {
            knowledge::run(
                origin,
                token,
                cli.org,
                (
                    "get_architecture_document",
                    serde_json::json!({"environment_id": environment_id}),
                ),
            )
            .await
        }
        Command::Plan(command) => knowledge::run(origin, token, cli.org, command.request()).await,
        Command::Reviews(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::json(
                &api.list_page(
                    args.repository_id,
                    args.search.as_deref(),
                    args.cursor.as_deref(),
                )
                .await?,
            )
        }
        Command::Routing { review_id } => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::json(
                &api.get(api.url_get_review_routing(&review_id.to_string()))
                    .await?,
            )
        }
        Command::Run(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            let runs = pull_request_runs(&api, &args.repository, args.pr).await?;
            tools::json(
                &api.get(api.url_get_pull_request_review(
                    route_name(&runs.full_name),
                    &args.pr.to_string(),
                    &args.run.to_string(),
                ))
                .await?,
            )
        }
        Command::Session(command) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::session(&api, command).await
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
        Command::Scan(args) => {
            let request = scan::request(&args)?;
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            scan::run(&api, &args, &request).await
        }
        Command::History(args) => {
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            tools::json(
                &pull_request_runs(&api, &args.repository, args.pr)
                    .await?
                    .raw,
            )
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
            ci_ending(result)
        }
        Command::Ci(CiCommand::Deploy(mut args)) => {
            if let Some(produced) = github_actions::producing_run()? {
                let cloud_build =
                    std::env::var("COMMIT_SHA").is_ok_and(|sha| !sha.trim().is_empty());
                args.follow(&produced, cloud_build);
            }
            let reader_run = github_actions::current_run_id();
            args.check_reader_run(reader_run)?;
            let commit = ci_commit(args.commit.as_deref())?;
            args.timeout_minutes()?;
            let http = Http::new(origin)?;
            let issuer = github_actions::Issuer::from_environment();
            let result = async {
                let api = match (token, issuer) {
                    (None, Some(issuer)) => {
                        github_actions::api(http, &issuer, cli.org, None).await?
                    }
                    (token, _) => connect(http, token, cli.org).await?,
                };
                deploy::wait(&api, &args, &commit, reader_run).await
            }
            .await;
            ci_ending(result)
        }
        Command::Hooks(args) => hooks::manage(args).await.map(|()| Verdict::Done),
        Command::Coverage(coverage::Command::Upload(args)) => {
            let request = coverage::request(&args).await?;
            let api = connect(Http::new(origin)?, token, cli.org).await?;
            coverage::upload(&api, &args, &request).await?;
            Ok(Verdict::Done)
        }
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

/// Writes the completion script for `shell`. It needs no origin, token or
/// network, so it works before `proofline login`.
fn completions(shell: clap_complete::Shell, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    const NAME: &str = "proofline";
    let full = <Cli as clap::CommandFactory>::command();
    // The static generators offer hidden subcommands too, so leave them out.
    let mut command = full.get_arguments().cloned().fold(
        clap::Command::new(NAME).version(env!("CARGO_PKG_VERSION")),
        clap::Command::arg,
    );
    command = full
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .cloned()
        .fold(command, clap::Command::subcommand);
    clap_complete::generate(shell, &mut command, NAME, out);
    out.flush()?;
    Ok(())
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
    // A stored sign-in names its scopes; an environment token may hold any.
    let delegates = scope.as_deref().is_none_or(|scope| {
        scope
            .split_whitespace()
            .any(|scope| matches!(scope, "setup:write" | "org:configure"))
    });
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
    if let Some(scope) = &scope {
        lines.push(format!("scopes: {}", text::one_line(scope)));
    }
    if let Some(expires_at) = expires_at {
        let left = expires_at.saturating_sub(device::now());
        lines.push(if left == 0 {
            "expires: expired; run `proofline login`".to_owned()
        } else {
            format!("expires: in {} hours", left.div_ceil(3600))
        });
    }
    // A sign-in narrowed to scans cannot read reviews, so the probe reads the
    // route that scope opens instead (#33149).
    let scans_only = scope.as_deref().is_some_and(|scope| {
        let mut scopes = scope.split_whitespace();
        !scopes.clone().any(|scope| scope == "reviews:read")
            && scopes.any(|scope| scope == "scans:request")
    });
    let api = Api::new(http, token, organization_id);
    let (result, accepted) = if scans_only {
        (
            api.scan_repository_names().await.map(drop),
            "server: accepted the token for scans",
        )
    } else {
        (
            api.review_filters().await.map(drop),
            "server: accepted the token for reviews",
        )
    };
    lines.push(match &result {
        Ok(()) => accepted.to_owned(),
        Err(error) if error.status() == Some(401) => {
            "server: the token is expired, revoked or malformed; run `proofline login`".to_owned()
        }
        Err(error) => format!("server: {error}"),
    });
    if result.is_ok() && delegates {
        lines.extend(delegation(&api).await);
    }
    writeln!(std::io::stdout().lock(), "{}", lines.join("\n"))?;
    result?;
    Ok(())
}

/// Whether the token's setup and configuration grants still work: they act
/// for the browser session that approved them and end with it, while review
/// access continues. `None` for a token that holds neither grant.
async fn delegation(api: &Api) -> Option<String> {
    let delegation = match api.agent_delegation().await {
        Ok(delegation) => delegation,
        Err(error) => return Some(format!("setup delegation: could not be read: {error}")),
    };
    if delegation.scopes.is_empty() {
        return None;
    }
    let scopes = text::one_line(&delegation.scopes.join(", "));
    Some(match delegation.state {
        Some(DelegationState::Active) => {
            format!("setup delegation: active for {scopes}")
        }
        Some(DelegationState::Ended) | None => format!(
            "setup delegation: ended for {scopes} because the approving browser sign-in ended; review access still works. Run `{}` and approve it in the browser",
            config::LOGIN
        ),
    })
}

async fn repository_name(args: &RepositoryArgs) -> anyhow::Result<String> {
    match &args.repo {
        Some(name) => Ok(name.clone()),
        None => Ok(git::repository(&args.remote).await?),
    }
}

/// The one candidate whose name is `name`, ignoring case, with the name as
/// the server spells it. A name shared by two IDs is refused rather than
/// guessed.
fn unique(
    api: &Api,
    name: &str,
    candidates: impl Iterator<Item = (Uuid, String)>,
    absent: impl FnOnce() -> anyhow::Error,
) -> anyhow::Result<(Uuid, String)> {
    let mut found = candidates.filter(|(_, candidate)| candidate.eq_ignore_ascii_case(name));
    match (found.next(), found.next()) {
        (Some(choice), None) => Ok(choice),
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
    connected(api, name, names)
}

/// A connected repository, for requesting a scan, resolved through the route
/// a sign-in holding only `scans:request` can read.
async fn scannable_repository(api: &Api, args: &RepositoryArgs) -> anyhow::Result<(String, Uuid)> {
    let name = repository_name(args).await?;
    let names = api.scan_repository_names().await?;
    connected(api, name, names)
}

fn connected(api: &Api, name: String, names: RepositoryNames) -> anyhow::Result<(String, Uuid)> {
    let candidates = names
        .repositories
        .into_iter()
        .map(|repository| (repository.id, repository.full_name));
    let (id, _) = unique(api, &name, candidates, || {
        anyhow::anyhow!(
            "{name} is not a repository in organization {} that this token can read; check the repository name and the token's repositories",
            api.organization_id()
        )
    })?;
    Ok((name, id))
}

/// A repository with reviews the token can read, for finding one of them, as
/// its full name and ID. A repository that has since left the installation
/// keeps its reviews, so this reads the review collection's repositories, not
/// the connected ones.
async fn reviewed_repository(api: &Api, args: &RepositoryArgs) -> anyhow::Result<(String, Uuid)> {
    let name = repository_name(args).await?;
    reviewed(api, &name, api.review_filters().await?)
}

/// The repository named `name` among the review collection's filter choices.
fn reviewed(api: &Api, name: &str, filters: ReviewFilters) -> anyhow::Result<(String, Uuid)> {
    let candidates = filters
        .repositories
        .into_iter()
        .map(|choice| (choice.id, choice.name));
    let (id, full_name) = unique(api, name, candidates, || {
        anyhow::anyhow!(
            "{name} has no reviews in organization {} that this token can read; check the repository name and the token's repositories",
            api.organization_id()
        )
    })?;
    Ok((full_name, id))
}

/// Pull request `number`'s runs as the server sent them, and the repository
/// they belong to as its full name and ID.
struct PullRequestRuns {
    full_name: String,
    repository_id: Uuid,
    raw: serde_json::Value,
}

/// Reads pull request `number`'s runs through its own route rather than the
/// organization's review list (#34229). The route matches the name without
/// its owner, so the response's filters must name the repository under its
/// full name before anything it returned is used.
async fn pull_request_runs(
    api: &Api,
    args: &RepositoryArgs,
    number: u64,
) -> anyhow::Result<PullRequestRuns> {
    let name = repository_name(args).await?;
    let (raw, filters) = api.pull_request_reviews(route_name(&name), number).await?;
    let (full_name, repository_id) = reviewed(api, &name, filters)?;
    Ok(PullRequestRuns {
        full_name,
        repository_id,
        raw,
    })
}

/// The newest review of pull request `number`, counting only runs of the
/// repository whose full name matched.
async fn pull_request_review(
    api: &Api,
    args: &RepositoryArgs,
    number: u64,
) -> anyhow::Result<Uuid> {
    let runs = pull_request_runs(api, args, number).await?;
    let page = serde_json::from_value::<model::ReviewPage>(runs.raw)
        .with_context(|| format!("{} returned an unreadable review list", api.origin()))?;
    page.items
        .iter()
        .find(|item| {
            item.kind == "PULL_REQUEST"
                && item.repository_id == Some(runs.repository_id)
                && item.pull_request_number == i64::try_from(number).ok()
        })
        .map(|item| item.id)
        .with_context(|| format!("{} #{number} has no review", runs.full_name))
}

/// The `{repository}` segment of the pull-request review routes: the name
/// without its owner. The route cannot check the owner, so callers check the
/// full name against the organization's reviewed repositories before they
/// use what it returns.
fn route_name(full_name: &str) -> &str {
    full_name
        .rsplit_once('/')
        .map_or(full_name, |(_, name)| name)
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
        args.path.as_deref(),
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
        args.fail_on,
    )
    .await
}

async fn findings(api: &Api, args: &FindingsArgs) -> anyhow::Result<Verdict> {
    let review_id = match (&args.selector.review, args.selector.pr) {
        (Some(id), _) => *id,
        (None, Some(number)) => pull_request_review(api, &args.repository, number).await?,
        (None, None) => {
            let sha = match &args.selector.head {
                Some(raw) => git::commit_sha(raw)?,
                None => git::head().await?,
            };
            let (name, repository_id) = reviewed_repository(api, &args.repository).await?;
            // An audit is a revision scan of this commit too, but its
            // findings are in its report, so it never answers for the head.
            latest(api, repository_id, &sha, |item| {
                item.audit_mode.is_none() && item.head_commit_sha.as_deref() == Some(sha.as_str())
            })
                .await?
                .with_context(|| format!("no review of {name} has head commit {sha}; push it and open a pull request, or name one with --pr"))?
        }
    };
    let format = if args.sarif {
        OutputFormat::Sarif
    } else {
        OutputFormat::from_json(args.output.json)
    };
    show(api, review_id, args.wait, &args.output, format, None).await
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
/// a deadline it reads once. Every read confirms the server's answer is of
/// the review requested, not a cache or routing mix-up that would otherwise
/// let a result for a different review decide this one's outcome.
async fn read_review(
    api: &Api,
    review_id: Uuid,
    deadline: Option<tokio::time::Instant>,
    sarif: bool,
) -> anyhow::Result<(serde_json::Value, ReviewDetail, Option<Outcome>)> {
    let mut delay = FIRST_POLL_SECONDS;
    loop {
        let (raw, detail) = api.review(review_id).await?;
        outcome::same_review(&detail, review_id)?;
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
    fail_on: Option<Severity>,
) -> anyhow::Result<Verdict> {
    let deadline = if wait {
        Some(poll_deadline(output.timeout)?)
    } else {
        None
    };
    let sarif = matches!(format, OutputFormat::Sarif);
    let (raw, detail, state) = read_review(api, review_id, deadline, sarif).await?;
    // `audit_mode` marks an audit, as on a listed review (`ReviewSummary`).
    if raw.get("audit_mode").is_some_and(|mode| !mode.is_null()) {
        print_audit(api, raw, &detail, format)?;
        return Ok(Verdict::NotComplete);
    }
    print_review(api, review_id, raw, &detail, state, format)?;
    match state {
        Some(Outcome::Completed) => {
            let verdict = review_verdict(&detail, fail_on);
            match verdict {
                Verdict::ThresholdReached => {
                    say("The review has an open finding at or above the --fail-on severity.");
                }
                Verdict::Unavailable => say(
                    "Proofline returned the completed review without `open_items`, so --fail-on could not be measured. It is not a pass.",
                ),
                Verdict::Done | Verdict::NotComplete | Verdict::Blocked | Verdict::Regressed => {}
            }
            return Ok(verdict);
        }
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

/// A CI command's result, with a failure that is Proofline's reported as
/// unavailable (exit 4) rather than as the caller's error (exit 1).
fn ci_ending(result: anyhow::Result<Verdict>) -> anyhow::Result<Verdict> {
    match result {
        Err(error) if unavailable(&error) => {
            say(&format!("proofline: {error:#}"));
            Ok(Verdict::Unavailable)
        }
        result => result,
    }
}

/// Whether a failure is Proofline's rather than the caller's: the console
/// could not be reached or failed on its side.
fn unavailable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|error| match error {
            ApiError::Transport { .. } => true,
            ApiError::Problem { status, .. } => *status >= 500,
            ApiError::Protocol { .. } | ApiError::Renewal { .. } => false,
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

/// Confirms `detail` is actually the pull-request review of `commit` in
/// `repository_id` before it is allowed to decide a CI verdict or produce a
/// SARIF artifact. [`read_review`] already confirms `detail` is the review
/// requested by id; a search match on `commit` against a summary row does
/// not guarantee the detail fetched moments later, by that id, kept the same
/// story, so the fields the search relied on are checked again here against
/// the server's own account of the subject. The repository is compared by
/// id, not `repository_full_name`: a GitHub rename changes the name but not
/// the id, and comparing names would then refuse a review that is actually
/// of the right repository. The id is checked only when the server names
/// one, since it is absent on an old server or a review that names no
/// repository.
fn confirm_ci_subject(
    detail: &ReviewDetail,
    commit: &str,
    repository_id: Uuid,
) -> anyhow::Result<()> {
    if detail.kind != "PULL_REQUEST" {
        bail!(
            "proofline asked for the pull-request review of {commit}, but the server returned a {} review",
            text::one_line(&detail.kind)
        );
    }
    if !detail
        .head_commit_sha
        .as_deref()
        .is_some_and(|head| head.eq_ignore_ascii_case(commit))
    {
        bail!(
            "proofline asked for the review of {commit}, but the server returned head commit {}",
            detail
                .head_commit_sha
                .as_deref()
                .map_or_else(|| "none".to_owned(), text::one_line)
        );
    }
    if let Some(detail_repository) = detail.repository_id
        && detail_repository != repository_id
    {
        bail!(
            "proofline asked for a review in repository {repository_id}, but the server returned a review in repository {detail_repository}"
        );
    }
    Ok(())
}

/// Waits for the review the App runs for the pull request whose head is
/// `commit`, then reports it. With `request`, a job that has found no review
/// after [`REQUEST_AFTER`] asks once for one and reports the review it gets;
/// a refusal is reported and the wait goes on. Without it nothing is
/// requested, so the job never starts a second review of the head.
async fn ci_review(
    api: &Api,
    args: &CiReviewArgs,
    commit: &str,
    request: Option<&github_actions::ReviewRequest>,
) -> anyhow::Result<Verdict> {
    let started = tokio::time::Instant::now();
    let deadline = poll_deadline(args.timeout)?;
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let Some(review_id) = wait_for_head_review(
        api,
        &name,
        repository_id,
        commit,
        args.timeout,
        started,
        deadline,
        request,
    )
    .await?
    else {
        return Ok(Verdict::Unavailable);
    };
    let sarif_path = args.sarif.as_deref();
    let (raw, detail, state) =
        read_review(api, review_id, Some(deadline), sarif_path.is_some()).await?;
    confirm_ci_subject(&detail, commit, repository_id)?;
    if let Some(path) = sarif_path {
        write_sarif(api, review_id, &detail, path).await?;
    }
    if args.annotations {
        annotations::write(&detail, &mut std::io::stderr().lock())?;
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
    say_ci_ending(api, review_id, &detail, state, verdict, args.timeout);
    Ok(verdict)
}

/// Polls for the newest `PULL_REQUEST` review whose head is `commit` until
/// `deadline`, asking once through `request` from [`REQUEST_AFTER`] past
/// `started`. `None` means no review appeared, which it has already said.
async fn wait_for_head_review(
    api: &Api,
    name: &str,
    repository_id: Uuid,
    commit: &str,
    timeout_minutes: u64,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
    mut request: Option<&github_actions::ReviewRequest>,
) -> anyhow::Result<Option<Uuid>> {
    let request_at = started + REQUEST_AFTER;
    let mut delay = FIRST_POLL_SECONDS;
    loop {
        let found = latest(api, repository_id, commit, |item| {
            item.kind == "PULL_REQUEST" && item.head_commit_sha.as_deref() == Some(commit)
        })
        .await?;
        if found.is_some() {
            return Ok(found);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            say(&format!(
                "No pull-request review of {name} has head commit {commit} after {timeout_minutes} minutes. Proofline reviews a commit once it is the head of an open pull request."
            ));
            return Ok(None);
        }
        if now >= request_at
            && let Some(asking) = request.take()
            && let Some(id) = ask_for_review(asking, name, commit).await
        {
            return Ok(Some(id));
        }
        say(&format!(
            "No review of {name} at {commit} yet; checking again in {delay} seconds."
        ));
        let pending = request.is_some().then_some(request_at);
        tokio::time::sleep(next_pause(delay, now, deadline, pending)).await;
        delay = (delay * 2).min(LONGEST_POLL_SECONDS);
    }
}

/// Sends the job's one review request and says what came of it.
async fn ask_for_review(
    asking: &github_actions::ReviewRequest,
    name: &str,
    commit: &str,
) -> Option<Uuid> {
    match asking.send().await {
        Ok(id) => {
            say(&format!(
                "No review of {name} at {commit} appeared, so this job requested one."
            ));
            Some(id)
        }
        Err(error) => {
            say(&format!(
                "proofline: this job could not request a review: {error:#}"
            ));
            None
        }
    }
}

/// How long the head-review wait sleeps: `delay` seconds, cut short at
/// `deadline` and, while a request is still pending, at `request_at`.
fn next_pause(
    delay: u64,
    now: tokio::time::Instant,
    deadline: tokio::time::Instant,
    request_at: Option<tokio::time::Instant>,
) -> Duration {
    let wake = request_at.map_or(deadline, |at| deadline.min(at));
    Duration::from_secs(delay).min(wake.saturating_duration_since(now))
}

/// Writes the review's SARIF document to `path`.
async fn write_sarif(
    api: &Api,
    review_id: Uuid,
    detail: &ReviewDetail,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    let document = sarif::review(
        detail,
        review_id,
        api.organization_id(),
        api.review_url(review_id).as_str(),
    )?;
    tokio::fs::write(path, serde_json::to_vec_pretty(&document)?)
        .await
        .with_context(|| format!("could not write SARIF to {}", path.display()))
}

/// The line `ci review` ends with: where a running review continues, why a
/// complete review failed the job, or why the review has no complete result.
fn say_ci_ending(
    api: &Api,
    review_id: Uuid,
    detail: &ReviewDetail,
    state: Option<Outcome>,
    verdict: Verdict,
    timeout_minutes: u64,
) {
    match state {
        None => say(&format!(
            "The review was still {} after {timeout_minutes} minutes; it continues at {}",
            text::one_line(&detail.status),
            api.review_url(review_id)
        )),
        Some(Outcome::Completed) => match verdict {
            Verdict::ThresholdReached => {
                say("The review has an open finding at or above the --fail-on severity.");
            }
            Verdict::Unavailable => say(
                "Proofline returned the completed review without `open_items`, so --fail-on could not be measured. It is not a pass.",
            ),
            Verdict::Done | Verdict::NotComplete | Verdict::Blocked | Verdict::Regressed => {}
        },
        Some(ended) => say_not_complete(ended),
    }
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

/// How `review --fail-on` ends for a complete review. A pull request counts
/// its open items, as `ci review` does; other reviews have no finding
/// decisions, so their findings count, as in a Git hook.
fn review_verdict(detail: &ReviewDetail, fail_on: Option<Severity>) -> Verdict {
    let Some(threshold) = fail_on else {
        return Verdict::Done;
    };
    if detail.kind == "PULL_REQUEST" {
        return ci_verdict(
            Some(Outcome::Completed),
            detail.open_items.as_ref(),
            outcome::code_assessment(detail),
            fail_on,
        );
    }
    if outcome::findings_reach(detail, threshold) {
        Verdict::ThresholdReached
    } else {
        Verdict::Done
    }
}

/// A repository audit read as a review: its findings are in its report, which
/// the review page links, so it is never a result to read as complete.
fn print_audit(
    api: &Api,
    raw: serde_json::Value,
    detail: &ReviewDetail,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let url = api.review_url(detail.id);
    let mut stdout = std::io::stdout().lock();
    match format {
        OutputFormat::Json => {
            let document = serde_json::json!({
                "schema": result::FORMAT,
                "outcome": result::REPOSITORY_AUDIT,
                "review_url": url.as_str(),
                "review": raw,
            });
            writeln!(stdout, "{}", serde_json::to_string_pretty(&document)?)?;
        }
        // `read_review` refuses SARIF for any review but a pull request's.
        OutputFormat::Sarif | OutputFormat::Text => {
            write!(stdout, "{}", render::audit(&url))?;
        }
    }
    Ok(())
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
    use axum::response::IntoResponse;
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

    /// How the stand-in console answers a job's review request.
    #[derive(Clone, Copy)]
    enum Grant {
        /// It starts the review, which is complete when read.
        Completes,
        /// It starts the review, which is still running whenever it is read.
        StaysRunning,
        /// It refuses the request.
        Refused,
    }

    /// How the stand-in console answers a job's credential exchanges.
    #[derive(Clone, Copy)]
    enum Exchange {
        /// Each exchange grants a numbered credential for this many seconds.
        Grants(i64),
        /// The first grants one for this many seconds, and each later
        /// exchange answers with this status.
        ThenAnswers(i64, u16),
    }

    /// An hour-long credential, as Proofline grants.
    const HOURLY: Exchange = Exchange::Grants(3_600);

    /// `unix` seconds as RFC 3339 in UTC, as the exchange writes `expires_at`.
    pub(crate) fn rfc3339(unix: i64) -> String {
        let (days, seconds) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
        let days = days + 719_468;
        let era = days.div_euclid(146_097);
        let of_era = days - era * 146_097;
        let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
        let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * of_year + 2) / 153;
        let day = of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            seconds / 3_600,
            seconds % 3_600 / 60,
            seconds % 60
        )
    }

    /// A runner that issues numbered OIDC tokens, a credential exchange that
    /// answers as `exchange` says, and a console on which no review of `HEAD`
    /// ever appears, except the one a job requests, which the console answers
    /// as `grant` says.
    async fn console(
        start: tokio::time::Instant,
        grant: Grant,
        exchange: Exchange,
    ) -> (String, Arc<Mutex<Vec<Received>>>) {
        let issued = Arc::new(Mutex::new(0_u32));
        let exchanged = Arc::new(Mutex::new(0_u32));
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
                post(move || {
                    let exchanged = Arc::clone(&exchanged);
                    async move {
                        let number = {
                            let mut exchanged = exchanged.lock().unwrap();
                            *exchanged += 1;
                            *exchanged
                        };
                        let lifetime = match exchange {
                            Exchange::ThenAnswers(_, status) if number > 1 => {
                                let status = axum::http::StatusCode::from_u16(status).unwrap();
                                return (status, Json(json!({ "detail": "refused" })))
                                    .into_response();
                            }
                            Exchange::Grants(lifetime) | Exchange::ThenAnswers(lifetime, _) => {
                                lifetime
                            }
                        };
                        let now = i64::try_from(device::now()).unwrap();
                        Json(json!({
                            "organization_id": ORG,
                            "repository_id": REPOSITORY,
                            "token": format!("plj_job-{number}"),
                            "expires_at": rfc3339(now + lifetime),
                        }))
                        .into_response()
                    }
                }),
            )
            .route(
                "/api/v1/ci/github-actions/review",
                post(move || async move {
                    if matches!(grant, Grant::Refused) {
                        return (
                            axum::http::StatusCode::FORBIDDEN,
                            Json(json!({ "detail": "automatic reviews are paused" })),
                        )
                            .into_response();
                    }
                    Json(json!({
                        "review_id": REQUESTED,
                        "run_number": 1,
                        "existing": false,
                        "automatic_reviews_paused": false,
                    }))
                    .into_response()
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
                get(move || async move {
                    let status = match grant {
                        Grant::StaysRunning => "RUNNING",
                        Grant::Completes | Grant::Refused => "COMPLETED",
                    };
                    Json(json!({
                        "id": REQUESTED,
                        "kind": "PULL_REQUEST",
                        "status": status,
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
            let (origin, received) = console(start, Grant::Completes, HOURLY).await;
            let http = Http::new(Origin::parse(&origin).unwrap()).unwrap();
            let issuer = github_actions::Issuer::new(
                format!("{origin}/github/token").parse().unwrap(),
                SecretString::from("runner-secret"),
            );
            let args = CiReviewArgs {
                commit: None,
                sarif: None,
                annotations: false,
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

    /// Runs a `pull_request` job on its own identity with a three-minute
    /// timeout against a console that answers its request as `grant` says
    /// and its exchanges as `exchange` says, on a paused clock.
    async fn pull_request_job(
        grant: Grant,
        exchange: Exchange,
    ) -> (anyhow::Result<Verdict>, Vec<Received>) {
        // As in the test above, a 10 ms ticker bounds each jump of the clock.
        let ticker = tokio::spawn(async {
            for _ in 0..1_000_000 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let start = tokio::time::Instant::now();
        let (origin, received) = console(start, grant, exchange).await;
        let http = Http::new(Origin::parse(&origin).unwrap()).unwrap();
        let issuer = github_actions::Issuer::new(
            format!("{origin}/github/token").parse().unwrap(),
            SecretString::from("runner-secret"),
        );
        let args = CiReviewArgs {
            commit: None,
            sarif: None,
            annotations: false,
            json: false,
            timeout: 3,
            fail_on: None,
            repository: RepositoryArgs {
                repo: Some("acme/app".to_owned()),
                remote: "origin".to_owned(),
            },
        };
        let verdict = ci_job(http, None, Some(issuer), "pull_request", None, &args, HEAD).await;
        ticker.abort();
        let received = received.lock().unwrap().clone();
        (verdict, received)
    }

    fn review_requests(received: &[Received]) -> usize {
        received
            .iter()
            .filter(|(request, ..)| request == "POST /api/v1/ci/github-actions/review")
            .count()
    }

    /// A refusal is reported and the job keeps waiting without asking again,
    /// so it ends at its deadline with no review, which is never a pass.
    #[tokio::test(start_paused = true)]
    async fn a_refused_request_is_asked_once_and_the_wait_runs_to_the_deadline() {
        let (verdict, received) = pull_request_job(Grant::Refused, HOURLY).await;
        assert_eq!(verdict.unwrap(), Verdict::Unavailable);
        assert_eq!(review_requests(&received), 1, "{received:?}");
        let last = received.iter().map(|(_, at, ..)| *at).max().unwrap();
        assert!(last >= Duration::from_secs(180), "{last:?}");
    }

    /// The requested review is read until the deadline; a review that is
    /// still running then has no result, which is never a pass.
    #[tokio::test(start_paused = true)]
    async fn a_review_still_running_at_the_deadline_is_unavailable() {
        let (verdict, received) = pull_request_job(Grant::StaysRunning, HOURLY).await;
        assert_eq!(verdict.unwrap(), Verdict::Unavailable);
        assert_eq!(review_requests(&received), 1, "{received:?}");
        let read = format!("GET /api/v1/organizations/{ORG}/reviews/{REQUESTED}");
        let last_read = received
            .iter()
            .filter(|(request, ..)| *request == read)
            .map(|(_, at, ..)| *at)
            .max()
            .unwrap();
        assert!(last_read >= Duration::from_secs(180), "{last_read:?}");
    }

    /// A credential granted for 100 seconds is renewed at the first read past
    /// half its lifetime, with a newly issued identity, so the wait reads under the first and
    /// completes under the second, and the job still asks for one review. A
    /// renewal the console refuses ends the same wait before it asks, as a
    /// failure (exit 1); one it cannot serve ends it as unavailable (exit 4).
    #[tokio::test(start_paused = true)]
    async fn a_wait_renews_its_credential_and_a_refused_renewal_ends_it() {
        let reviews = format!("GET /api/v1/organizations/{ORG}/reviews");
        let requested = format!("GET /api/v1/organizations/{ORG}/reviews/{REQUESTED}");
        let exchanges = "POST /api/v1/ci/github-actions/credentials";
        let (verdict, received) = pull_request_job(Grant::Completes, Exchange::Grants(100)).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        let at = |path: &str| -> Vec<(Duration, &str)> {
            received
                .iter()
                .filter(|(request, ..)| request == path)
                .map(|(_, at, bearer, _)| (*at, bearer.as_str()))
                .collect()
        };
        let renewals = at(exchanges);
        assert_eq!(renewals.len(), 2, "{received:?}");
        // Each exchange spends its own runner identity; the review request
        // between them has the third.
        assert_eq!(renewals[0].1, "Bearer job-identity-1");
        assert_eq!(renewals[1].1, "Bearer job-identity-2");
        assert!(renewals[1].0 >= Duration::from_secs(50), "{renewals:?}");
        let listed = at(&reviews);
        assert_eq!(listed[0].1, "Bearer plj_job-1", "{listed:?}");
        assert!(listed.iter().all(|(when, bearer)| {
            *bearer
                == if *when < renewals[1].0 {
                    "Bearer plj_job-1"
                } else {
                    "Bearer plj_job-2"
                }
        }));
        let completed = at(&requested);
        assert_eq!(completed.last().unwrap().1, "Bearer plj_job-2");
        assert_eq!(review_requests(&received), 1, "{received:?}");

        for (status, exit_four) in [(403, false), (503, true)] {
            let (verdict, received) =
                pull_request_job(Grant::Completes, Exchange::ThenAnswers(100, status)).await;
            let error = verdict.unwrap_err();
            assert_eq!(unavailable(&error), exit_four, "{status}: {error:#}");
            assert_eq!(review_requests(&received), 0, "{status}: {received:?}");
            let last = received.iter().map(|(_, at, ..)| *at).max().unwrap();
            assert!(last < REQUEST_AFTER, "{status}: {last:?}");
        }
    }

    #[test]
    fn the_wait_wakes_for_a_pending_request_and_never_sleeps_past_the_deadline() {
        let now = tokio::time::Instant::now();
        let at = |seconds| now + Duration::from_secs(seconds);
        let seconds = Duration::from_secs;
        // The delay, when the deadline and the request time are both later.
        assert_eq!(next_pause(20, now, at(100), Some(at(50))), seconds(20));
        // The request time, when it is sooner than the delay.
        assert_eq!(next_pause(20, now, at(100), Some(at(5))), seconds(5));
        // The deadline, when it is sooner than the delay and the request time.
        assert_eq!(next_pause(20, now, at(3), Some(at(5))), seconds(3));
        // With no request pending, only the deadline cuts the delay short.
        assert_eq!(next_pause(20, now, at(100), None), seconds(20));
        assert_eq!(next_pause(20, now, at(10), None), seconds(10));
        // A deadline already passed allows no sleep.
        assert_eq!(next_pause(20, at(10), at(3), None), Duration::ZERO);
    }

    #[test]
    fn review_fail_on_measures_pull_requests_by_open_items_and_others_by_findings() {
        let detail = |kind: &str, open_items: serde_json::Value| -> ReviewDetail {
            serde_json::from_value(json!({
                "id": "0190f3a0-0000-7000-8000-000000000033",
                "kind": kind,
                "status": "COMPLETED",
                "assessment_count": 1,
                "assessments": [{
                    "id": "0190f3a0-0000-7000-8000-000000000033",
                    "environment_display_name": "production",
                    "status": "COMPLETED",
                    "findings": [{
                        "id": "0190f3a0-0000-7000-8000-000000000044",
                        "finding_fingerprint": null,
                        "severity": "SERIOUS",
                        "risk_domain": "resource_capacity",
                        "claim": "The pool outgrows the connection limit.",
                        "impact": "Connections are refused during the rollout.",
                        "lifecycle_state": "NEW",
                        "remediation": null,
                        "evidence_refs": [],
                    }],
                    "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
                    "incompleteness_kind": null,
                    "reason_codes": null,
                    "release_evidence_gap": null,
                }],
                "code_assessment": null,
                "base_commit_sha": "b".repeat(40),
                "head_commit_sha": "c".repeat(40),
                "open_items": open_items,
                "pull_request_number": null,
                "repository_full_name": "acme/app",
                "run_number": null,
            }))
            .unwrap()
        };
        let (warning, serious) = (Some(Severity::Warning), Some(Severity::Serious));
        for kind in ["PATCH", "COMMIT", "FILES"] {
            let review = detail(kind, serde_json::Value::Null);
            assert_eq!(
                review_verdict(&review, serious),
                Verdict::ThresholdReached,
                "{kind}"
            );
            assert_eq!(
                review_verdict(&review, warning),
                Verdict::ThresholdReached,
                "{kind}"
            );
            assert_eq!(review_verdict(&review, None), Verdict::Done, "{kind}");
        }
        // The finding was dismissed.
        let dismissed = detail(
            "PULL_REQUEST",
            json!({ "open_findings": 0, "serious_findings": 0 }),
        );
        assert_eq!(review_verdict(&dismissed, serious), Verdict::Done);
        let open = detail(
            "PULL_REQUEST",
            json!({ "open_findings": 1, "serious_findings": 1 }),
        );
        assert_eq!(review_verdict(&open, serious), Verdict::ThresholdReached);
        let unmeasured = detail("PULL_REQUEST", serde_json::Value::Null);
        assert_eq!(review_verdict(&unmeasured, serious), Verdict::Unavailable);
        assert_eq!(review_verdict(&unmeasured, None), Verdict::Done);
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
