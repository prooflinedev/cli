//! Native operations on the existing token API.
use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::{OutputArgs, OutputFormat, RepositoryArgs, Verdict, api::Api, say, show};

#[derive(Debug, Args)]
pub(crate) struct RerunArgs {
    review_id: Uuid,
    /// Return the new review acknowledgment without polling.
    #[arg(long)]
    no_wait: bool,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
pub(crate) struct HistoryArgs {
    #[arg(long)]
    pub pr: u64,
    #[command(flatten)]
    pub repository: RepositoryArgs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Dataset {
    Reviews,
    #[value(name = "finding_outcomes")]
    FindingOutcomes,
    #[value(name = "finding_validations")]
    FindingValidations,
    Spend,
    Findings,
}

impl Dataset {
    const fn name(self) -> &'static str {
        match self {
            Self::Reviews => "reviews",
            Self::FindingOutcomes => "finding_outcomes",
            Self::FindingValidations => "finding_validations",
            Self::Spend => "spend",
            Self::Findings => "findings",
        }
    }
}

/// Version 2 of the finding datasets adds code-lane rows. Version 1 stays
/// accepted from servers that have not moved to version 2.
const fn versions(dataset: Dataset) -> &'static [&'static str] {
    match dataset {
        Dataset::Findings | Dataset::FindingValidations => &["1", "2"],
        Dataset::Reviews | Dataset::FindingOutcomes | Dataset::Spend => &["1"],
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Csv,
    Ndjson,
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[arg(value_enum)]
    dataset: Dataset,
    /// Inclusive RFC3339 start of a window of at most 31 days.
    #[arg(long)]
    from: String,
    /// Exclusive RFC3339 end of the window.
    #[arg(long)]
    to: String,
    #[arg(long, value_enum, default_value = "ndjson")]
    format: Format,
    /// Opaque continuation from the preceding page; keep the same filters.
    #[arg(long)]
    cursor: Option<String>,
    /// Grouping for `finding_outcomes` only.
    #[arg(long)]
    group_by: Option<String>,
}

pub(crate) fn json(value: &serde_json::Value) -> anyhow::Result<Verdict> {
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(value)?
    )?;
    Ok(Verdict::Done)
}

pub(crate) async fn rerun(api: &Api, args: &RerunArgs) -> anyhow::Result<Verdict> {
    let reply = api.rerun(args.review_id).await?;
    let id: Uuid = reply
        .get("review_id")
        .and_then(serde_json::Value::as_str)
        .context("the rerun response has no review_id")?
        .parse()?;
    if args.no_wait {
        if args.output.json {
            return json(&reply);
        }
        writeln!(std::io::stdout().lock(), "{}", api.review_url(id))?;
        return Ok(Verdict::Done);
    }
    show(
        api,
        id,
        true,
        &args.output,
        OutputFormat::from_json(args.output.json),
        None,
    )
    .await
}

pub(crate) async fn export(api: &Api, args: &ExportArgs) -> anyhow::Result<Verdict> {
    if args.group_by.is_some() && !matches!(args.dataset, Dataset::FindingOutcomes) {
        bail!("--group-by is available only for finding_outcomes");
    }
    let (format, accept) = match args.format {
        Format::Csv => ("csv", "text/csv"),
        Format::Ndjson => ("ndjson", "application/x-ndjson"),
    };
    let mut query = vec![
        ("from", args.from.clone()),
        ("to", args.to.clone()),
        ("format", format.to_owned()),
    ];
    if let Some(cursor) = &args.cursor {
        query.push(("cursor", cursor.clone()));
    }
    if let Some(group) = &args.group_by {
        query.push(("group_by", group.clone()));
    }
    let reply = api.export(args.dataset.name(), &query, accept).await?;
    let content_type = reply
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if content_type.split(';').next().map(str::trim) != Some(accept)
        || !reply
            .headers
            .get("x-proofline-export-version")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|version| versions(args.dataset).contains(&version))
    {
        bail!("the server returned an unsupported export format or version");
    }
    let horizon = reply
        .headers
        .get("x-proofline-export-settled-until")
        .context("the export has no settled horizon")?
        .to_str()?;
    let body = std::str::from_utf8(&reply.body).context("the export is not UTF-8")?;
    let stdout = std::io::stdout();
    if stdout.is_terminal() {
        write!(stdout.lock(), "{}", crate::text::terminal_safe(body))?;
    } else {
        stdout.lock().write_all(&reply.body)?;
    }
    say(&format!(
        "settled-until: {}",
        crate::text::terminal_safe(horizon)
    ));
    if let Some(cursor) = reply.headers.get("x-proofline-export-next-cursor") {
        say(&format!(
            "next-cursor: {}",
            crate::text::terminal_safe(cursor.to_str()?)
        ));
    }
    Ok(Verdict::Done)
}

/// One review status, as the review list filters it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Status {
    Pending,
    Running,
    Completed,
    Incomplete,
    Failed,
    Superseded,
    Stopped,
    Excluded,
}

impl Status {
    pub(crate) const fn query(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Incomplete => "INCOMPLETE",
            Self::Failed => "FAILED",
            Self::Superseded => "SUPERSEDED",
            Self::Stopped => "STOPPED",
            Self::Excluded => "EXCLUDED",
        }
    }
}

/// One review kind, as the review list filters it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Kind {
    PullRequest,
    Deployment,
    Patch,
    Commit,
    Files,
    MergeGroup,
    RevisionScan,
}

impl Kind {
    pub(crate) const fn query(self) -> &'static str {
        match self {
            Self::PullRequest => "PULL_REQUEST",
            Self::Deployment => "DEPLOYMENT",
            Self::Patch => "PATCH",
            Self::Commit => "COMMIT",
            Self::Files => "FILES",
            Self::MergeGroup => "MERGE_GROUP",
            Self::RevisionScan => "REVISION_SCAN",
        }
    }
}

/// Whether a listed review has findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Findings {
    /// Reviews with at least one finding.
    Present,
    /// Reviews with no finding.
    None,
}

impl Findings {
    pub(crate) const fn query(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::None => "none",
        }
    }
}

/// `mine`, or a numeric GitHub user ID.
fn author(value: &str) -> Result<String, String> {
    if value == "mine" || (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())) {
        Ok(value.to_owned())
    } else {
        Err("expected `mine` or a numeric GitHub user ID".to_owned())
    }
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    /// Repository ID to list reviews of.
    #[arg(long)]
    pub repository_id: Option<Uuid>,
    /// GitHub repository as owner/name to list reviews of. Unlike other
    /// commands, it does not default to the checkout's remote: without it,
    /// the list spans the organization.
    #[arg(long, value_name = "OWNER/NAME", conflicts_with = "repository_id")]
    pub repo: Option<String>,
    /// Free-text search.
    #[arg(long)]
    pub search: Option<String>,
    /// Search with qualifiers, quoted values, AND/OR, groups and minus exclusions.
    #[arg(long)]
    pub query: Option<String>,
    /// Only reviews with this status.
    #[arg(long, value_enum)]
    pub status: Option<Status>,
    /// Only reviews of this kind.
    #[arg(long, value_enum)]
    pub kind: Option<Kind>,
    /// `mine` for your own pull requests (needs a person's sign-in or token),
    /// or a numeric GitHub user ID.
    #[arg(long, value_parser = author)]
    pub author: Option<String>,
    /// Only terminal reviews of open pull requests with active findings,
    /// failed, incomplete or stopped execution, or an earlier reviewed commit.
    #[arg(long)]
    pub needs_attention: bool,
    /// Only reviews with findings (`present`) or without (`none`).
    #[arg(long, value_enum)]
    pub findings: Option<Findings>,
    /// Reviews per page.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..))]
    pub limit: u32,
    /// Continuation cursor from a previous page.
    #[arg(long)]
    pub cursor: Option<String>,
}

impl ListArgs {
    /// The server's query for these arguments, with the repository already
    /// resolved to its ID.
    pub(crate) fn filters(&self, repository: Option<Uuid>) -> crate::api::ReviewFilters<'_> {
        crate::api::ReviewFilters {
            repository,
            search: self.search.as_deref(),
            query: self.query.as_deref(),
            status: self.status.map(Status::query),
            kind: self.kind.map(Kind::query),
            author: self.author.as_deref(),
            attention: self.needs_attention,
            findings: self.findings.map(Findings::query),
            limit: self.limit,
            cursor: self.cursor.as_deref(),
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[arg(long)]
    pub pr: u64,
    #[arg(long)]
    pub run: u64,
    #[command(flatten)]
    pub repository: RepositoryArgs,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommand {
    /// Read the protected prompt and eligible vendor connections before starting.
    Prompt { finding_id: Uuid },
    /// Start once with the digest of the prompt you reviewed. Vendor charges apply.
    Start {
        finding_id: Uuid,
        #[arg(long)]
        connection_id: Uuid,
        #[arg(long)]
        prompt_digest: String,
    },
    /// Read the recorded vendor session status.
    Get { session_id: Uuid },
}

pub(crate) async fn session(api: &Api, command: SessionCommand) -> anyhow::Result<Verdict> {
    let value = match command {
        SessionCommand::Prompt { finding_id } => api.get(api.url_get_agent_session_prompt(&finding_id.to_string())).await?,
        SessionCommand::Get { session_id } => api.get(api.url_get_agent_session(&session_id.to_string())).await?,
        SessionCommand::Start { finding_id, connection_id, prompt_digest } => api.tool_post(
            api.url_start_agent_session(&finding_id.to_string()),
            &serde_json::json!({"connection_id": connection_id, "prompt_digest": prompt_digest}),
        ).await?,
    };
    json(&value)
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum as _;
    use serde_json::Value;

    use super::{Findings, Kind, Status, author};

    /// The review list's description of one query parameter.
    fn described(name: &str) -> String {
        let document: Value = serde_json::from_str(include_str!(concat!(
            env!("OUT_DIR"),
            "/openapi.public.json"
        )))
        .unwrap();
        document["paths"]["/api/v1/organizations/{org_id}/reviews"]["get"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == name)
            .unwrap()["description"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn each_filter_value_is_one_the_server_lists() {
        let status = described("status");
        for value in Status::value_variants() {
            assert!(
                status.contains(&format!("`{}`", value.query())),
                "{value:?}"
            );
        }
        let kind = described("kind");
        for value in Kind::value_variants() {
            assert!(kind.contains(&format!("`{}`", value.query())), "{value:?}");
        }
        let findings = described("findings");
        for value in Findings::value_variants() {
            assert!(
                findings.contains(&format!("`{}`", value.query())),
                "{value:?}"
            );
        }
        assert!(described("attention").contains("`needed`"));
        assert!(described("author").contains("`mine`"));
    }

    #[test]
    fn author_is_mine_or_a_github_user_id() {
        assert_eq!(author("mine").unwrap(), "mine");
        assert_eq!(author("583231").unwrap(), "583231");
        for refused in ["", "Mine", "octocat", "12a", "-1"] {
            assert!(author(refused).is_err(), "{refused:?}");
        }
    }
}
