//! Native operations on the existing token API.
use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context as _, bail};
use clap::{Args, ValueEnum};
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
    /// Grouping for finding_outcomes only.
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
        || reply
            .headers
            .get("x-proofline-export-version")
            .and_then(|v| v.to_str().ok())
            != Some("1")
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
