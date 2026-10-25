//! Uploads customer-produced coverage at an explicit tested commit.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use tokio::io::AsyncReadExt as _;
use uuid::Uuid;

use crate::api::Api;
use crate::model::{CoverageUploadRequest, UploadedReport};

const MAX_BODY_BYTES: usize = 64 << 20;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Upload LCOV, Cobertura, `JaCoCo` or Go reports. Requires coverage:write
    /// on a token restricted to this repository, with live GitHub write access.
    Upload(UploadArgs),
}

#[derive(Debug, Args)]
pub(crate) struct UploadArgs {
    /// Full lowercase 40-character SHA that the reports tested; never a branch.
    #[arg(long, value_name = "SHA")]
    commit: String,
    /// Proofline repository ID receiving the reports.
    #[arg(long, value_name = "UUID")]
    repository_id: Uuid,
    /// Report file. Repeat for up to 50 files with distinct file names.
    #[arg(long = "report", value_name = "FILE", required = true)]
    reports: Vec<PathBuf>,
    /// Print the recorded upload as JSON.
    #[arg(long)]
    json: bool,
}

pub(crate) async fn request(args: &UploadArgs) -> anyhow::Result<CoverageUploadRequest> {
    if args.commit.len() != 40
        || !args
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("--commit must name the full lowercase 40-character SHA the reports tested");
    }
    if args.reports.is_empty() || args.reports.len() > 50 {
        bail!("name between 1 and 50 coverage report files");
    }
    let mut names = BTreeSet::new();
    let mut reports = Vec::with_capacity(args.reports.len());
    let mut remaining = MAX_BODY_BYTES;
    for path in &args.reports {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.contains(['\\', ':']))
            .context("each coverage report needs a UTF-8 file name without a backslash or colon")?;
        if !names.insert(name) {
            bail!("coverage report file names must be distinct: {name:?}");
        }
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("could not open coverage report {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(remaining)? + 1)
            .read_to_end(&mut bytes)
            .await
            .with_context(|| format!("could not read coverage report {}", path.display()))?;
        if bytes.len() > remaining {
            bail!("the coverage upload body is larger than 64 MiB");
        }
        remaining -= bytes.len();
        reports.push(UploadedReport {
            name: name.to_owned(),
            content: String::from_utf8(bytes)
                .with_context(|| format!("coverage report {} is not UTF-8", path.display()))?,
        });
    }
    let request = CoverageUploadRequest {
        tested_sha: args.commit.clone(),
        reports,
    };
    if serde_json::to_vec(&request)?.len() > MAX_BODY_BYTES {
        bail!("the coverage upload body is larger than 64 MiB after JSON encoding");
    }
    Ok(request)
}

pub(crate) async fn upload(
    api: &Api,
    args: &UploadArgs,
    request: &CoverageUploadRequest,
) -> anyhow::Result<()> {
    let result = api
        .upload_coverage_reports(args.repository_id, request)
        .await?;
    let mut stdout = std::io::stdout().lock();
    if args.json {
        writeln!(stdout, "{}", serde_json::to_string(&result)?)?;
    } else {
        writeln!(
            stdout,
            "Coverage report {}: {} of {} instrumented lines covered; tested commit {}.",
            result.report_id,
            result.covered_lines,
            result.instrumented_lines,
            crate::text::terminal_safe(&result.tested_sha),
        )?;
        if !result.created {
            writeln!(stdout, "These reports were already recorded.")?;
        }
    }
    Ok(())
}
