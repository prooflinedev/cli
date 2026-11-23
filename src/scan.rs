//! Requests a whole-repository scan of one ref or commit.
//!
//! A scan spends credits, so the budget has no default, the request carries an
//! identity the caller can reuse, and the CLI never repeats the POST itself.

use std::io::Write as _;

use anyhow::bail;
use clap::Args;
use uuid::Uuid;

use crate::api::{Api, ApiError};
use crate::model::{ScanRequest, ScanResponse};
use crate::{
    OnInterrupt, OutputArgs, OutputFormat, RepositoryArgs, Verdict, git, say, show, text, tools,
};

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    /// Branch, tag or other ref. GitHub resolves it once, when the request
    /// arrives, and the scan records that commit.
    #[arg(
        long = "ref",
        value_name = "REF",
        conflicts_with = "commit",
        required_unless_present = "commit"
    )]
    git_ref: Option<String>,
    /// Exact full SHA to scan; never a branch.
    #[arg(long, value_name = "SHA")]
    commit: Option<String>,
    /// Credits the whole scan may spend. Required, so a scan never spends
    /// without a number you chose. The organization's on-demand limit caps it.
    #[arg(
        long,
        value_name = "CREDITS",
        value_parser = clap::value_parser!(i64).range(1..)
    )]
    budget: i64,
    /// Identity of this request. Repeating it returns the first resolution
    /// instead of scanning again. Omit it to get a fresh one, printed first.
    #[arg(long, value_name = "UUID")]
    request_id: Option<Uuid>,
    /// Return the scan's link without waiting for its result.
    #[arg(long)]
    no_wait: bool,
    #[command(flatten)]
    repository: RepositoryArgs,
    #[command(flatten)]
    output: OutputArgs,
}

/// The request body, checked before anything is sent.
pub(crate) fn request(args: &ScanArgs) -> anyhow::Result<ScanRequest> {
    let commit_sha = args.commit.as_deref().map(git::commit_sha).transpose()?;
    let git_ref = args.git_ref.as_deref().map(str::trim).map(str::to_owned);
    if git_ref.as_deref() == Some("") {
        bail!("--ref is empty; name a branch, a tag or another ref");
    }
    Ok(ScanRequest {
        request_id: args.request_id.unwrap_or_else(Uuid::now_v7),
        budget_credits: args.budget,
        git_ref,
        commit_sha,
    })
}

const SCAN_SIGN_IN: &str = "this sign-in cannot request scans; run `proofline login --scope reviews:read --scope findings:read --scope reviews:request --scope scans:request`, and have the token's repositories include this one";

pub(crate) async fn run(
    api: &Api,
    args: &ScanArgs,
    request: &ScanRequest,
) -> anyhow::Result<Verdict> {
    let (name, repository_id) = match crate::scannable_repository(api, &args.repository).await {
        Err(error) if error.downcast_ref::<ApiError>().and_then(ApiError::status) == Some(403) => {
            return Err(error.context(SCAN_SIGN_IN));
        }
        resolved => resolved?,
    };
    let name = text::terminal_safe(&name);
    let target = request
        .commit_sha
        .as_deref()
        .or(request.git_ref.as_deref())
        .map(text::terminal_safe)
        .unwrap_or_default();
    // Said before the request, so a timeout still leaves the caller an
    // identity that cannot start a second scan.
    say(&format!(
        "Requesting a scan of {name} at {target} with a budget of {} credits (request {}).",
        request.budget_credits, request.request_id
    ));
    let response = match api.request_scan(repository_id, request).await {
        Ok(response) => response,
        Err(error) if error.status() == Some(403) => {
            return Err(anyhow::Error::new(error).context(SCAN_SIGN_IN));
        }
        // The scan may have started, so the caller gets the one retry that
        // cannot start a second one, and an exit code that says "unknown".
        Err(error) if uncertain(&error) => {
            say(&format!("proofline: {error}"));
            say(&format!(
                "The scan may have started. Repeat with --request-id {} to read its first resolution instead of starting a second scan.",
                request.request_id
            ));
            return Ok(Verdict::Unavailable);
        }
        // A definite refusal created nothing; the server's reason is enough.
        Err(error) => return Err(error.into()),
    };
    if args.output.json && response.review_id.is_none() {
        // Scripts read the resolution from stdout even when no scan started.
        tools::json(&serde_json::to_value(&response)?)?;
    }
    let review_id = resolved(&response, request)?;
    say(&format!(
        "{} scan, resolution {}.",
        if response.outcome == "EXISTING" {
            "Found the existing"
        } else {
            "Started a"
        },
        response.resolution_id
    ));
    if args.no_wait {
        return link(api, args, &response, review_id);
    }
    match show(
        api,
        review_id,
        true,
        &args.output,
        OutputFormat::from_json(args.output.json),
        None,
        OnInterrupt::Detach,
    )
    .await
    {
        // A sign-in that may request scans need not read reviews. The scan
        // has started, so the caller gets its link instead of an error.
        Err(error) if error.downcast_ref::<ApiError>().and_then(ApiError::status) == Some(403) => {
            say(
                "This sign-in cannot read reviews, so the CLI does not wait for the result; open the scan's link instead.",
            );
            link(api, args, &response, review_id)
        }
        verdict => verdict,
    }
}

/// The started scan's link, as `--no-wait` prints it.
fn link(
    api: &Api,
    args: &ScanArgs,
    response: &ScanResponse,
    review_id: Uuid,
) -> anyhow::Result<Verdict> {
    let url = api.review_url(review_id);
    if args.output.json {
        return tools::json(&serde_json::json!({
            "outcome": response.outcome,
            "resolution_id": response.resolution_id,
            "review_id": review_id,
            "review_url": url.as_str(),
        }));
    }
    writeln!(std::io::stdout().lock(), "{url}")?;
    Ok(Verdict::Done)
}

/// Whether a failed request leaves its outcome unknown: the server may have
/// recorded it before the connection, its body or its answer failed.
const fn uncertain(error: &ApiError) -> bool {
    match error {
        ApiError::Transport { .. } | ApiError::Protocol { .. } => true,
        ApiError::Problem { status, .. } => *status >= 500,
        // A renewal fails before its request is sent.
        ApiError::Renewal { .. } => false,
    }
}

/// The scan's review, or the reason there is none.
fn resolved(response: &ScanResponse, request: &ScanRequest) -> anyhow::Result<Uuid> {
    match (response.outcome.as_str(), response.review_id) {
        ("CREATED" | "EXISTING", Some(review_id)) => Ok(review_id),
        ("CREATED" | "EXISTING", None) => bail!(
            "the server reported a scan but named no review for resolution {}",
            response.resolution_id
        ),
        ("REPOSITORY_UNAVAILABLE", _) => bail!(
            "GitHub could not resolve the request, so no scan started and nothing was spent (resolution {}). Repeating request {} returns this same answer; omit --request-id to ask again",
            response.resolution_id,
            request.request_id
        ),
        (other, _) => bail!(
            "the server answered with the unknown scan outcome {}; update this CLI with `proofline update`",
            text::one_line(other)
        ),
    }
}
