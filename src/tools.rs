//! Native operations on the existing token API.
use std::collections::HashMap;
use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand, ValueEnum};
use url::Url;
use uuid::Uuid;

use crate::model::{Finding, ReviewDetail};
use crate::outcome::{self, Outcome};
use crate::severity::Severity;
use crate::text::one_line;
use crate::{OutputArgs, OutputFormat, RepositoryArgs, Verdict, api::Api, render, say, show};

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

#[derive(Debug, Args)]
pub(crate) struct DiffArgs {
    #[arg(long)]
    pub pr: u64,
    #[command(flatten)]
    pub repository: RepositoryArgs,
    #[command(flatten)]
    pub output: DiffOutput,
}

#[derive(Debug, Args)]
pub(crate) struct DiffOutput {
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy)]
enum Lane {
    Environment,
    Code,
}

impl Lane {
    const fn name(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Code => "CODE",
        }
    }
}

#[derive(Debug)]
struct LaneFindings<'a> {
    previous: Vec<&'a Finding>,
    current: Vec<&'a Finding>,
}

#[derive(Debug)]
struct LaneState<'a> {
    lane: Lane,
    findings: LaneFindings<'a>,
    reasons: Vec<String>,
}

#[derive(Debug)]
struct Uncomparable<'a> {
    lane: Lane,
    reasons: Vec<String>,
    findings: Vec<(u64, &'a Finding)>,
}

#[derive(Debug, Default)]
struct Classification<'a> {
    new: Vec<&'a Finding>,
    resolved: Vec<&'a Finding>,
    persisting: Vec<(&'a Finding, &'a Finding)>,
    uncorrelated: Vec<(u64, &'a Finding)>,
}

#[derive(Debug)]
struct FindingsDiff<'a> {
    previous_run: u64,
    current_run: u64,
    previous_status: Outcome,
    current_status: Outcome,
    new: Vec<&'a Finding>,
    resolved: Vec<&'a Finding>,
    persisting: Vec<(&'a Finding, &'a Finding)>,
    uncorrelated: Vec<(u64, &'a Finding)>,
    uncomparable: Vec<Uncomparable<'a>>,
}

fn environment_findings(review: &ReviewDetail) -> Vec<&Finding> {
    review
        .assessments
        .iter()
        .flat_map(|assessment| assessment.findings.iter())
        .collect()
}

fn code_findings(review: &ReviewDetail) -> Vec<&Finding> {
    outcome::code_assessment(review)
        .map(|code| code.findings.iter().collect())
        .unwrap_or_default()
}

fn split_fingerprints(findings: Vec<&Finding>) -> (HashMap<&str, &Finding>, Vec<&Finding>) {
    let mut fingerprinted = HashMap::new();
    let mut uncorrelated = Vec::new();
    for finding in findings {
        match finding.finding_fingerprint.as_deref() {
            Some(fingerprint) => {
                fingerprinted.entry(fingerprint).or_insert(finding);
            }
            None => uncorrelated.push(finding),
        }
    }
    (fingerprinted, uncorrelated)
}

fn compare_findings(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    Severity::parse(&b.severity)
        .cmp(&Severity::parse(&a.severity))
        .then_with(|| a.claim.cmp(&b.claim))
        .then_with(|| a.id.cmp(&b.id))
}

fn sort_by_severity(findings: &mut [&Finding]) {
    findings.sort_by(|a, b| compare_findings(a, b));
}

fn sort_tagged(findings: &mut [(u64, &Finding)]) {
    findings
        .sort_by(|(a_run, a), (b_run, b)| a_run.cmp(b_run).then_with(|| compare_findings(a, b)));
}

fn classify_lane<'a>(
    findings: LaneFindings<'a>,
    previous_run: u64,
    current_run: u64,
) -> Classification<'a> {
    let (previous_by_fingerprint, previous_uncorrelated) = split_fingerprints(findings.previous);
    let (current_by_fingerprint, current_uncorrelated) = split_fingerprints(findings.current);

    let mut new = Vec::new();
    let mut persisting = Vec::new();
    for (fingerprint, finding) in &current_by_fingerprint {
        match previous_by_fingerprint.get(*fingerprint) {
            Some(before) => persisting.push((*before, *finding)),
            None => new.push(*finding),
        }
    }

    let mut resolved = Vec::new();
    for (fingerprint, finding) in &previous_by_fingerprint {
        if !current_by_fingerprint.contains_key(*fingerprint) {
            resolved.push(*finding);
        }
    }

    let mut uncorrelated: Vec<(u64, &Finding)> = previous_uncorrelated
        .into_iter()
        .map(|finding| (previous_run, finding))
        .chain(
            current_uncorrelated
                .into_iter()
                .map(|finding| (current_run, finding)),
        )
        .collect();

    sort_by_severity(&mut new);
    sort_by_severity(&mut resolved);
    persisting.sort_by(|(_, a), (_, b)| compare_findings(a, b));
    sort_tagged(&mut uncorrelated);

    Classification {
        new,
        resolved,
        persisting,
        uncorrelated,
    }
}

fn environment_lane<'a>(
    previous_run: u64,
    previous: &'a ReviewDetail,
    current_run: u64,
    current: &'a ReviewDetail,
) -> Option<LaneState<'a>> {
    let previous_present = previous.assessment_count > 0 || !previous.assessments.is_empty();
    let current_present = current.assessment_count > 0 || !current.assessments.is_empty();
    if !previous_present && !current_present {
        return None;
    }
    let mut reasons = Vec::new();
    if previous_present != current_present {
        let missing = if previous_present {
            current_run
        } else {
            previous_run
        };
        reasons.push(format!("run {missing} has no environment assessment"));
    }
    if previous_present {
        environment_reasons(previous_run, previous, &mut reasons);
    }
    if current_present {
        environment_reasons(current_run, current, &mut reasons);
    }
    Some(LaneState {
        lane: Lane::Environment,
        findings: LaneFindings {
            previous: environment_findings(previous),
            current: environment_findings(current),
        },
        reasons,
    })
}

fn environment_reasons(run: u64, review: &ReviewDetail, reasons: &mut Vec<String>) {
    match review.status.as_str() {
        "COMPLETED" | "INCOMPLETE" => {}
        status => reasons.push(format!("run {run} is {}", one_line(status))),
    }
    if usize::try_from(review.assessment_count).ok() != Some(review.assessments.len()) {
        reasons.push(format!(
            "run {run} has not recorded every environment assessment"
        ));
    }
    for assessment in &review.assessments {
        if let Some(gaps) = outcome::gap(assessment) {
            reasons.push(format!(
                "run {run} environment {} is incomplete: {}",
                one_line(&assessment.environment_display_name),
                one_line(&gaps.join(", "))
            ));
        }
    }
}

fn code_lane<'a>(
    previous_run: u64,
    previous: &'a ReviewDetail,
    current_run: u64,
    current: &'a ReviewDetail,
) -> Option<LaneState<'a>> {
    let previous_present = previous.code_assessment.is_some();
    let current_present = current.code_assessment.is_some();
    if !previous_present && !current_present {
        return None;
    }
    let mut reasons = Vec::new();
    if previous_present != current_present {
        let missing = if previous_present {
            current_run
        } else {
            previous_run
        };
        reasons.push(format!("run {missing} has no CODE assessment"));
    }
    if previous_present {
        code_reasons(previous_run, previous, &mut reasons);
    }
    if current_present {
        code_reasons(current_run, current, &mut reasons);
    }
    Some(LaneState {
        lane: Lane::Code,
        findings: LaneFindings {
            previous: code_findings(previous),
            current: code_findings(current),
        },
        reasons,
    })
}

fn code_reasons(run: u64, review: &ReviewDetail, reasons: &mut Vec<String>) {
    match review.status.as_str() {
        "COMPLETED" | "INCOMPLETE" => {}
        status => reasons.push(format!("run {run} is {}", one_line(status))),
    }
    if matches!(review.status.as_str(), "FAILED" | "STOPPED") {
        return;
    }
    match outcome::code_assessment(review) {
        None => reasons.push(format!("run {run} CODE result is unavailable")),
        Some(code) => {
            if let Some(gap) = outcome::code_gap(code) {
                reasons.push(format!("run {run} CODE is incomplete: {}", one_line(gap)));
            }
        }
    }
}

fn compare<'a>(
    previous_run: u64,
    previous: &'a ReviewDetail,
    previous_status: Outcome,
    current_run: u64,
    current: &'a ReviewDetail,
    current_status: Outcome,
) -> FindingsDiff<'a> {
    let mut diff = FindingsDiff {
        previous_run,
        current_run,
        previous_status,
        current_status,
        new: Vec::new(),
        resolved: Vec::new(),
        persisting: Vec::new(),
        uncorrelated: Vec::new(),
        uncomparable: Vec::new(),
    };

    for lane in [
        environment_lane(previous_run, previous, current_run, current),
        code_lane(previous_run, previous, current_run, current),
    ]
    .into_iter()
    .flatten()
    {
        if lane.reasons.is_empty() {
            let classified = classify_lane(lane.findings, previous_run, current_run);
            diff.new.extend(classified.new);
            diff.resolved.extend(classified.resolved);
            diff.persisting.extend(classified.persisting);
            diff.uncorrelated.extend(classified.uncorrelated);
        } else {
            let mut findings: Vec<(u64, &Finding)> = lane
                .findings
                .previous
                .into_iter()
                .map(|finding| (previous_run, finding))
                .chain(
                    lane.findings
                        .current
                        .into_iter()
                        .map(|finding| (current_run, finding)),
                )
                .collect();
            sort_tagged(&mut findings);
            diff.uncomparable.push(Uncomparable {
                lane: lane.lane,
                reasons: lane.reasons,
                findings,
            });
        }
    }

    sort_by_severity(&mut diff.new);
    sort_by_severity(&mut diff.resolved);
    diff.persisting
        .sort_by(|(_, a), (_, b)| compare_findings(a, b));
    sort_tagged(&mut diff.uncorrelated);
    diff
}

fn write_finding(out: &mut Vec<String>, run: Option<u64>, finding: &Finding) {
    let tag = run.map_or_else(String::new, |run| format!("run {run}  "));
    out.push(format!(
        "  {tag}{:<8} {}  {}",
        one_line(&finding.severity),
        one_line(&finding.risk_domain),
        one_line(&finding.claim)
    ));
    for place in render::location(finding) {
        out.push(format!("           at {place}"));
    }
}

fn text(
    name: &str,
    number: u64,
    diff: &FindingsDiff<'_>,
    previous_url: &Url,
    current_url: &Url,
) -> String {
    let mut out = vec![
        format!(
            "{} #{number}: run {} (previous, {}) vs run {} (latest, {})",
            one_line(name),
            diff.previous_run,
            diff.previous_status.as_str(),
            diff.current_run,
            diff.current_status.as_str()
        ),
        format!("  run {}: {previous_url}", diff.previous_run),
        format!("  run {}: {current_url}", diff.current_run),
    ];

    if !diff.uncomparable.is_empty() {
        out.push(String::new());
        out.push("Not comparable:".to_owned());
        for lane in &diff.uncomparable {
            out.push(format!("  {}:", lane.lane.name()));
            for reason in &lane.reasons {
                out.push(format!("    {reason}"));
            }
            for (run, finding) in &lane.findings {
                write_finding(&mut out, Some(*run), finding);
            }
        }
    }

    out.push(String::new());
    out.push(format!("New ({}):", diff.new.len()));
    for finding in &diff.new {
        write_finding(&mut out, None, finding);
    }

    out.push(String::new());
    out.push(format!("Resolved ({}):", diff.resolved.len()));
    for finding in &diff.resolved {
        write_finding(&mut out, None, finding);
    }

    out.push(String::new());
    out.push(format!("Persisting ({}):", diff.persisting.len()));
    for (before, after) in &diff.persisting {
        write_finding(&mut out, None, after);
        if before.severity != after.severity {
            out.push(format!("           was {}", one_line(&before.severity)));
        }
    }

    out.push(String::new());
    out.push(format!("Uncorrelated ({}):", diff.uncorrelated.len()));
    for (run, finding) in &diff.uncorrelated {
        write_finding(&mut out, Some(*run), finding);
    }

    out.push(String::new());
    out.join("\n")
}

fn diff_json(name: &str, number: u64, diff: &FindingsDiff<'_>) -> serde_json::Value {
    let new: Vec<_> = diff
        .new
        .iter()
        .map(|finding| serde_json::json!(finding))
        .collect();
    let resolved: Vec<_> = diff
        .resolved
        .iter()
        .map(|finding| serde_json::json!(finding))
        .collect();
    let persisting: Vec<_> = diff
        .persisting
        .iter()
        .map(|(before, after)| serde_json::json!({"before": before, "after": after}))
        .collect();
    let uncorrelated: Vec<_> = diff
        .uncorrelated
        .iter()
        .map(|(run, finding)| serde_json::json!({"run": run, "finding": finding}))
        .collect();
    let not_comparable: Vec<_> = diff
        .uncomparable
        .iter()
        .map(|lane| {
            let findings: Vec<_> = lane
                .findings
                .iter()
                .map(|(run, finding)| serde_json::json!({"run": run, "finding": finding}))
                .collect();
            serde_json::json!({
                "lane": lane.lane.name(),
                "reasons": lane.reasons,
                "findings": findings,
            })
        })
        .collect();

    serde_json::json!({
        "repository": name,
        "pull_request": number,
        "from": diff.previous_run,
        "to": diff.current_run,
        "from_status": diff.previous_status.as_str(),
        "to_status": diff.current_status.as_str(),
        "new": new,
        "resolved": resolved,
        "persisting": persisting,
        "uncorrelated": uncorrelated,
        "not_comparable": not_comparable,
    })
}

pub(crate) async fn diff(api: &Api, args: &DiffArgs) -> anyhow::Result<Verdict> {
    let name = crate::repository_name(&args.repository).await?;
    let mut runs = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..crate::SEARCH_PAGES {
        let page = api
            .pull_request_history(&name, args.pr, cursor.as_deref())
            .await?;
        runs.extend(
            page.items
                .iter()
                .filter_map(|item| item.run_number)
                .filter_map(|run| u64::try_from(run).ok()),
        );
        runs.sort_unstable();
        runs.dedup();
        if !page.truncated {
            break;
        }
        match page.next_cursor {
            Some(next) if cursor.as_deref() != Some(&next) => cursor = Some(next),
            _ => break,
        }
    }
    let Some((&current_run, earlier)) = runs.split_last() else {
        bail!(
            "{} #{} has no recorded runs to compare",
            one_line(&name),
            args.pr
        );
    };
    let Some(&previous_run) = earlier.last() else {
        bail!(
            "{} #{} has only run {current_run}; a diff needs two runs",
            one_line(&name),
            args.pr
        );
    };
    let previous = api.pull_request_run(&name, args.pr, previous_run).await?;
    let current = api.pull_request_run(&name, args.pr, current_run).await?;
    let Some(previous_status) = outcome::terminal(&previous) else {
        bail!(
            "{} #{} run {previous_run} has not finished",
            one_line(&name),
            args.pr
        );
    };
    let Some(current_status) = outcome::terminal(&current) else {
        bail!(
            "{} #{} run {current_run} has not finished",
            one_line(&name),
            args.pr
        );
    };
    let diff = compare(
        previous_run,
        &previous,
        previous_status,
        current_run,
        &current,
        current_status,
    );

    let mut stdout = std::io::stdout().lock();
    if args.output.json {
        writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&diff_json(&name, args.pr, &diff))?
        )?;
    } else {
        let previous_url = api.review_url(previous.id);
        let current_url = api.review_url(current.id);
        writeln!(
            stdout,
            "{}",
            text(&name, args.pr, &diff, &previous_url, &current_url)
        )?;
    }

    if previous_status == Outcome::Completed
        && current_status == Outcome::Completed
        && diff.uncomparable.is_empty()
    {
        Ok(Verdict::Done)
    } else {
        Ok(Verdict::NotComplete)
    }
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

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    #[arg(long)]
    pub repository_id: Option<Uuid>,
    #[arg(long)]
    pub search: Option<String>,
    #[arg(long)]
    pub cursor: Option<String>,
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
        SessionCommand::Prompt { finding_id } => api.tool_get(&["findings", &finding_id.to_string(), "agent-session-prompt"]).await?,
        SessionCommand::Get { session_id } => api.tool_get(&["agent-sessions", &session_id.to_string()]).await?,
        SessionCommand::Start { finding_id, connection_id, prompt_digest } => api.tool_post(
            &["findings", &finding_id.to_string(), "agent-sessions"],
            &serde_json::json!({"connection_id": connection_id, "prompt_digest": prompt_digest}),
        ).await?,
    };
    json(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Assessment, Checks, CodeAssessment, CodeAssessmentRead, CodeAssessmentStatus,
    };

    fn review_with(status: &str, assessment_status: &str, findings: Vec<Finding>) -> ReviewDetail {
        ReviewDetail {
            id: Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: status.to_owned(),
            assessment_count: 1,
            assessments: vec![Assessment {
                id: Uuid::nil(),
                environment_display_name: "production".to_owned(),
                status: assessment_status.to_owned(),
                findings,
                checks: Checks {
                    receipt_recorded: true,
                    status: "READY".to_owned(),
                    families: Vec::new(),
                },
                incompleteness_kind: (assessment_status != "COMPLETED")
                    .then(|| "WORLD_UNAVAILABLE".to_owned()),
                reason_codes: None,
                release_evidence_gap: None,
            }],
            code_assessment: None,
            base_commit_sha: None,
            head_commit_sha: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            open_items: None,
            pull_request_number: Some(42),
            repository_full_name: Some("acme/app".to_owned()),
            run_number: Some(1),
            subjects: Vec::new(),
            local_reverifications: Vec::new(),
        }
    }

    fn review(findings: Vec<Finding>) -> ReviewDetail {
        review_with("COMPLETED", "COMPLETED", findings)
    }

    fn code_review(finding: Finding) -> ReviewDetail {
        let mut review = review_with("COMPLETED", "COMPLETED", Vec::new());
        let base = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let head = "89abcdef0123456789abcdef0123456789abcdef".to_owned();
        review.assessment_count = 0;
        review.assessments = Vec::new();
        review.base_commit_sha = Some(base.clone());
        review.head_commit_sha = Some(head.clone());
        review.code_assessment = Some(CodeAssessmentRead::Recorded(CodeAssessment {
            id: Uuid::nil(),
            status: CodeAssessmentStatus::Completed,
            base_commit_sha: base,
            head_commit_sha: head,
            findings: vec![finding],
            incompleteness_kind: None,
        }));
        review
    }

    fn finding(severity: &str, fingerprint: Option<&str>, claim: &str) -> Finding {
        Finding {
            id: Uuid::nil(),
            finding_fingerprint: fingerprint.map(str::to_owned),
            severity: severity.to_owned(),
            risk_domain: "data_integrity".to_owned(),
            claim: claim.to_owned(),
            impact: "orders are lost".to_owned(),
            lifecycle_state: "ACTIVE".to_owned(),
            remediation: None,
            evidence_refs: Vec::new(),
        }
    }

    fn url(run: u64) -> Url {
        Url::parse(&format!(
            "https://proofline.sh/orgs/by-id/o/reviews/run-{run}"
        ))
        .unwrap()
    }

    #[test]
    fn fingerprints_sort_findings_into_new_resolved_persisting_and_uncorrelated() {
        let previous = review(vec![
            finding("WARNING", Some("keep"), "still there"),
            finding("SERIOUS", Some("fixed"), "was fixed"),
            finding("WARNING", None, "previous unknown"),
        ]);
        let current = review(vec![
            finding("SERIOUS", Some("keep"), "still there"),
            finding("WARNING", Some("new"), "brand new"),
            finding("NOTE", None, "current unknown"),
        ]);

        let diff = compare(
            2,
            &previous,
            Outcome::Completed,
            3,
            &current,
            Outcome::Completed,
        );

        assert_eq!(
            diff.new
                .iter()
                .map(|f| f.claim.as_str())
                .collect::<Vec<_>>(),
            ["brand new"]
        );
        assert_eq!(
            diff.resolved
                .iter()
                .map(|f| f.claim.as_str())
                .collect::<Vec<_>>(),
            ["was fixed"]
        );
        assert_eq!(diff.persisting.len(), 1);
        assert_eq!(diff.persisting[0].0.severity, "WARNING");
        assert_eq!(diff.persisting[0].1.severity, "SERIOUS");
        assert_eq!(
            diff.uncorrelated
                .iter()
                .map(|(run, f)| (*run, f.claim.as_str()))
                .collect::<Vec<_>>(),
            [(2, "previous unknown"), (3, "current unknown")]
        );
    }

    #[test]
    fn an_incomplete_environment_is_not_compared() {
        let previous = review(vec![finding("SERIOUS", Some("keep"), "still there")]);
        let current = review_with("INCOMPLETE", "INCOMPLETE", Vec::new());

        let diff = compare(
            2,
            &previous,
            Outcome::Completed,
            3,
            &current,
            Outcome::Incomplete,
        );

        assert!(diff.resolved.is_empty());
        assert_eq!(diff.uncomparable.len(), 1);
        assert!(matches!(diff.uncomparable[0].lane, Lane::Environment));
        assert_eq!(
            diff.uncomparable[0]
                .findings
                .iter()
                .map(|(run, finding)| (*run, finding.claim.as_str()))
                .collect::<Vec<_>>(),
            [(2, "still there")]
        );
    }

    #[test]
    fn a_missing_code_lane_is_not_compared() {
        let previous = code_review(finding("SERIOUS", Some("code"), "code issue"));
        let current = review(Vec::new());

        let diff = compare(
            2,
            &previous,
            Outcome::Completed,
            3,
            &current,
            Outcome::Completed,
        );

        assert!(diff.new.is_empty());
        assert!(diff.resolved.is_empty());
        let code = diff
            .uncomparable
            .iter()
            .find(|lane| matches!(lane.lane, Lane::Code))
            .expect("the CODE lane is not comparable");
        assert!(
            code.reasons
                .iter()
                .any(|reason| reason.contains("has no CODE assessment"))
        );
    }

    #[test]
    fn a_missing_environment_lane_is_not_compared() {
        let previous = review(vec![finding("SERIOUS", Some("env"), "env issue")]);
        let mut current = review(Vec::new());
        current.assessment_count = 0;
        current.assessments = Vec::new();

        let diff = compare(
            2,
            &previous,
            Outcome::Completed,
            3,
            &current,
            Outcome::Completed,
        );

        assert!(diff.resolved.is_empty());
        assert_eq!(diff.uncomparable.len(), 1);
        assert!(matches!(diff.uncomparable[0].lane, Lane::Environment));
        assert!(
            diff.uncomparable[0]
                .reasons
                .iter()
                .any(|reason| reason.contains("has no environment assessment"))
        );
    }

    #[test]
    fn text_prints_all_four_labels_and_a_changed_severity() {
        let previous = review(vec![finding("WARNING", Some("keep"), "still there")]);
        let current = review(vec![
            finding("SERIOUS", Some("keep"), "still there"),
            finding("WARNING", None, "cannot correlate"),
        ]);

        let diff = compare(
            2,
            &previous,
            Outcome::Completed,
            3,
            &current,
            Outcome::Completed,
        );
        let output = text("acme/app", 42, &diff, &url(2), &url(3));

        for label in [
            "New (0):",
            "Resolved (0):",
            "Persisting (1):",
            "Uncorrelated (1):",
        ] {
            assert!(output.contains(label), "{output}");
        }
        assert!(output.contains("was WARNING"), "{output}");
        assert!(output.contains("run 3"), "{output}");
    }
}
