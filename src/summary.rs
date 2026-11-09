//! Renders a Markdown job summary of a review for GitHub Actions
//! (`$GITHUB_STEP_SUMMARY`) or a local report file.

use std::fmt::Write as _;
use std::path::Path;

use crate::model::{Finding, ReviewDetail};
use crate::outcome::{self, Outcome};
use crate::render;
use crate::severity::Severity;
use crate::text::{one_line, terminal_safe};

/// Writes a Markdown job summary of the review to `path`, appending if the file exists.
pub(crate) async fn write(
    detail: &ReviewDetail,
    review_url: &str,
    path: &Path,
) -> anyhow::Result<()> {
    let markdown = render(detail, review_url);
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, markdown.as_bytes()).await?;
    Ok(())
}

/// Renders the review as a Markdown document suitable for a GitHub Actions job summary.
pub(crate) fn render(detail: &ReviewDetail, review_url: &str) -> String {
    let (icon, outcome_str) = match outcome::terminal(detail) {
        Some(Outcome::Completed) => ("✅", "COMPLETED"),
        Some(Outcome::Incomplete) => ("⚠️", "INCOMPLETE"),
        Some(Outcome::Failed) => ("❌", "FAILED"),
        Some(Outcome::Stopped) => ("⏹️", "STOPPED"),
        None => ("⏳", detail.status.as_str()),
    };
    let mut out = String::new();

    let _ = writeln!(out, "### {icon} Proofline Review: {outcome_str}\n");
    let _ = writeln!(out, "[View review in Proofline]({review_url})\n");

    if let Some(repo) = &detail.repository_full_name {
        let _ = writeln!(out, "- **Repository:** `{}`", escape_cell(repo));
    }
    if let Some(commit) = &detail.head_commit_sha {
        let _ = writeln!(out, "- **Commit:** `{}`", escape_cell(commit));
    }
    if let Some(pr) = detail.pull_request_number {
        if let Some(run) = detail.run_number {
            let _ = writeln!(out, "- **Pull Request:** #{pr} (run {run})");
        } else {
            let _ = writeln!(out, "- **Pull Request:** #{pr}");
        }
    }
    let _ = writeln!(out);

    render_assessments(&mut out, detail);
    render_findings(&mut out, detail);

    out
}

fn render_assessments(out: &mut String, detail: &ReviewDetail) {
    let _ = writeln!(out, "#### Assessments\n");
    let _ = writeln!(out, "| Assessment | Status | Open Findings |");
    let _ = writeln!(out, "| :--- | :--- | :--- |");

    if let Some(code) = outcome::code_assessment(detail) {
        let status = code.status.as_str();
        let open_count = code.findings.iter().filter(|f| !is_resolved(f)).count();
        let status_desc = outcome::code_gap(code)
            .map_or_else(|| status.to_owned(), |gap| format!("{status} ({gap})"));
        let _ = writeln!(
            out,
            "| Code | {} | {} |",
            escape_cell(&status_desc),
            open_count
        );
    }

    for assessment in &detail.assessments {
        let name = &assessment.environment_display_name;
        let status = assessment.status.as_str();
        let open_count = assessment
            .findings
            .iter()
            .filter(|f| !is_resolved(f))
            .count();
        let status_desc = outcome::gap(assessment).map_or_else(
            || status.to_owned(),
            |gaps| format!("{status} ({})", gaps.join(", ")),
        );
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            escape_cell(name),
            escape_cell(&status_desc),
            open_count
        );
    }
    let _ = writeln!(out);
}

fn render_findings(out: &mut String, detail: &ReviewDetail) {
    let _ = writeln!(out, "#### Findings\n");

    let mut open_findings: Vec<(&str, &Finding)> = Vec::new();
    if let Some(code) = outcome::code_assessment(detail) {
        for finding in &code.findings {
            if !is_resolved(finding) {
                open_findings.push(("Code", finding));
            }
        }
    }
    for assessment in &detail.assessments {
        for finding in &assessment.findings {
            if !is_resolved(finding) {
                open_findings.push((&assessment.environment_display_name, finding));
            }
        }
    }

    if open_findings.is_empty() {
        let _ = writeln!(out, "✅ No open infrastructure findings.\n");
        return;
    }

    let _ = writeln!(
        out,
        "| Severity | Environment | Risk Domain | Claim | Location |"
    );
    let _ = writeln!(out, "| :--- | :--- | :--- | :--- | :--- |");

    for (env, finding) in open_findings {
        let severity = severity_badge(&finding.severity);
        let domain = escape_cell(&one_line(&finding.risk_domain));
        let claim = escape_cell(&one_line(&finding.claim));
        let locs = render::location(finding);
        let loc_str = if locs.is_empty() {
            "-".to_owned()
        } else {
            locs.iter()
                .map(|l| format!("`{}`", escape_cell(l)))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let _ = writeln!(
            out,
            "| {} | {} | `{}` | {} | {} |",
            severity,
            escape_cell(env),
            domain,
            claim,
            loc_str
        );
    }
    let _ = writeln!(out);
}

fn is_resolved(finding: &Finding) -> bool {
    finding.lifecycle_state == "RESOLVED"
}

fn severity_badge(severity_str: &str) -> String {
    match Severity::parse(severity_str) {
        Some(Severity::Serious) => "🔴 **SERIOUS**".to_owned(),
        Some(Severity::Warning) => "🟡 **WARNING**".to_owned(),
        None => format!("ℹ️ **{}**", escape_cell(severity_str)),
    }
}

fn escape_cell(value: &str) -> String {
    terminal_safe(value)
        .replace('|', "\\|")
        .replace('\n', " ")
        .replace('\r', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assessment, Checks};
    use uuid::Uuid;

    #[test]
    fn renders_clean_review_summary() {
        let detail = ReviewDetail {
            id: Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: "COMPLETED".to_owned(),
            assessment_count: 1,
            assessments: vec![Assessment {
                id: Uuid::nil(),
                environment_display_name: "production".to_owned(),
                status: "COMPLETED".to_owned(),
                findings: Vec::new(),
                checks: Checks {
                    receipt_recorded: true,
                    status: "READY".to_owned(),
                    families: Vec::new(),
                },
                incompleteness_kind: None,
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
        };

        let summary = render(&detail, "https://proofline.sh/reviews/test");
        assert!(summary.contains("### ✅ Proofline Review: COMPLETED"));
        assert!(summary.contains("[View review in Proofline](https://proofline.sh/reviews/test)"));
        assert!(summary.contains("- **Repository:** `acme/app`"));
        assert!(summary.contains("- **Pull Request:** #42 (run 1)"));
        assert!(summary.contains("| production | COMPLETED | 0 |"));
        assert!(summary.contains("✅ No open infrastructure findings."));
    }

    #[test]
    fn escapes_pipe_and_newlines_in_cells() {
        assert_eq!(escape_cell("foo|bar\nbaz"), "foo\\|bar baz");
    }
}
