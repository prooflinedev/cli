//! Renders a Markdown job summary of a review for GitHub Actions
//! (`$GITHUB_STEP_SUMMARY`) or a local report file.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::model::{Finding, ReviewDetail};
use crate::outcome::{self, Outcome};
use crate::render;
use crate::severity::Severity;
use crate::text::{one_line, terminal_safe};

/// Destination where the summary should be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SummaryDestination {
    File(PathBuf),
    Stdout,
}

/// Writes a Markdown job summary of the review to `destination`, appending if writing to a file.
pub(crate) async fn write(
    detail: &ReviewDetail,
    review_url: &str,
    destination: &SummaryDestination,
) -> anyhow::Result<()> {
    let markdown = render(detail, review_url);
    match destination {
        SummaryDestination::Stdout => {
            let mut stdout = tokio::io::stdout();
            tokio::io::AsyncWriteExt::write_all(&mut stdout, markdown.as_bytes()).await?;
            tokio::io::AsyncWriteExt::flush(&mut stdout).await?;
        }
        SummaryDestination::File(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, markdown.as_bytes()).await?;
            tokio::io::AsyncWriteExt::flush(&mut file).await?;
        }
    }
    Ok(())
}

/// Renders the review as a Markdown document suitable for a GitHub Actions job summary.
pub(crate) fn render(detail: &ReviewDetail, review_url: &str) -> String {
    let open_findings = collect_open_findings(detail);
    let (serious_count, warning_count) = count_severities(&open_findings);

    let (icon, outcome_str) = match outcome::terminal(detail) {
        Some(Outcome::Completed) => {
            if serious_count > 0 {
                ("🔴", "BLOCKING")
            } else if warning_count > 0 {
                ("🟡", "WARNINGS")
            } else {
                ("🟢", "PASS")
            }
        }
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

    render_metrics_table(
        &mut out,
        detail,
        open_findings.len(),
        serious_count,
        warning_count,
        &open_findings,
    );
    render_assessments(&mut out, detail);
    render_findings(&mut out, &open_findings);

    out
}

fn collect_open_findings(detail: &ReviewDetail) -> Vec<(&str, &Finding)> {
    let mut findings = Vec::new();
    if let Some(code) = outcome::code_assessment(detail) {
        for item in &code.findings {
            if !is_resolved(item) {
                findings.push(("Code", item));
            }
        }
    }
    for assessment in &detail.assessments {
        for item in &assessment.findings {
            if !is_resolved(item) {
                findings.push((assessment.environment_display_name.as_str(), item));
            }
        }
    }
    findings
}

fn count_severities(findings: &[(&str, &Finding)]) -> (usize, usize) {
    let mut serious = 0;
    let mut warning = 0;
    for (_, finding) in findings {
        match Severity::parse(&finding.severity) {
            Some(Severity::Serious) => serious += 1,
            Some(Severity::Warning) => warning += 1,
            None => {}
        }
    }
    (serious, warning)
}

fn render_metrics_table(
    out: &mut String,
    detail: &ReviewDetail,
    total_findings: usize,
    serious_count: usize,
    warning_count: usize,
    open_findings: &[(&str, &Finding)],
) {
    let files_count = files_inspected_count(detail, open_findings);

    let _ = writeln!(out, "#### Summary Metrics\n");
    let _ = writeln!(
        out,
        "| Files Inspected | Open Findings | Serious (🔴) | Warnings (🟡) |"
    );
    let _ = writeln!(out, "| :---: | :---: | :---: | :---: |");
    let _ = writeln!(
        out,
        "| {files_count} | {total_findings} | {serious_count} | {warning_count} |\n"
    );
}

fn files_inspected_count(detail: &ReviewDetail, open_findings: &[(&str, &Finding)]) -> usize {
    let scope_files = detail
        .subjects
        .iter()
        .find(|subject| subject.role == "PRIMARY" && subject.kind == "GIT_REVISION")
        .and_then(|subject| subject.file_scope.as_ref())
        .map(|scope| scope.paths.len());

    if let Some(count) = scope_files.filter(|&c| c > 0) {
        return count;
    }

    let mut cited_files = BTreeSet::new();
    for (_, finding) in open_findings {
        for evidence in &finding.evidence_refs {
            if let Some(path) = &evidence.repository_path {
                cited_files.insert(path.as_str());
            }
        }
    }
    cited_files.len()
}

fn render_assessments(out: &mut String, detail: &ReviewDetail) {
    let _ = writeln!(out, "#### Assessments\n");
    let _ = writeln!(out, "| Assessment | Status | Open Findings |");
    let _ = writeln!(out, "| :--- | :--- | :--- |");

    if let Some(code) = outcome::code_assessment(detail) {
        let status = code.status.as_str();
        let open_count = code.findings.iter().filter(|f| !is_resolved(f)).count();
        let status_desc = outcome::code_gap(code).map_or_else(
            || status.to_owned(),
            |gaps| format!("{status} ({})", gaps.join(", ")),
        );
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

fn render_findings(out: &mut String, open_findings: &[(&str, &Finding)]) {
    let _ = writeln!(out, "#### Findings\n");

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

    let _ = writeln!(
        out,
        "<details>\n<summary><strong>🔍 Finding Details & Remediation</strong></summary>\n"
    );

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

        let _ = writeln!(out, "##### {severity} {claim}");
        let _ = writeln!(out, "- **Environment:** {}", escape_cell(env));
        let _ = writeln!(out, "- **Risk Domain:** `{domain}`");
        let _ = writeln!(out, "- **Location:** {loc_str}");
        if !finding.impact.is_empty() {
            let _ = writeln!(
                out,
                "- **Impact:** {}",
                escape_cell(&one_line(&finding.impact))
            );
        }
        if let Some(remediation) = finding.remediation.as_deref().filter(|r| !r.is_empty()) {
            let _ = writeln!(
                out,
                "- **Remediation:** {}",
                escape_cell(&one_line(remediation))
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "</details>\n");
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

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            } else if chars.peek() == Some(&']') {
                chars.next();
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub(crate) fn escape_cell(value: &str) -> String {
    let stripped = strip_ansi(value);
    let normalized = stripped.replace('\r', "").replace('\n', " ");
    terminal_safe(&normalized).replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assessment, Checks, EvidenceRef, FileScope, ReviewSubject};
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
            subjects: vec![ReviewSubject {
                kind: "GIT_REVISION".to_owned(),
                role: "PRIMARY".to_owned(),
                file_scope: Some(FileScope {
                    paths: vec!["src/main.rs".to_owned(), "src/lib.rs".to_owned()],
                    paths_digest: "sha256:abc".to_owned(),
                }),
            }],
            local_reverifications: Vec::new(),
        };

        let summary = render(&detail, "https://proofline.sh/reviews/test");
        assert!(summary.contains("### 🟢 Proofline Review: PASS"));
        assert!(summary.contains("[View review in Proofline](https://proofline.sh/reviews/test)"));
        assert!(summary.contains("- **Repository:** `acme/app`"));
        assert!(summary.contains("- **Commit:** `0123456789abcdef0123456789abcdef01234567`"));
        assert!(summary.contains("- **Pull Request:** #42 (run 1)"));
        assert!(summary.contains("| 2 | 0 | 0 | 0 |"));
        assert!(summary.contains("| production | COMPLETED | 0 |"));
        assert!(summary.contains("✅ No open infrastructure findings."));
    }

    #[test]
    fn renders_summary_with_mixed_serious_and_warning_findings() {
        let finding_serious = Finding {
            id: Uuid::nil(),
            finding_fingerprint: Some("fp-1".to_owned()),
            severity: "SERIOUS".to_owned(),
            risk_domain: "reliability".to_owned(),
            claim: "Orders dropped on retry".to_owned(),
            impact: "Data loss in queue".to_owned(),
            lifecycle_state: "OPEN".to_owned(),
            remediation: Some("Persist transactions before retry".to_owned()),
            evidence_refs: vec![EvidenceRef {
                kind: "CODE".to_owned(),
                label: "order logic".to_owned(),
                provenance_status: None,
                repository_path: Some("src/orders.rs".to_owned()),
                start_line: Some(42),
                end_line: Some(50),
                file_sha256: None,
                commit_sha: None,
                companion_repository: None,
            }],
        };

        let finding_warning = Finding {
            id: Uuid::nil(),
            finding_fingerprint: Some("fp-2".to_owned()),
            severity: "WARNING".to_owned(),
            risk_domain: "performance".to_owned(),
            claim: "Missing index on lookup".to_owned(),
            impact: "Slow queries under peak load".to_owned(),
            lifecycle_state: "ACTIVE".to_owned(),
            remediation: Some("Add index on user_id".to_owned()),
            evidence_refs: vec![EvidenceRef {
                kind: "CODE".to_owned(),
                label: "query".to_owned(),
                provenance_status: None,
                repository_path: Some("db/schema.sql".to_owned()),
                start_line: Some(15),
                end_line: None,
                file_sha256: None,
                commit_sha: None,
                companion_repository: None,
            }],
        };

        let detail = ReviewDetail {
            id: Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: "COMPLETED".to_owned(),
            assessment_count: 1,
            assessments: vec![Assessment {
                id: Uuid::nil(),
                environment_display_name: "production".to_owned(),
                status: "COMPLETED".to_owned(),
                findings: vec![finding_serious, finding_warning],
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
            head_commit_sha: Some("abcdef1234567890abcdef1234567890abcdef12".to_owned()),
            open_items: None,
            pull_request_number: Some(99),
            repository_full_name: Some("acme/orders".to_owned()),
            run_number: None,
            subjects: Vec::new(),
            local_reverifications: Vec::new(),
        };

        let summary = render(&detail, "https://proofline.sh/reviews/orders-99");
        assert!(summary.contains("### 🔴 Proofline Review: BLOCKING"));
        assert!(summary.contains("| 2 | 2 | 1 | 1 |"));
        assert!(summary.contains("| 🔴 **SERIOUS** | production | `reliability` | Orders dropped on retry | `src/orders.rs:42-50` |"));
        assert!(summary.contains("| 🟡 **WARNING** | production | `performance` | Missing index on lookup | `db/schema.sql:15` |"));
        assert!(summary.contains("<details>"));
        assert!(summary.contains("🔍 Finding Details & Remediation"));
        assert!(summary.contains("- **Impact:** Data loss in queue"));
        assert!(summary.contains("- **Remediation:** Persist transactions before retry"));
    }

    #[test]
    fn renders_warning_only_findings_as_warnings_banner() {
        let finding = Finding {
            id: Uuid::nil(),
            finding_fingerprint: Some("fp-warn".to_owned()),
            severity: "WARNING".to_owned(),
            risk_domain: "security".to_owned(),
            claim: "Loose CORS header".to_owned(),
            impact: "Potential CSRF vulnerability".to_owned(),
            lifecycle_state: "OPEN".to_owned(),
            remediation: Some("Restrict origin list".to_owned()),
            evidence_refs: Vec::new(),
        };

        let detail = ReviewDetail {
            id: Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: "COMPLETED".to_owned(),
            assessment_count: 1,
            assessments: vec![Assessment {
                id: Uuid::nil(),
                environment_display_name: "staging".to_owned(),
                status: "COMPLETED".to_owned(),
                findings: vec![finding],
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
            head_commit_sha: None,
            open_items: None,
            pull_request_number: Some(10),
            repository_full_name: None,
            run_number: None,
            subjects: Vec::new(),
            local_reverifications: Vec::new(),
        };

        let summary = render(&detail, "https://proofline.sh/reviews/10");
        assert!(summary.contains("### 🟡 Proofline Review: WARNINGS"));
        assert!(summary.contains("| 0 | 1 | 0 | 1 |"));
    }

    #[test]
    fn escapes_pipe_newlines_and_ansi_in_cells() {
        assert_eq!(escape_cell("foo|bar\nbaz\rqux"), "foo\\|bar bazqux");
        assert_eq!(escape_cell("\x1b[31mred\x1b[0m|text"), "red\\|text");
    }

    #[tokio::test]
    async fn writes_and_appends_to_summary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("job_summary.md");
        let dest = SummaryDestination::File(path.clone());

        let detail = ReviewDetail {
            id: Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: "COMPLETED".to_owned(),
            assessment_count: 0,
            assessments: Vec::new(),
            code_assessment: None,
            base_commit_sha: None,
            head_commit_sha: None,
            open_items: None,
            pull_request_number: None,
            repository_full_name: None,
            run_number: None,
            subjects: Vec::new(),
            local_reverifications: Vec::new(),
        };

        write(&detail, "https://proofline.sh/r/1", &dest)
            .await
            .unwrap();
        assert!(path.exists());
        let first_len = std::fs::read(&path).unwrap().len();

        // Second write should append, not truncate
        write(&detail, "https://proofline.sh/r/1", &dest)
            .await
            .unwrap();
        let second_len = std::fs::read(&path).unwrap().len();
        assert_eq!(second_len, first_len * 2);
    }
}
