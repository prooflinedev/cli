//! Findings and gaps as GitHub Actions workflow commands. The runner reads
//! each `::error file=...,line=...::message` line from a step's output and
//! shows it on the pull request's diff, on every GitHub plan. Findings quote
//! reviewer output and repository content, so every value is escaped: a
//! newline in a claim must never start a second command.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::io::Write;

use crate::model::{Finding, ReviewDetail};
use crate::outcome::{self, Outcome};
use crate::severity::Severity;
use crate::{sarif, text};

/// Writes one annotation per unresolved finding and one per gap in the
/// result. Gaps come first so a long finding list cannot hide them.
pub(super) fn write(detail: &ReviewDetail, out: &mut impl Write) -> std::io::Result<()> {
    let head = detail.head_commit_sha.as_deref().unwrap_or_default();
    let state = outcome::terminal(detail);
    let code = outcome::code_assessment(detail);

    if let Some(code) = code {
        for reason in outcome::code_gap(code).unwrap_or_default() {
            gap(
                out,
                "Code-only",
                &reason,
                &format!("Code-only: {reason}. Findings here are not a complete result."),
            )?;
        }
    } else if outcome::code_unavailable(detail) {
        gap(
            out,
            "Code-only",
            "CODE_ASSESSMENT_UNAVAILABLE",
            "Code-only: CODE_ASSESSMENT_UNAVAILABLE. Findings here are not a complete result.",
        )?;
    }
    for assessment in &detail.assessments {
        let name = text::one_line(&assessment.environment_display_name);
        let reasons: BTreeSet<String> = outcome::gap(assessment)
            .unwrap_or_default()
            .into_iter()
            .collect();
        for reason in &reasons {
            gap(
                out,
                &name,
                reason,
                &format!("{name}: {reason}. Findings here are not a complete result."),
            )?;
        }
    }
    if let Some(reason) = outcome::review_gap(detail) {
        gap(
            out,
            "Review",
            reason,
            &format!("Review: {reason}. This is not a complete result."),
        )?;
    }
    if state != Some(Outcome::Completed) {
        let reason = match state {
            None => "REVIEW_IN_PROGRESS",
            Some(Outcome::Failed) => "REVIEW_FAILED",
            Some(Outcome::Stopped) => "REVIEW_STOPPED",
            Some(Outcome::Incomplete | Outcome::Completed) => "REVIEW_RESULT_INCOMPLETE",
        };
        gap(
            out,
            "Review",
            reason,
            &format!(
                "Review {}: {reason}. These annotations are not a complete result.",
                detail.id
            ),
        )?;
    }

    if let Some(code) = code {
        let partial = outcome::code_gap(code).is_some();
        let mut findings: Vec<&Finding> = code.findings.iter().collect();
        findings.sort_by_key(|item| Reverse(Severity::parse(&item.severity)));
        for finding in findings {
            annotate(out, finding, "code", head, partial)?;
        }
    }
    for assessment in &detail.assessments {
        let partial = outcome::gap(assessment).is_some();
        let mut findings: Vec<&Finding> = assessment.findings.iter().collect();
        findings.sort_by_key(|item| Reverse(Severity::parse(&item.severity)));
        let lane = text::one_line(&assessment.environment_display_name);
        for finding in findings {
            annotate(out, finding, &lane, head, partial)?;
        }
    }
    Ok(())
}

/// A gap is an error on the job, with no file or line to place it on.
fn gap(out: &mut impl Write, lane: &str, reason: &str, message: &str) -> std::io::Result<()> {
    let title = format!("Proofline {lane}: {reason}");
    writeln!(
        out,
        "::error title={}::{}",
        escape_property(&title),
        escape_data(message)
    )
}

fn annotate(
    out: &mut impl Write,
    finding: &Finding,
    lane: &str,
    head: &str,
    partial: bool,
) -> std::io::Result<()> {
    if outcome::resolved(finding) {
        return Ok(());
    }
    // A severity this CLI does not know yet is still shown, as a notice.
    let command = match Severity::parse(&finding.severity) {
        Some(Severity::Serious) => "error",
        Some(Severity::Warning) => "warning",
        None => "notice",
    };
    let lane = if partial {
        format!("{lane} (partial)")
    } else {
        lane.to_owned()
    };
    let mut properties = Vec::new();
    if let Some((path, start, end)) = finding
        .evidence_refs
        .iter()
        .find_map(|reference| sarif::location(reference, head))
    {
        properties.push(format!("file={}", escape_property(path)));
        properties.push(format!("line={start}"));
        properties.push(format!("endLine={end}"));
    }
    let title = format!("Proofline {lane}: {}", finding.risk_domain);
    properties.push(format!("title={}", escape_property(&title)));
    let message = format!("{}\n\n{}", finding.claim, finding.impact);
    writeln!(
        out,
        "::{command} {}::{}",
        properties.join(","),
        escape_data(&message)
    )
}

/// The message of a workflow command, escaped as `@actions/core` does.
/// Control characters other than a newline or a tab, `\r` among them, are
/// replaced first, so nothing reaches the log that the runner or a terminal
/// would interpret.
fn escape_data(value: &str) -> String {
    text::terminal_safe(value)
        .replace('%', "%25")
        .replace('\n', "%0A")
}

/// A property value of a workflow command, where `:` and `,` also delimit.
fn escape_property(value: &str) -> String {
    escape_data(value).replace(':', "%3A").replace(',', "%2C")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assessment, Checks};
    use uuid::Uuid;

    fn assessment(status: &str, incomplete: bool) -> Assessment {
        Assessment {
            id: Uuid::nil(),
            environment_display_name: "production".to_owned(),
            status: status.to_owned(),
            findings: vec![Finding {
                id: Uuid::nil(),
                finding_fingerprint: None,
                severity: "SERIOUS".to_owned(),
                risk_domain: "data_integrity".to_owned(),
                claim: "orders are dropped".to_owned(),
                impact: "customers are charged twice".to_owned(),
                lifecycle_state: "NEW".to_owned(),
                remediation: None,
                evidence_refs: Vec::new(),
            }],
            checks: Checks {
                receipt_recorded: true,
                status: "READY".to_owned(),
                families: Vec::new(),
            },
            incompleteness_kind: incomplete.then(|| "WORLD_UNAVAILABLE".to_owned()),
            reason_codes: None,
            release_evidence_gap: None,
        }
    }

    fn review(status: &str, assessments: Vec<Assessment>, count: i64) -> ReviewDetail {
        ReviewDetail {
            id: Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: status.to_owned(),
            assessment_count: count,
            assessments,
            code_assessment: None,
            subjects: Vec::new(),
            base_commit_sha: None,
            head_commit_sha: None,
            open_items: None,
            pull_request_number: Some(7),
            repository_id: None,
            repository_full_name: Some("acme/web".to_owned()),
            run_number: Some(1),
            local_reverifications: Vec::new(),
        }
    }

    fn write_review(detail: &ReviewDetail) -> String {
        let mut out = Vec::new();
        write(detail, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn values_cannot_end_the_command_or_start_another() {
        assert_eq!(escape_data("50% a\r\nb::c"), "50%25 a\u{FFFD}%0Ab::c");
        assert_eq!(
            escape_data("x\n::add-mask::secret"),
            "x%0A::add-mask::secret"
        );
        assert_eq!(escape_property("a:b,c%\nd"), "a%3Ab%2Cc%25%0Ad");
        assert_eq!(escape_data("ok\u{1b}[2J"), "ok\u{FFFD}[2J");
    }

    #[test]
    fn an_incomplete_assessment_names_its_gap_and_marks_its_findings_partial() {
        let text = write_review(&review(
            "COMPLETED",
            vec![assessment("INCOMPLETE", true)],
            1,
        ));
        assert!(text.contains(
            "::error title=Proofline production%3A WORLD_UNAVAILABLE::production: WORLD_UNAVAILABLE. Findings here are not a complete result."
        ));
        assert!(text.contains(
            "::error title=Proofline Review%3A REVIEW_RESULT_INCOMPLETE::Review 00000000-0000-0000-0000-000000000000: REVIEW_RESULT_INCOMPLETE. These annotations are not a complete result."
        ));
        assert!(text.contains(
            "::error title=Proofline production (partial)%3A data_integrity::orders are dropped"
        ));
    }

    #[test]
    fn a_complete_review_has_no_gap_annotations() {
        let text = write_review(&review(
            "COMPLETED",
            vec![assessment("COMPLETED", false)],
            1,
        ));
        assert!(!text.contains("::error title=Proofline Review"));
        assert!(!text.contains("(partial)"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn a_review_still_running_reports_that_its_result_is_unknown() {
        let text = write_review(&review("RUNNING", Vec::new(), 1));
        assert!(text.contains("REVIEW_IN_PROGRESS"));
    }
}
