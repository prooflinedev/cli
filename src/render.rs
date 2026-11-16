//! The text form of a review. An incomplete assessment prints its gap and
//! never "no findings": unknown is not safe.

use std::cmp::Reverse;

use url::Url;

use crate::model::{Assessment, CodeAssessment, Finding, LocalReverification, ReviewDetail};
use crate::outcome::{self, Outcome};
use crate::severity::Severity;
use crate::text::{one_line, terminal_safe};

pub(crate) fn location(finding: &Finding) -> Vec<String> {
    finding
        .evidence_refs
        .iter()
        .filter_map(|evidence| {
            let path = one_line(evidence.repository_path.as_deref()?);
            Some(match (evidence.start_line, evidence.end_line) {
                (Some(start), Some(end)) if end > start => format!("{path}:{start}-{end}"),
                (Some(start), _) => format!("{path}:{start}"),
                (None, _) => path,
            })
        })
        .collect()
}

fn finding(out: &mut Vec<String>, finding: &Finding) {
    out.push(format!(
        "  {:<8} {}  {}",
        one_line(&finding.severity),
        one_line(&finding.risk_domain),
        one_line(&finding.claim)
    ));
    for place in location(finding) {
        out.push(format!("           at {place}"));
    }
    out.push(format!("           impact: {}", one_line(&finding.impact)));
    if let Some(remediation) = &finding.remediation {
        out.push(format!("           fix: {}", one_line(remediation)));
    }
}

fn assessment(out: &mut Vec<String>, assessment: &Assessment) {
    let name = one_line(&assessment.environment_display_name);
    let mut findings: Vec<&Finding> = assessment.findings.iter().collect();
    // Most severe first; a severity this CLI does not know prints last.
    findings.sort_by_key(|item| Reverse(Severity::parse(&item.severity)));
    match outcome::gap(assessment) {
        Some(reasons) => {
            out.push(format!(
                "{name}: {} (incomplete: {})",
                one_line(&assessment.status),
                one_line(&reasons.join(", "))
            ));
            if !findings.is_empty() {
                out.push("  findings so far, not a complete result:".to_owned());
            }
        }
        None if findings.is_empty() => {
            out.push(format!("{name}: COMPLETED, no findings"));
        }
        None => {
            out.push(format!("{name}: COMPLETED, {} findings", findings.len()));
        }
    }
    for item in findings {
        finding(out, item);
    }
}

fn code_assessment(out: &mut Vec<String>, code: &CodeAssessment) {
    let mut findings: Vec<&Finding> = code.findings.iter().collect();
    findings.sort_by_key(|item| Reverse(Severity::parse(&item.severity)));
    match outcome::code_gap(code) {
        Some(reasons) => {
            out.push(format!(
                "Code-only: {} (incomplete: {})",
                code.status.as_str(),
                one_line(&reasons.join(", "))
            ));
            if !findings.is_empty() {
                out.push("  findings so far, not a complete result:".to_owned());
            }
        }
        None if findings.is_empty() => out.push("Code-only: COMPLETED, no findings".to_owned()),
        None => out.push(format!("Code-only: COMPLETED, {} findings", findings.len())),
    }
    for item in findings {
        finding(out, item);
    }
}

/// `{subject}{run}{commits}: {status}`.
fn headline(review: &ReviewDetail, state: Option<Outcome>) -> String {
    let subject = match (&review.repository_full_name, review.pull_request_number) {
        (Some(repository), Some(number)) => format!("{} #{number}", one_line(repository)),
        (Some(repository), None) => one_line(repository),
        _ => one_line(&review.kind),
    };
    let run = review
        .run_number
        .map(|run| format!(" run {run}"))
        .unwrap_or_default();
    let status = state.map_or_else(
        || terminal_safe(&review.status),
        |state| state.as_str().to_owned(),
    );
    format!("{subject}{run}{}: {status}", commits(review))
}

/// The reviewed commits. A patch review's head is a revision ID, not a
/// commit, so it names its base; a commit review is of a range, so it names
/// both ends.
fn commits(review: &ReviewDetail) -> String {
    let short = |sha: &str| one_line(sha.get(..12).unwrap_or(sha));
    match (
        review.kind.as_str(),
        review.base_commit_sha.as_deref(),
        review.head_commit_sha.as_deref(),
    ) {
        ("PATCH", base, _) => base
            .map(|sha| format!(" local changes on {}", short(sha)))
            .unwrap_or_default(),
        ("COMMIT", Some(base), Some(head)) => format!(" {}..{}", short(base), short(head)),
        (_, _, head) => head
            .map(|sha| format!(" at {}", short(sha)))
            .unwrap_or_default(),
    }
}

/// The paths a FILES review selected at its primary revision.
fn selected_files(review: &ReviewDetail) -> Option<String> {
    if review.kind != "FILES" {
        return None;
    }
    let scope = review
        .subjects
        .iter()
        .find(|subject| subject.role == "PRIMARY" && subject.kind == "GIT_REVISION")
        .and_then(|subject| subject.file_scope.as_ref())?;
    Some(format!(
        "Selected files: {}",
        scope
            .paths
            .iter()
            .map(|path| one_line(path))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn reverifications(out: &mut Vec<String>, items: &[LocalReverification]) {
    if items.is_empty() {
        return;
    }
    out.push(String::new());
    out.push(
        "Re-verified against the local changes (the pull request's findings are unchanged):"
            .to_owned(),
    );
    for item in items {
        out.push(format!(
            "  {}  {}  (request {} of 3)",
            item.finding_id,
            one_line(&item.outcome),
            item.iteration
        ));
    }
}

/// The review, with separate CODE and environment assessment blocks.
pub fn review(review: &ReviewDetail, state: Option<Outcome>, url: &Url) -> String {
    let mut out = vec![headline(review, state), url.to_string()];
    if let Some(reason) = outcome::review_gap(review) {
        out.push(format!("Review incomplete: {reason}"));
    }
    out.extend(selected_files(review));
    if let Some(code) = outcome::code_assessment(review) {
        out.push(String::new());
        code_assessment(&mut out, code);
    } else if outcome::code_unavailable(review) {
        out.push("Code-only: incomplete (CODE_ASSESSMENT_UNAVAILABLE)".to_owned());
    }
    if review.assessments.is_empty() && review.assessment_count != 0 {
        out.push("no environment assessment has been recorded yet".to_owned());
    }
    for item in &review.assessments {
        out.push(String::new());
        assessment(&mut out, item);
    }
    reverifications(&mut out, &review.local_reverifications);
    out.push(String::new());
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Checks, EvidenceRef, FileScope, ReviewSubject};

    fn sample(status: &str, findings: Vec<Finding>) -> ReviewDetail {
        ReviewDetail {
            id: uuid::Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: "COMPLETED".to_owned(),
            assessment_count: 1,
            code_assessment: None,
            subjects: Vec::new(),
            assessments: vec![Assessment {
                id: uuid::Uuid::nil(),
                environment_display_name: "production".to_owned(),
                status: status.to_owned(),
                findings,
                checks: Checks {
                    receipt_recorded: true,
                    status: "READY".to_owned(),
                    families: Vec::new(),
                },
                incompleteness_kind: (status != "COMPLETED")
                    .then(|| "WORLD_UNAVAILABLE".to_owned()),
                reason_codes: None,
                release_evidence_gap: None,
            }],
            base_commit_sha: None,
            head_commit_sha: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            open_items: None,
            pull_request_number: Some(42),
            repository_full_name: Some("acme/web".to_owned()),
            run_number: Some(2),
            local_reverifications: Vec::new(),
        }
    }

    fn finding(severity: &str, claim: &str) -> Finding {
        Finding {
            id: uuid::Uuid::nil(),
            finding_fingerprint: None,
            severity: severity.to_owned(),
            risk_domain: "data_integrity".to_owned(),
            claim: claim.to_owned(),
            impact: "orders are lost".to_owned(),
            lifecycle_state: "ACTIVE".to_owned(),
            remediation: None,
            evidence_refs: vec![EvidenceRef {
                kind: "CODE".to_owned(),
                label: "handler".to_owned(),
                provenance_status: None,
                repository_path: Some("src/orders.rs".to_owned()),
                start_line: Some(10),
                end_line: Some(14),
                file_sha256: None,
                commit_sha: None,
                companion_repository: None,
            }],
        }
    }

    fn url() -> Url {
        Url::parse("https://proofline.sh/orgs/by-id/o/reviews/r").unwrap()
    }

    #[test]
    fn an_incomplete_assessment_never_reads_as_clean() {
        let detail = sample("INCOMPLETE", Vec::new());
        let text = review(&detail, outcome::terminal(&detail), &url());
        assert!(text.contains("production: INCOMPLETE (incomplete: WORLD_UNAVAILABLE)"));
        assert!(!text.contains("no findings"));
    }

    #[test]
    fn findings_print_most_severe_first_and_an_unknown_severity_last() {
        let detail = sample(
            "COMPLETED",
            vec![
                finding("WARNING", "second"),
                finding("NOTE", "third"),
                finding("SERIOUS", "first"),
            ],
        );
        let text = review(&detail, None, &url());
        let places = ["first", "second", "third"].map(|claim| text.find(claim).unwrap());
        assert!(places.is_sorted(), "{text}");
    }

    #[test]
    fn model_text_cannot_drive_the_terminal() {
        let detail = sample("COMPLETED", vec![finding("SERIOUS", "x\u{1b}[2J\ny")]);
        let text = review(&detail, None, &url());
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("x\u{FFFD}[2J y"));
    }

    fn first_line(detail: &ReviewDetail, state: Option<Outcome>) -> String {
        review(detail, state, &url())
            .lines()
            .next()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn the_headline_names_the_pull_request_the_repository_or_the_kind() {
        let mut detail = sample("COMPLETED", Vec::new());
        assert_eq!(
            first_line(&detail, None),
            "acme/web #42 run 2 at 0123456789ab: COMPLETED"
        );
        detail.pull_request_number = None;
        detail.run_number = None;
        assert_eq!(
            first_line(&detail, Some(Outcome::Incomplete)),
            "acme/web at 0123456789ab: INCOMPLETE"
        );
        detail.repository_full_name = None;
        assert_eq!(
            first_line(&detail, None),
            "PULL_REQUEST at 0123456789ab: COMPLETED"
        );
    }

    #[test]
    fn a_patch_review_names_its_base_a_commit_review_its_range_and_others_their_head() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.repository_full_name = None;
        detail.run_number = None;
        detail.kind = "PATCH".to_owned();
        assert_eq!(first_line(&detail, None), "PATCH: COMPLETED");
        detail.base_commit_sha = Some("fedcba9876543210fedcba9876543210fedcba98".to_owned());
        assert_eq!(
            first_line(&detail, None),
            "PATCH local changes on fedcba987654: COMPLETED"
        );
        detail.kind = "COMMIT".to_owned();
        assert_eq!(
            first_line(&detail, None),
            "COMMIT fedcba987654..0123456789ab: COMPLETED"
        );
        detail.base_commit_sha = None;
        assert_eq!(
            first_line(&detail, None),
            "COMMIT at 0123456789ab: COMPLETED"
        );
    }

    #[test]
    fn a_review_level_gap_prints_beside_the_headline() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.assessment_count = 2;
        let text = review(&detail, outcome::terminal(&detail), &url());
        assert_eq!(
            text.lines().nth(2),
            Some("Review incomplete: ASSESSMENT_HISTORY_UNAVAILABLE"),
            "{text}"
        );
    }

    #[test]
    fn a_files_review_lists_its_selected_paths() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.subjects = vec![ReviewSubject {
            kind: "GIT_REVISION".to_owned(),
            role: "PRIMARY".to_owned(),
            file_scope: Some(FileScope {
                paths: vec!["src/orders.rs".to_owned(), "src/lib.rs".to_owned()],
                paths_digest: "digest".to_owned(),
            }),
        }];
        assert!(!review(&detail, None, &url()).contains("Selected files"));
        detail.kind = "FILES".to_owned();
        let text = review(&detail, None, &url());
        assert_eq!(
            text.lines().nth(2),
            Some("Selected files: src/orders.rs, src/lib.rs"),
            "{text}"
        );
    }

    #[test]
    fn a_review_with_no_recorded_environment_says_so() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.assessments.clear();
        let text = review(&detail, outcome::terminal(&detail), &url());
        assert!(
            text.contains("\nno environment assessment has been recorded yet\n"),
            "{text}"
        );
        assert!(!text.contains("no findings"), "{text}");
    }

    #[test]
    fn local_reverifications_print_after_the_assessments() {
        let mut detail = sample("COMPLETED", Vec::new());
        assert!(!review(&detail, None, &url()).contains("Re-verified"));
        detail.local_reverifications = vec![LocalReverification {
            finding_id: uuid::Uuid::nil(),
            iteration: 2,
            outcome: "STILL_PRESENT".to_owned(),
            checks: serde_json::Value::Null,
        }];
        let text = review(&detail, None, &url());
        let environment = text.find("production: COMPLETED").unwrap();
        let block = text.find("Re-verified against the local changes").unwrap();
        assert!(environment < block, "{text}");
        assert!(
            text.contains(
                "  00000000-0000-0000-0000-000000000000  STILL_PRESENT  (request 2 of 3)"
            ),
            "{text}"
        );
    }
}
