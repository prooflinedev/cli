//! The text form of a review. An incomplete assessment prints its gap and
//! never "no findings": unknown is not safe.

use std::cmp::Reverse;

use url::Url;

use crate::model::{
    Assessment, CodeAssessment, EarlierFinding, Finding, FindingDecision, InvestigationFinding,
    LocalReverification, ReviewDetail, StoredCheck,
};
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
    if let Some(decision) = &finding.latest_validation {
        out.push(format!("           decision: {}", decided(decision)));
    }
    // fix and session commands take this ID, so text output must not need --json
    out.push(format!("           id: {}", finding.id));
}

/// `DISMISSED by Ada (GITHUB_COMMENT, 2026-11-20T10:00:00Z)`. An automatic
/// decision names no one.
fn decided(decision: &FindingDecision) -> String {
    let actor = decision
        .actor_name
        .as_deref()
        .or(decision.actor_login.as_deref())
        .map(|actor| format!(" by {}", one_line(actor)))
        .unwrap_or_default();
    format!(
        "{}{actor} ({}, {})",
        one_line(&decision.validation),
        one_line(&decision.source),
        one_line(&decision.recorded_at)
    )
}

/// An environment finding with no severity prints after the rated findings,
/// led by what published it.
fn investigation(out: &mut Vec<String>, finding: &InvestigationFinding) {
    out.push(format!(
        "  {}  {}  {}",
        one_line(finding.published_by()),
        one_line(&finding.area),
        one_line(&finding.title)
    ));
}

/// Environment findings of an assessment this review does not list. The
/// counts still include them, so they print on their own.
fn unlisted(out: &mut Vec<String>, review: &ReviewDetail) {
    let listed = |finding: &&InvestigationFinding| {
        review
            .assessments
            .iter()
            .any(|assessment| assessment.id == finding.assessment_id)
    };
    let findings: Vec<&InvestigationFinding> = review
        .investigation_findings
        .iter()
        .filter(|finding| !listed(finding))
        .collect();
    if findings.is_empty() {
        return;
    }
    out.push(String::new());
    out.push("Findings of an environment assessment this review does not list:".to_owned());
    for item in findings {
        investigation(out, item);
    }
}

fn assessment(
    out: &mut Vec<String>,
    assessment: &Assessment,
    investigations: &[&InvestigationFinding],
) {
    let name = one_line(&assessment.environment_display_name);
    let mut findings: Vec<&Finding> = assessment.findings.iter().collect();
    // Most severe first; a severity this CLI does not know prints last.
    findings.sort_by_key(|item| Reverse(Severity::parse(&item.severity)));
    let count = findings.len() + investigations.len();
    match outcome::gap(assessment) {
        Some(reasons) => {
            out.push(format!(
                "{name}: {} (incomplete: {})",
                one_line(&assessment.status),
                one_line(&reasons.join(", "))
            ));
            if count != 0 {
                out.push("  findings so far, not a complete result:".to_owned());
            }
        }
        None if count == 0 => {
            out.push(format!("{name}: COMPLETED, no findings"));
        }
        None => {
            out.push(format!("{name}: COMPLETED, {count} findings"));
        }
    }
    for item in findings {
        finding(out, item);
    }
    for item in investigations {
        investigation(out, item);
    }
}

/// Earlier runs' findings that this review did not find again. The server
/// still counts them as open, so `--fail-on` measures them too.
fn earlier(out: &mut Vec<String>, findings: &[EarlierFinding]) {
    if findings.is_empty() {
        return;
    }
    out.push(String::new());
    out.push("Still open from earlier runs, not found again by this review:".to_owned());
    for item in findings {
        let title = item
            .title
            .as_deref()
            .map(|title| format!("  {}", one_line(title)))
            .unwrap_or_default();
        out.push(format!(
            "  {:<8} run {}{title}",
            one_line(&item.severity),
            item.run_number
        ));
        out.push(format!("           review: {}", item.review_id));
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
        if let Some(check) = &item.stored_check {
            stored_check(out, check);
        }
    }
}

/// A finding's stored check: the command to run against the local changes,
/// what it last gave and what such a run can show.
fn stored_check(out: &mut Vec<String>, check: &StoredCheck) {
    out.push(format!("    Stored check: {}", one_line(&check.command)));
    if let Some(last) = &check.last_result {
        let at = last
            .commit_sha
            .as_deref()
            .map_or_else(String::new, |sha| format!(" at {}", one_line(sha)));
        let source = if last.source == "RERUN" {
            "a later head's run"
        } else {
            "the reproduction"
        };
        let reason = last
            .reason
            .as_deref()
            .map_or_else(String::new, |reason| format!(" ({})", one_line(reason)));
        out.push(format!(
            "    Last result: {}{reason}{at}, from {source}",
            one_line(&last.result)
        ));
    }
    out.push(
        "    The run shows code behavior under the conditions the test exercised, and no environment fact. The patch review did not run it.".to_owned(),
    );
}

/// The review, with separate CODE and environment assessment blocks.
/// A repository audit read as a review. Its findings are in its report, which
/// the review page at `url` links.
pub fn audit(url: &Url) -> String {
    format!("Repository audit: its findings are in its report, not in this review.\n{url}\n")
}

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
        let investigations: Vec<&InvestigationFinding> = review
            .investigation_findings
            .iter()
            .filter(|finding| finding.assessment_id == item.id)
            .collect();
        out.push(String::new());
        assessment(&mut out, item, &investigations);
    }
    unlisted(&mut out, review);
    earlier(
        &mut out,
        review
            .open_items
            .as_ref()
            .map_or(&[], |open| &open.earlier_findings),
    );
    reverifications(&mut out, &review.local_reverifications);
    out.push(String::new());
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Checks, EvidenceRef};

    fn sample(status: &str, findings: Vec<Finding>) -> ReviewDetail {
        ReviewDetail {
            id: uuid::Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: "COMPLETED".to_owned(),
            assessment_count: 1,
            code_assessment: None,
            subjects: Vec::new(),
            investigation_findings: Vec::new(),
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
            repository_id: None,
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
            latest_validation: None,
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
    fn each_finding_prints_the_id_that_fix_commands_take() {
        let mut item = finding("SERIOUS", "lost order");
        item.id = uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let detail = sample("COMPLETED", vec![item]);
        let text = review(&detail, None, &url());
        assert!(
            text.contains("           id: 01234567-89ab-cdef-0123-456789abcdef\n"),
            "{text}"
        );
    }

    #[test]
    fn model_text_cannot_drive_the_terminal() {
        let detail = sample("COMPLETED", vec![finding("SERIOUS", "x\u{1b}[2J\ny")]);
        let text = review(&detail, None, &url());
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("x\u{FFFD}[2J y"));
    }

    fn decision(actor_name: Option<&str>, actor_login: Option<&str>) -> FindingDecision {
        FindingDecision {
            validation: "DISMISSED".to_owned(),
            source: "GITHUB_COMMENT".to_owned(),
            recorded_at: "2026-11-20T10:00:00Z".to_owned(),
            actor_name: actor_name.map(str::to_owned),
            actor_login: actor_login.map(str::to_owned),
        }
    }

    #[test]
    fn a_decided_finding_names_its_decision_and_stays_listed() {
        let mut item = finding("SERIOUS", "lost order");
        item.latest_validation = Some(decision(Some("Ada\u{1b}[2J"), Some("ada")));
        let detail = sample("COMPLETED", vec![item]);
        let text = review(&detail, None, &url());
        assert!(text.contains("production: COMPLETED, 1 findings"), "{text}");
        assert!(
            text.contains(
                "           decision: DISMISSED by Ada\u{FFFD}[2J (GITHUB_COMMENT, 2026-11-20T10:00:00Z)\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_decision_names_the_login_without_a_name_and_no_one_when_automatic() {
        assert_eq!(
            decided(&decision(None, Some("ada"))),
            "DISMISSED by ada (GITHUB_COMMENT, 2026-11-20T10:00:00Z)"
        );
        assert_eq!(
            decided(&decision(None, None)),
            "DISMISSED (GITHUB_COMMENT, 2026-11-20T10:00:00Z)"
        );
    }

    fn investigation_finding(
        assessment_id: uuid::Uuid,
        source: Option<&str>,
        title: &str,
    ) -> InvestigationFinding {
        InvestigationFinding {
            assessment_id,
            area: "iam".to_owned(),
            title: title.to_owned(),
            source: source.map(str::to_owned),
        }
    }

    #[test]
    fn an_environment_finding_prints_under_its_environment_led_by_its_source() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.investigation_findings = vec![
            investigation_finding(uuid::Uuid::nil(), Some("INVESTIGATION"), "no bucket read"),
            investigation_finding(uuid::Uuid::nil(), Some("CONFIRMED_REQUIREMENT"), "no TLS"),
            investigation_finding(uuid::Uuid::nil(), None, "unnamed\u{1b}[2J"),
        ];
        let text = review(&detail, None, &url());
        assert!(
            text.contains(concat!(
                "production: COMPLETED, 3 findings\n",
                "  INVESTIGATION  iam  no bucket read\n",
                "  CONFIRMED_REQUIREMENT  iam  no TLS\n",
                "  ENVIRONMENT  iam  unnamed\u{FFFD}[2J\n",
            )),
            "{text}"
        );
        assert!(!text.contains("no findings"), "{text}");
        assert!(!text.contains("does not list"), "{text}");
    }

    #[test]
    fn an_environment_finding_of_an_unlisted_assessment_still_prints() {
        let mut detail = sample("COMPLETED", Vec::new());
        let elsewhere = uuid::Uuid::from_u128(9);
        detail.investigation_findings = vec![investigation_finding(
            elsewhere,
            Some("SHARED_IDENTITY"),
            "the worker loses its queue grant",
        )];
        let text = review(&detail, None, &url());
        assert!(
            text.contains(concat!(
                "production: COMPLETED, no findings\n\n",
                "Findings of an environment assessment this review does not list:\n",
                "  SHARED_IDENTITY  iam  the worker loses its queue grant\n",
            )),
            "{text}"
        );
    }

    #[test]
    fn an_incomplete_assessment_marks_its_environment_findings_as_partial() {
        let mut detail = sample("INCOMPLETE", Vec::new());
        detail.investigation_findings = vec![investigation_finding(
            uuid::Uuid::nil(),
            Some("INVESTIGATION"),
            "partial",
        )];
        let text = review(&detail, outcome::terminal(&detail), &url());
        assert!(
            text.contains(
                "  findings so far, not a complete result:\n  INVESTIGATION  iam  partial\n"
            ),
            "{text}"
        );
    }

    fn earlier_finding(title: Option<&str>) -> EarlierFinding {
        EarlierFinding {
            review_id: uuid::Uuid::from_u128(7),
            run_number: 1,
            severity: "SERIOUS".to_owned(),
            title: title.map(str::to_owned),
        }
    }

    #[test]
    fn earlier_runs_open_findings_print_after_the_assessments() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.open_items = Some(crate::model::OpenItems {
            open_findings: 2,
            serious_findings: 2,
            earlier_findings: vec![
                earlier_finding(Some("pool\u{1b}[2J")),
                earlier_finding(None),
            ],
        });
        let text = review(&detail, None, &url());
        let review_line = "           review: 00000000-0000-0000-0000-000000000007\n";
        assert!(
            text.contains(&format!(
                "production: COMPLETED, no findings\n\nStill open from earlier runs, not found again by this review:\n  SERIOUS  run 1  pool\u{FFFD}[2J\n{review_line}  SERIOUS  run 1\n{review_line}"
            )),
            "{text}"
        );
    }

    #[test]
    fn a_review_without_earlier_findings_prints_no_earlier_block() {
        let mut detail = sample("COMPLETED", Vec::new());
        detail.open_items = Some(crate::model::OpenItems {
            open_findings: 0,
            serious_findings: 0,
            earlier_findings: Vec::new(),
        });
        let text = review(&detail, None, &url());
        assert!(!text.contains("earlier runs"), "{text}");
    }
}
