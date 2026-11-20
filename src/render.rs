//! The text form of a review. An incomplete assessment prints its gap and
//! never "no findings": unknown is not safe.

use std::cmp::Reverse;

use url::Url;

use crate::model::{
    Assessment, CodeAssessment, CustomerEvidenceRef, CustomerFinding, Finding, LocalReverification,
    ReviewDetail,
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
    // fix and session commands take this ID, so text output must not need --json
    out.push(format!("           id: {}", finding.id));
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

fn format_evidence_ref(evidence: &CustomerEvidenceRef) -> String {
    let place = evidence
        .repository_path
        .as_deref()
        .map(one_line)
        .map(|path| match (evidence.start_line, evidence.end_line) {
            (Some(start), Some(end)) if end > start => format!("{path}:{start}-{end}"),
            (Some(start), _) => format!("{path}:{start}"),
            (None, _) => path,
        });
    let mut parts = vec![format!(
        "[{}] {} ({})",
        one_line(&evidence.kind),
        one_line(&evidence.label),
        one_line(&evidence.provenance_status)
    )];
    if let Some(place) = place {
        parts.push(format!("at {place}"));
    }
    if let Some(url) = &evidence.url {
        parts.push(one_line(url));
    }
    parts.join("  ")
}

/// Renders one `CustomerFinding` for terminal output, keeping all model- or
/// repository-derived strings terminal-safe.
pub fn finding_detail(finding: &CustomerFinding) -> String {
    let mut out = vec![
        format!(
            "{:<8} {}  [{}]",
            one_line(&finding.severity),
            one_line(&finding.risk_domain),
            one_line(&finding.lifecycle_state),
        ),
        format!("id: {}", finding.id),
    ];
    if let Some(class) = &finding.evidence_class {
        out.push(format!("evidence_class: {}", one_line(class)));
    }
    if let Some(validation) = &finding.latest_validation {
        let actor = validation
            .actor_name
            .as_deref()
            .or(validation.actor_login.as_deref())
            .map_or_else(|| "automatic".to_owned(), one_line);
        out.push(format!(
            "validation: {} ({}, {}, {})",
            one_line(&validation.validation),
            one_line(&validation.source),
            actor,
            one_line(&validation.recorded_at),
        ));
    } else if let Some(validation) = &finding.validation {
        out.push(format!("validation: {}", one_line(validation)));
    }
    out.push(format!("claim: {}", one_line(&finding.claim)));
    out.push(format!("impact: {}", one_line(&finding.impact)));
    if let Some(remediation) = &finding.remediation {
        out.push(format!("fix: {}", one_line(remediation)));
    }
    if let Some(url) = &finding.github_comment_url {
        out.push(format!("github_comment: {}", one_line(url)));
    }
    if !finding.evidence_refs.is_empty() {
        out.push("evidence:".to_owned());
        for evidence in &finding.evidence_refs {
            out.push(format!("  {}", format_evidence_ref(evidence)));
        }
    }
    if let Some(support) = &finding.supporting_evidence {
        if let Some(explanation) = &support.explanation {
            out.push(format!(
                "support: {}",
                one_line(&explanation.untrusted_text)
            ));
        }
        for evidence in &support.evidence_refs {
            out.push(format!("  support_ref: {}", format_evidence_ref(evidence)));
        }
    }
    if let Some(graph) = &finding.causal_graph {
        out.push(format!(
            "causal_graph: {} nodes, {} edges",
            graph.nodes.len(),
            graph.edges.len()
        ));
        for node in &graph.nodes {
            let role = if node.role.is_empty() {
                String::new()
            } else {
                format!(" [{}]", one_line(&node.role))
            };
            out.push(format!(
                "  node {}{}: {}",
                one_line(&node.id),
                role,
                one_line(&node.label)
            ));
        }
        for edge in &graph.edges {
            let relation = edge
                .label
                .as_deref()
                .map(|label| format!(" ({})", one_line(label)))
                .unwrap_or_default();
            out.push(format!(
                "  edge {} -> {}{}",
                one_line(&edge.from),
                one_line(&edge.to),
                relation
            ));
        }
    }
    if !finding.rule_refs.is_empty() {
        let keys: Vec<String> = finding
            .rule_refs
            .iter()
            .map(|rule| one_line(&rule.key))
            .collect();
        out.push(format!("rules: {}", keys.join(", ")));
    }
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

    #[test]
    fn finding_detail_renders_evidence_validation_and_causal_graph() {
        use crate::model::{
            CustomerEvidenceRef, CustomerFinding, CustomerFindingValidation, FindingCausalEdgeView,
            FindingCausalGraphView, FindingCausalNodeView, FindingRuleRefView, FindingSupport,
            UntrustedText,
        };

        let item = CustomerFinding {
            id: uuid::Uuid::nil(),
            finding_fingerprint: None,
            severity: "SERIOUS".to_owned(),
            risk_domain: "data_integrity".to_owned(),
            claim: "x\u{1b}[2J\norder lost".to_owned(),
            impact: "orders are dropped".to_owned(),
            symbols: vec!["save_order".to_owned()],
            lifecycle_state: "NEW".to_owned(),
            remediation: Some("wrap in transaction".to_owned()),
            evidence_class: Some("WORLD_EVIDENCED".to_owned()),
            evidence_refs: vec![CustomerEvidenceRef {
                kind: "CODE".to_owned(),
                label: "handler".to_owned(),
                provenance_status: "VERIFIED".to_owned(),
                repository_path: Some("src/orders.rs".to_owned()),
                start_line: Some(10),
                end_line: Some(14),
                file_sha256: None,
                commit_sha: None,
                companion_repository: None,
                url: None,
                workflow_run_id: None,
                workflow_attempt: None,
                legacy_text: None,
            }],
            causal_graph: Some(FindingCausalGraphView {
                nodes: vec![
                    FindingCausalNodeView {
                        id: "n1".to_owned(),
                        label: "save_order".to_owned(),
                        role: "change".to_owned(),
                    },
                    FindingCausalNodeView {
                        id: "n2".to_owned(),
                        label: "orders_db".to_owned(),
                        role: "failure".to_owned(),
                    },
                ],
                edges: vec![FindingCausalEdgeView {
                    from: "n1".to_owned(),
                    to: "n2".to_owned(),
                    label: Some("writes without tx".to_owned()),
                }],
            }),
            supporting_evidence: Some(FindingSupport {
                explanation: Some(UntrustedText {
                    untrusted_text: "verified against schema".to_owned(),
                }),
                evidence_refs: Vec::new(),
            }),
            latest_validation: Some(CustomerFindingValidation {
                validation: "CONFIRMED".to_owned(),
                source: "GITHUB_COMMENT".to_owned(),
                recorded_at: "2026-11-18T00:00:00Z".to_owned(),
                actor_github_user_id: Some(42),
                actor_login: Some("octocat".to_owned()),
                actor_name: Some("Octo Cat".to_owned()),
                covering_author_kind: None,
                covering_author_login: None,
                covering_comment_created_at: None,
                github_comment_url: None,
            }),
            validation: Some("CONFIRMED".to_owned()),
            github_comment_url: Some(
                "https://github.com/owner/repo/pull/1#discussion_r1".to_owned(),
            ),
            rule_refs: vec![FindingRuleRefView {
                key: "tx-safety".to_owned(),
                revisions: Vec::new(),
            }],
            comment_reactions: Vec::new(),
            local_findings: Vec::new(),
            placement: None,
            comment_evaluation: None,
            thread_observation: None,
        };
        let text = finding_detail(&item);
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(text.contains("SERIOUS  data_integrity  [NEW]"), "{text}");
        assert!(text.contains("evidence_class: WORLD_EVIDENCED"), "{text}");
        assert!(
            text.contains("validation: CONFIRMED (GITHUB_COMMENT, Octo Cat, 2026-11-18T00:00:00Z)"),
            "{text}"
        );
        assert!(text.contains("at src/orders.rs:10-14"), "{text}");
        assert!(text.contains("causal_graph: 2 nodes, 1 edges"), "{text}");
        assert!(text.contains("edge n1 -> n2 (writes without tx)"), "{text}");
        assert!(text.contains("rules: tx-safety"), "{text}");
    }
}
