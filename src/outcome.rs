//! Whether a review has finished, and whether its result is complete. These
//! rules match `waitForReview` in the TypeScript SDK: unknown is never
//! complete, and an assessment with a gap is never reported as clean.

use serde::Serialize;
use uuid::Uuid;

use crate::model::{
    Assessment, CodeAssessment, CodeAssessmentRead, CodeAssessmentStatus, Finding, ReviewDetail,
};
use crate::severity::Severity;

/// A review-reading endpoint is keyed by review id, so its response should
/// always echo the id requested. A cache or routing bug that serves another
/// review's body under that id would otherwise read as a clean result for
/// the wrong subject.
#[derive(Debug, thiserror::Error)]
#[error("requested review {requested}, but the server returned review {returned}")]
pub(crate) struct WrongReview {
    pub(crate) requested: Uuid,
    pub(crate) returned: Uuid,
}

/// Confirms `detail` is the review `requested`, not merely a review that
/// happened to come back from that endpoint.
pub(crate) fn same_review(detail: &ReviewDetail, requested: Uuid) -> Result<(), WrongReview> {
    if detail.id == requested {
        Ok(())
    } else {
        Err(WrongReview {
            requested,
            returned: detail.id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Incomplete,
    Failed,
    Stopped,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Incomplete => "INCOMPLETE",
            Self::Failed => "FAILED",
            Self::Stopped => "STOPPED",
        }
    }
}

const COMPLETE_CHECKS: [&str; 3] = ["READY", "BLOCKED", "NOT_APPLICABLE"];
const COMPLETE_LIFECYCLES: [&str; 4] = ["GATING", "SHADOW", "QUARANTINED", "RETIRED"];
const KNOWN_ASSESSMENTS: [&str; 8] = [
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "INCOMPLETE",
    "FAILED",
    "STOPPED",
    "SUPERSEDED",
    "EXCLUDED",
];
// The server's classification policy owns this marker. The API publishes it in
// place of every CODE finding's risk domain, claim and impact once the review's
// protected evidence is missing or has expired.
const WITHHELD_MARKER: &str = "[withheld: environment value]";

/// `None` while the review is still running.
pub fn terminal(review: &ReviewDetail) -> Option<Outcome> {
    match review.status.as_str() {
        "PENDING" | "RUNNING" => None,
        "FAILED" => Some(Outcome::Failed),
        "STOPPED" | "SUPERSEDED" => Some(Outcome::Stopped),
        "COMPLETED"
            if usize::try_from(review.assessment_count).ok() == Some(review.assessments.len()) =>
        {
            // CODE cannot replace a missing ENV assessment or its receipts.
            let complete = if review.assessments.is_empty() {
                code_assessment(review).is_some_and(|code| code_gap(code).is_none())
            } else {
                review
                    .assessments
                    .iter()
                    .all(|assessment| gap(assessment).is_none())
            };
            Some(if complete {
                Outcome::Completed
            } else {
                Outcome::Incomplete
            })
        }
        _ => Some(Outcome::Incomplete),
    }
}

/// A review-level gap, apart from the CODE and environment assessment gaps.
pub(crate) fn review_gap(review: &ReviewDetail) -> Option<&'static str> {
    if usize::try_from(review.assessment_count).ok() != Some(review.assessments.len()) {
        return Some("ASSESSMENT_HISTORY_UNAVAILABLE");
    }
    if ![
        "PENDING",
        "RUNNING",
        "COMPLETED",
        "FAILED",
        "STOPPED",
        "SUPERSEDED",
    ]
    .contains(&review.status.as_str())
        && review.assessments.iter().all(|item| gap(item).is_none())
        && (!review.assessments.is_empty()
            || code_assessment(review).is_some_and(|code| code_gap(code).is_none()))
    {
        return Some("REVIEW_STATE_UNAVAILABLE");
    }
    None
}

/// The CODE record, only when it is of this review's subject and its findings
/// are published. The code lane pins its assessment to the review's own head
/// and base, so a record of other commits is unavailable: it neither completes
/// the review nor supplies findings. A review's base is null until pinned, so
/// only a recorded base is compared. A withheld finding names no domain, claim
/// or location, so a record that holds one is unavailable too.
pub(crate) fn code_assessment(review: &ReviewDetail) -> Option<&CodeAssessment> {
    let same = |recorded: Option<&str>, code: &str| {
        recorded.is_none_or(|sha| sha.eq_ignore_ascii_case(code))
    };
    review
        .code_assessment
        .as_ref()
        .and_then(CodeAssessmentRead::recorded)
        .filter(|code| {
            same(review.head_commit_sha.as_deref(), &code.head_commit_sha)
                && same(review.base_commit_sha.as_deref(), &code.base_commit_sha)
                && !code
                    .findings
                    .iter()
                    .any(|finding| finding.risk_domain == WITHHELD_MARKER)
        })
}

/// Whether the review reports its CODE result as unavailable: the API sent a
/// CODE record this CLI cannot use, or nothing else stands in the result.
pub(crate) fn code_unavailable(review: &ReviewDetail) -> bool {
    code_assessment(review).is_none()
        && (review.code_assessment.is_some()
            || (review.assessment_count == 0 && review.assessments.is_empty()))
}

/// Whether an open finding of a complete CODE assessment reaches `threshold`,
/// for a review that has no finding decisions: a patch, range, commit or file
/// review, or a Git hook. Its recorded lifecycle and severity decide. A
/// pull-request review is measured by the server's `open_items` counts
/// instead, which hold both lanes and their decisions. Complete environments
/// complete a review even beside a partial CODE assessment, and a partial
/// assessment's findings are not its whole result.
pub(crate) fn code_reaches(code: &CodeAssessment, threshold: Severity) -> bool {
    code_gap(code).is_none()
        && code
            .findings
            .iter()
            .any(|finding| !resolved(finding) && threshold.reached_by(&finding.severity))
}

/// Whether the finding's recorded lifecycle says it is fixed.
pub(crate) fn resolved(finding: &Finding) -> bool {
    finding.lifecycle_state == "RESOLVED"
}

/// Whether an unresolved finding of a review without finding decisions
/// reaches `threshold`.
pub(crate) fn findings_reach(review: &ReviewDetail, threshold: Severity) -> bool {
    let environment = review.assessments.iter().any(|assessment| {
        assessment.findings.iter().any(|finding| {
            finding.lifecycle_state != "RESOLVED" && threshold.reached_by(&finding.severity)
        })
    });
    environment || code_assessment(review).is_some_and(|code| code_reaches(code, threshold))
}

/// Categorized difference between findings across two review runs.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct FindingDiff<'a> {
    /// Findings that were open in the previous run but are resolved or absent in the current run.
    pub resolved: Vec<&'a Finding>,
    /// Findings that were open in the previous run and remain open in the current run.
    pub persistent: Vec<&'a Finding>,
    /// New or reintroduced findings in the current run that were not open in the previous run.
    pub regressions: Vec<&'a Finding>,
}

impl<'a> FindingDiff<'a> {
    /// Whether there are no findings in any category.
    pub fn is_empty(&self) -> bool {
        self.resolved.is_empty() && self.persistent.is_empty() && self.regressions.is_empty()
    }
}

/// Collects all findings across CODE and environment assessments of a review.
pub fn all_findings(review: &ReviewDetail) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(code) = code_assessment(review) {
        findings.extend(code.findings.iter().cloned());
    }
    for assessment in &review.assessments {
        findings.extend(assessment.findings.iter().cloned());
    }
    findings
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct FallbackKey<'a> {
    domain: &'a str,
    claim: &'a str,
    path: Option<&'a str>,
    start_line: Option<u32>,
}

fn fallback_key(finding: &Finding) -> FallbackKey<'_> {
    let primary = finding.evidence_refs.first();
    FallbackKey {
        domain: &finding.risk_domain,
        claim: &finding.claim,
        path: primary.and_then(|evidence| evidence.repository_path.as_deref()),
        start_line: primary.and_then(|evidence| evidence.start_line),
    }
}

fn claim_fingerprint_match(
    curr: &Finding,
    previous: &[Finding],
    prev_matched: &mut [bool],
) -> bool {
    if let Some(fp_curr) = curr.finding_fingerprint.as_deref() {
        for (i, prev) in previous.iter().enumerate() {
            if !prev_matched[i]
                && !resolved(prev)
                && prev.finding_fingerprint.as_deref() == Some(fp_curr)
            {
                prev_matched[i] = true;
                return true;
            }
        }
    }
    false
}

fn claim_fallback_match(curr: &Finding, previous: &[Finding], prev_matched: &mut [bool]) -> bool {
    let key_curr = fallback_key(curr);
    for (i, prev) in previous.iter().enumerate() {
        // Fallback matching is only valid when at least one finding lacks a fingerprint.
        // If both sides have explicit but different fingerprints, they are distinct issues.
        let has_missing_fingerprint =
            curr.finding_fingerprint.is_none() || prev.finding_fingerprint.is_none();
        if !prev_matched[i]
            && !resolved(prev)
            && has_missing_fingerprint
            && fallback_key(prev) == key_curr
        {
            prev_matched[i] = true;
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FindingStatus {
    ExplicitResolved,
    Persistent,
    Regression,
    Ignored,
}

/// Diffs findings across two review runs, categorizing them into resolved,
/// persistent, and new regressions.
///
/// Findings are correlated primarily by their semantic `finding_fingerprint`.
/// If fingerprints are missing or mismatched across server versions, it falls
/// back to matching on the risk domain, claim, and primary evidence location.
pub fn diff_findings<'a>(previous: &'a [Finding], current: &'a [Finding]) -> FindingDiff<'a> {
    let mut diff = FindingDiff::default();
    let mut prev_matched = vec![false; previous.len()];
    let mut curr_states: Vec<FindingStatus> = current
        .iter()
        .map(|f| {
            if resolved(f) {
                FindingStatus::Ignored
            } else {
                FindingStatus::Regression
            }
        })
        .collect();

    // Pass 1A: Match open current findings by exact fingerprint.
    // Open findings match first so resolved findings cannot consume their match.
    for (j, curr) in current.iter().enumerate() {
        if !resolved(curr) && claim_fingerprint_match(curr, previous, &mut prev_matched) {
            curr_states[j] = if curr.lifecycle_state == "REINTRODUCED" {
                FindingStatus::Regression
            } else {
                FindingStatus::Persistent
            };
        }
    }

    // Pass 1B: Fallback correlation for remaining unmatched open findings.
    // Only pairs findings when at least one side lacks a fingerprint.
    for (j, curr) in current.iter().enumerate() {
        if curr_states[j] == FindingStatus::Regression
            && claim_fallback_match(curr, previous, &mut prev_matched)
        {
            curr_states[j] = if curr.lifecycle_state == "REINTRODUCED" {
                FindingStatus::Regression
            } else {
                FindingStatus::Persistent
            };
        }
    }

    // Pass 2A: Match resolved current findings by exact fingerprint against remaining baseline.
    for (j, curr) in current.iter().enumerate() {
        if resolved(curr) && claim_fingerprint_match(curr, previous, &mut prev_matched) {
            curr_states[j] = FindingStatus::ExplicitResolved;
        }
    }

    // Pass 2B: Match resolved current findings by fallback against remaining baseline.
    for (j, curr) in current.iter().enumerate() {
        if resolved(curr)
            && curr_states[j] == FindingStatus::Ignored
            && claim_fallback_match(curr, previous, &mut prev_matched)
        {
            curr_states[j] = FindingStatus::ExplicitResolved;
        }
    }

    // Assemble the diff preserving original slice ordering.
    // Note: Unmatched resolved target findings remain `Ignored` and are not included in the diff.
    for (j, curr) in current.iter().enumerate() {
        match curr_states[j] {
            FindingStatus::ExplicitResolved => diff.resolved.push(curr),
            FindingStatus::Persistent => diff.persistent.push(curr),
            FindingStatus::Regression => diff.regressions.push(curr),
            FindingStatus::Ignored => {}
        }
    }

    // Any open previous finding that was not matched in current was fixed/removed in code.
    for (i, prev) in previous.iter().enumerate() {
        if !prev_matched[i] && !resolved(prev) {
            diff.resolved.push(prev);
        }
    }

    diff
}

/// CODE has no World receipts or environment checks. Its recorded status,
/// public reason codes and incompleteness are the only completion evidence for
/// the code lane. Reason codes come first, as for an environment assessment.
pub(crate) fn code_gap(code: &CodeAssessment) -> Option<Vec<String>> {
    let mut reasons = code.reason_codes.clone().unwrap_or_default();
    reasons.extend(
        code.incompleteness_kind
            .clone()
            .filter(|kind| !kind.is_empty()),
    );
    if reasons.is_empty() && code.status != CodeAssessmentStatus::Completed {
        reasons.push("CODE_ASSESSMENT_STATE_UNAVAILABLE".to_owned());
    }
    (!reasons.is_empty()).then_some(reasons)
}

/// Why an assessment's result is incomplete, or `None` when it is complete.
pub fn gap(assessment: &Assessment) -> Option<Vec<String>> {
    let checks = &assessment.checks;
    let check_gap = !checks.receipt_recorded
        || !COMPLETE_CHECKS.contains(&checks.status.as_str())
        || checks.families.iter().any(|check| {
            !COMPLETE_CHECKS.contains(&check.outcome.as_str())
                || !COMPLETE_LIFECYCLES.contains(&check.lifecycle.as_str())
        });
    let reasons = assessment.reason_codes.clone().unwrap_or_default();
    let complete = assessment.status == "COMPLETED"
        && !check_gap
        && reasons.is_empty()
        && assessment.release_evidence_gap.is_none()
        && assessment.incompleteness_kind.is_none();
    if complete {
        return None;
    }
    let mut why = reasons;
    if let Some(kind) = &assessment.incompleteness_kind {
        why.push(kind.clone());
    }
    if let Some(release) = &assessment.release_evidence_gap {
        why.push(release.clone());
    }
    if check_gap {
        why.push(if checks.receipt_recorded {
            "CHECKS_UNRESOLVED".to_owned()
        } else {
            "CHECK_RECEIPT_ABSENT".to_owned()
        });
    }
    if why.is_empty() {
        why.push(if KNOWN_ASSESSMENTS.contains(&assessment.status.as_str()) {
            "ASSESSMENT_RESULT_UNAVAILABLE".to_owned()
        } else {
            "UNKNOWN_ASSESSMENT_STATUS".to_owned()
        });
    }
    Some(why)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Checks;

    #[test]
    fn shared_outcome_contract() {
        use serde_json::{Value, json};

        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/review-outcomes.json")).unwrap();
        let mut schema: Value = serde_json::from_str(include_str!(concat!(
            env!("OUT_DIR"),
            "/openapi.public.json"
        )))
        .unwrap();
        schema["$ref"] = json!("#/components/schemas/CustomerReviewDetail");
        // Fixtures use only declared properties: removing an optional field
        // from the public contract must fail here too.
        for definition in schema["components"]["schemas"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            if definition["type"] == "object" && definition.get("additionalProperties").is_none() {
                definition["additionalProperties"] = json!(false);
            }
        }
        let validator = jsonschema::validator_for(&schema).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let document = &case["review"];
            assert!(
                validator.is_valid(document),
                "{}: {:?}",
                case["name"],
                validator.validate(document)
            );
            let review: ReviewDetail = serde_json::from_value(document.clone()).unwrap();
            assert_eq!(
                json!(terminal(&review).map(Outcome::as_str)),
                case["outcome"],
                "{}",
                case["name"]
            );
            let mut gaps = Vec::new();
            for assessment in &review.assessments {
                if let Some(reasons) = gap(assessment) {
                    gaps.push(json!({"assessment_id": assessment.id, "reason_codes": reasons}));
                }
            }
            if review.assessment_count == 0 && review.assessments.is_empty() {
                if let Some(code) = code_assessment(&review) {
                    if let Some(reasons) = code_gap(code) {
                        gaps.push(json!({"assessment_id": code.id, "reason_codes": reasons}));
                    }
                } else {
                    gaps.push(json!({"assessment_id": null, "reason_codes": ["CODE_ASSESSMENT_UNAVAILABLE"]}));
                }
            }
            if let Some(reason) = review_gap(&review) {
                gaps.push(json!({"assessment_id": null, "reason_codes": [reason]}));
            }
            assert_eq!(json!(gaps), case["gaps"], "{}", case["name"]);
        }
    }

    fn assessment(status: &str) -> Assessment {
        Assessment {
            id: Uuid::nil(),
            environment_display_name: "production".to_owned(),
            status: status.to_owned(),
            findings: Vec::new(),
            checks: Checks {
                receipt_recorded: true,
                status: "READY".to_owned(),
                families: Vec::new(),
            },
            incompleteness_kind: None,
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

    fn finding(severity: &str, lifecycle_state: &str) -> Finding {
        Finding {
            id: Uuid::nil(),
            finding_fingerprint: None,
            severity: severity.to_owned(),
            risk_domain: "resource_capacity".to_owned(),
            claim: "the pool outgrows the database's connection limit".to_owned(),
            impact: "new connections are refused during the rollout".to_owned(),
            lifecycle_state: lifecycle_state.to_owned(),
            remediation: None,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn findings_reach_counts_unresolved_findings_at_or_above_the_threshold() {
        let with = |severity: &str, lifecycle_state: &str| {
            let mut production = assessment("COMPLETED");
            production.findings = vec![finding(severity, lifecycle_state)];
            let mut detail = review("COMPLETED", vec![production], 1);
            detail.kind = "COMMIT".to_owned();
            detail
        };
        for (severity, lifecycle_state, threshold, reaches) in [
            ("SERIOUS", "NEW", Severity::Serious, true),
            ("SERIOUS", "NEW", Severity::Warning, true),
            ("WARNING", "NEW", Severity::Warning, true),
            ("WARNING", "UNCHANGED", Severity::Serious, false),
            ("SERIOUS", "REINTRODUCED", Severity::Serious, true),
            ("SERIOUS", "RESOLVED", Severity::Warning, false),
            ("CRITICAL", "NEW", Severity::Serious, true),
        ] {
            assert_eq!(
                findings_reach(&with(severity, lifecycle_state), threshold),
                reaches,
                "{severity} {lifecycle_state} {threshold:?}"
            );
        }
        let clean = review("COMPLETED", vec![assessment("COMPLETED")], 1);
        assert!(!findings_reach(&clean, Severity::Warning));
    }

    #[test]
    fn running_reviews_are_not_terminal() {
        assert_eq!(terminal(&review("RUNNING", Vec::new(), 1)), None);
        assert_eq!(terminal(&review("PENDING", Vec::new(), 1)), None);
    }

    #[test]
    fn a_complete_review_needs_every_assessment_complete() {
        assert_eq!(
            terminal(&review("COMPLETED", vec![assessment("COMPLETED")], 1)),
            Some(Outcome::Completed)
        );
        assert_eq!(
            terminal(&review("COMPLETED", vec![assessment("COMPLETED")], 2)),
            Some(Outcome::Incomplete)
        );
        assert_eq!(
            terminal(&review("COMPLETED", Vec::new(), 0)),
            Some(Outcome::Incomplete)
        );
        assert_eq!(
            terminal(&review("SURPRISE", Vec::new(), 0)),
            Some(Outcome::Incomplete)
        );
    }

    #[test]
    fn gaps_name_their_cause() {
        let mut missing_receipt = assessment("COMPLETED");
        missing_receipt.checks.receipt_recorded = false;
        assert_eq!(
            gap(&missing_receipt),
            Some(vec!["CHECK_RECEIPT_ABSENT".to_owned()])
        );

        let mut world_down = assessment("INCOMPLETE");
        world_down.incompleteness_kind = Some("WORLD_UNAVAILABLE".to_owned());
        assert_eq!(gap(&world_down), Some(vec!["WORLD_UNAVAILABLE".to_owned()]));

        assert_eq!(
            gap(&assessment("MYSTERY")),
            Some(vec!["UNKNOWN_ASSESSMENT_STATUS".to_owned()])
        );
        assert_eq!(gap(&assessment("COMPLETED")), None);
    }

    fn finding_with(severity: &str, lifecycle: &str, fp: Option<&str>, claim: &str) -> Finding {
        Finding {
            id: Uuid::nil(),
            finding_fingerprint: fp.map(str::to_owned),
            severity: severity.to_owned(),
            risk_domain: "resource_capacity".to_owned(),
            claim: claim.to_owned(),
            impact: "connection limit exceeded".to_owned(),
            lifecycle_state: lifecycle.to_owned(),
            remediation: None,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn diff_findings_categorization_and_empty_runs() {
        let f1 = finding_with("HIGH", "NEW", Some("fp1"), "issue 1");
        let f2 = finding_with("MEDIUM", "NEW", Some("fp2"), "issue 2");
        let f3 = finding_with("SERIOUS", "NEW", Some("fp3"), "issue 3");

        // 1. Both runs empty
        let empty_a: [Finding; 0] = [];
        let empty_b: [Finding; 0] = [];
        assert!(diff_findings(&empty_a, &empty_b).is_empty());

        // 2. Clean baseline regressed (0 -> 1)
        let curr_regressed = [f1.clone()];
        let diff = diff_findings(&empty_a, &curr_regressed);
        assert_eq!(diff.regressions.len(), 1);
        assert_eq!(
            diff.regressions[0].finding_fingerprint.as_deref(),
            Some("fp1")
        );
        assert!(diff.resolved.is_empty() && diff.persistent.is_empty());

        // 3. All resolved (1 -> 0)
        let prev_resolved = [f1.clone()];
        let diff = diff_findings(&prev_resolved, &empty_b);
        assert_eq!(diff.resolved.len(), 1);
        assert_eq!(diff.resolved[0].finding_fingerprint.as_deref(), Some("fp1"));
        assert!(diff.persistent.is_empty() && diff.regressions.is_empty());

        // 4. Mixed: f1 resolved, f2 persistent, f3 regression
        let prev_mixed = [f1.clone(), f2.clone()];
        let curr_mixed = [f2.clone(), f3];
        let diff = diff_findings(&prev_mixed, &curr_mixed);
        assert_eq!(diff.resolved.len(), 1);
        assert_eq!(diff.resolved[0].finding_fingerprint.as_deref(), Some("fp1"));
        assert_eq!(diff.persistent.len(), 1);
        assert_eq!(
            diff.persistent[0].finding_fingerprint.as_deref(),
            Some("fp2")
        );
        assert_eq!(diff.regressions.len(), 1);
        assert_eq!(
            diff.regressions[0].finding_fingerprint.as_deref(),
            Some("fp3")
        );

        // 5. Identical runs
        let prev_identical = [f1.clone(), f2.clone()];
        let curr_identical = [f1, f2];
        let diff = diff_findings(&prev_identical, &curr_identical);
        assert_eq!(diff.persistent.len(), 2);
        assert_eq!(
            diff.persistent[0].finding_fingerprint.as_deref(),
            Some("fp1")
        );
        assert_eq!(
            diff.persistent[1].finding_fingerprint.as_deref(),
            Some("fp2")
        );
        assert!(diff.resolved.is_empty() && diff.regressions.is_empty());
    }

    #[test]
    fn diff_findings_server_version_mismatches_and_reintroduced() {
        // Fallback matching when one side lacks fingerprint (legacy <-> upgraded)
        let legacy = [finding_with("HIGH", "NEW", None, "issue 1")];
        let upgraded = [finding_with("HIGH", "NEW", Some("fp1"), "issue 1")];

        let diff_upgraded = diff_findings(&legacy, &upgraded);
        assert_eq!(diff_upgraded.persistent.len(), 1);
        assert_eq!(diff_upgraded.persistent[0].claim, "issue 1");
        assert!(diff_upgraded.resolved.is_empty() && diff_upgraded.regressions.is_empty());

        let diff_legacy = diff_findings(&upgraded, &legacy);
        assert_eq!(diff_legacy.persistent.len(), 1);
        assert_eq!(diff_legacy.persistent[0].claim, "issue 1");
        assert!(diff_legacy.resolved.is_empty() && diff_legacy.regressions.is_empty());

        // Reintroduced finding is a regression, not persistent
        let resolved = [finding_with("HIGH", "RESOLVED", Some("fp1"), "issue 1")];
        let reintroduced = [finding_with("HIGH", "REINTRODUCED", Some("fp1"), "issue 1")];
        let diff_reintroduced = diff_findings(&resolved, &reintroduced);
        assert_eq!(diff_reintroduced.regressions.len(), 1);
        assert_eq!(
            diff_reintroduced.regressions[0]
                .finding_fingerprint
                .as_deref(),
            Some("fp1")
        );
        assert!(diff_reintroduced.persistent.is_empty() && diff_reintroduced.resolved.is_empty());

        // Duplicate occurrences cardinality: 2 in prev, 1 in curr -> 1 persistent, 1 resolved
        let prev_dup = [
            finding_with("HIGH", "NEW", None, "dup issue"),
            finding_with("HIGH", "NEW", None, "dup issue"),
        ];
        let curr_dup = [finding_with("HIGH", "NEW", None, "dup issue")];
        let diff_dup = diff_findings(&prev_dup, &curr_dup);
        assert_eq!(diff_dup.persistent.len(), 1);
        assert_eq!(diff_dup.resolved.len(), 1);
        assert!(diff_dup.regressions.is_empty());

        // Duplicate test: 1 in prev, 2 in curr -> 1 persistent, 1 regression
        let prev_single = [finding_with("HIGH", "NEW", None, "dup issue")];
        let curr_double = [
            finding_with("HIGH", "NEW", None, "dup issue"),
            finding_with("HIGH", "NEW", None, "dup issue"),
        ];
        let diff_dup2 = diff_findings(&prev_single, &curr_double);
        assert_eq!(diff_dup2.persistent.len(), 1);
        assert_eq!(diff_dup2.regressions.len(), 1);
        assert!(diff_dup2.resolved.is_empty());

        // Conflicting fingerprints: even if claim/location match, distinct fingerprints mean distinct issues
        let prev_fp1 = [finding_with("HIGH", "NEW", Some("fp1"), "shared claim")];
        let curr_fp2 = [finding_with("HIGH", "NEW", Some("fp2"), "shared claim")];
        let diff_conflict = diff_findings(&prev_fp1, &curr_fp2);
        assert_eq!(diff_conflict.resolved.len(), 1);
        assert_eq!(
            diff_conflict.resolved[0].finding_fingerprint.as_deref(),
            Some("fp1")
        );
        assert_eq!(diff_conflict.regressions.len(), 1);
        assert_eq!(
            diff_conflict.regressions[0].finding_fingerprint.as_deref(),
            Some("fp2")
        );
        assert!(diff_conflict.persistent.is_empty());

        // Fingerprint precedence over fallback: ensure exact match takes priority over fallback-only candidate
        let prev_candidates = [
            finding_with("HIGH", "NEW", None, "shared claim"),
            finding_with("HIGH", "NEW", Some("fp_target"), "shared claim"),
        ];
        let curr_target = [finding_with(
            "HIGH",
            "NEW",
            Some("fp_target"),
            "shared claim",
        )];
        let diff_precedence = diff_findings(&prev_candidates, &curr_target);
        assert_eq!(diff_precedence.persistent.len(), 1);
        assert_eq!(
            diff_precedence.persistent[0].finding_fingerprint.as_deref(),
            Some("fp_target")
        );
        assert_eq!(diff_precedence.resolved.len(), 1);
        assert!(diff_precedence.resolved[0].finding_fingerprint.is_none());
        assert!(diff_precedence.regressions.is_empty());

        // Reintroduced finding matching an open baseline is still a regression, not persistent
        let prev_open = [finding_with("HIGH", "NEW", Some("fp1"), "issue 1")];
        let curr_reint = [finding_with("HIGH", "REINTRODUCED", Some("fp1"), "issue 1")];
        let diff_reint = diff_findings(&prev_open, &curr_reint);
        assert_eq!(diff_reint.regressions.len(), 1);
        assert_eq!(
            diff_reint.regressions[0].finding_fingerprint.as_deref(),
            Some("fp1")
        );
        assert!(diff_reint.persistent.is_empty());
        assert!(diff_reint.resolved.is_empty());

        // Unmatched target resolved finding is omitted, not reported as newly resolved
        let empty_prev: [Finding; 0] = [];
        let curr_resolved_only = [finding_with("HIGH", "RESOLVED", Some("fp1"), "issue 1")];
        let diff_unmatched_resolved = diff_findings(&empty_prev, &curr_resolved_only);
        assert!(diff_unmatched_resolved.is_empty());
    }
}
