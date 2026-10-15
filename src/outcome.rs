//! Whether a review has finished, and whether its result is complete. These
//! rules match `waitForReview` in the TypeScript SDK: unknown is never
//! complete, and an assessment with a gap is never reported as clean.

use crate::model::{
    Assessment, CodeAssessment, CodeAssessmentRead, CodeAssessmentStatus, ReviewDetail,
};
use crate::severity::Severity;

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
const KNOWN_ASSESSMENTS: [&str; 5] = ["PENDING", "RUNNING", "COMPLETED", "INCOMPLETE", "FAILED"];
// The server's classification policy owns this marker. The API publishes it in
// place of every CODE finding's risk domain, claim and impact once the review's
// protected evidence is missing or has expired.
const WITHHELD_MARKER: &str = "[withheld: environment value]";

/// `None` while the review is still running.
pub fn terminal(review: &ReviewDetail) -> Option<Outcome> {
    match review.status.as_str() {
        "PENDING" | "RUNNING" => None,
        "FAILED" => Some(Outcome::Failed),
        "STOPPED" => Some(Outcome::Stopped),
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

/// Whether an open finding of a complete CODE assessment reaches `threshold`.
/// CODE findings have no projected decisions, so their recorded lifecycle and
/// severity decide. Complete environments complete a review even beside a
/// partial CODE assessment, and a partial assessment's findings are not its
/// whole result.
pub(crate) fn code_reaches(code: &CodeAssessment, threshold: Severity) -> bool {
    code_gap(code).is_none()
        && code.findings.iter().any(|finding| {
            finding.lifecycle_state != "RESOLVED" && threshold.reached_by(&finding.severity)
        })
}

/// CODE has no World receipts or environment checks. Its recorded status and
/// incompleteness are the only completion evidence for the code lane.
pub(crate) fn code_gap(code: &CodeAssessment) -> Option<&str> {
    if let Some(kind) = code
        .incompleteness_kind
        .as_deref()
        .filter(|kind| !kind.is_empty())
    {
        return Some(kind);
    }
    match code.status {
        CodeAssessmentStatus::Completed => None,
        CodeAssessmentStatus::Pending
        | CodeAssessmentStatus::Running
        | CodeAssessmentStatus::Incomplete
        | CodeAssessmentStatus::Excluded => Some("CODE_ASSESSMENT_STATE_UNAVAILABLE"),
    }
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

    fn assessment(status: &str) -> Assessment {
        Assessment {
            id: uuid::Uuid::nil(),
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
            id: uuid::Uuid::nil(),
            kind: "PULL_REQUEST".to_owned(),
            status: status.to_owned(),
            assessment_count: count,
            assessments,
            code_assessment: None,
            base_commit_sha: None,
            head_commit_sha: None,
            open_items: None,
            pull_request_number: Some(7),
            repository_full_name: Some("acme/web".to_owned()),
            run_number: Some(1),
        }
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
}
