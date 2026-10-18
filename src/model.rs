//! The parts of the public review API this CLI reads, from
//! `openapi.public.json`. Unknown fields are ignored so a
//! compatible server addition never breaks the CLI; `tests/contract.rs` holds
//! every field here to the committed document.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct ReviewPage {
    pub items: Vec<ReviewSummary>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub filters: ReviewFilters,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReviewFilters {
    pub repositories: Vec<FilterChoice>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FilterChoice {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RepositoryNames {
    pub repositories: Vec<RepositoryName>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RepositoryName {
    pub id: Uuid,
    pub full_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReviewSummary {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub created_at: String,
    pub head_commit_sha: Option<String>,
    pub pull_request_number: Option<i64>,
    pub repository_id: Option<Uuid>,
    pub run_number: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReviewDetail {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub assessment_count: i64,
    pub assessments: Vec<Assessment>,
    pub code_assessment: Option<CodeAssessmentRead>,
    pub base_commit_sha: Option<String>,
    pub head_commit_sha: Option<String>,
    pub open_items: Option<OpenItems>,
    pub pull_request_number: Option<i64>,
    pub repository_full_name: Option<String>,
    pub run_number: Option<i64>,
    #[serde(default)]
    pub subjects: Vec<ReviewSubject>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReviewSubject {
    pub kind: String,
    pub role: String,
    pub file_scope: Option<FileScope>,
}

/// Selection identity at one commit, not a digest of file contents.
#[derive(Debug, Deserialize, Serialize)]
pub struct FileScope {
    pub paths: Vec<String>,
    pub paths_digest: String,
}

/// A malformed or newer CODE record cannot establish completeness. Keep it
/// distinct from the typed record while the JSON output retains the raw API.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CodeAssessmentRead {
    Recorded(CodeAssessment),
    Unavailable(serde_json::Value),
}

impl CodeAssessmentRead {
    pub fn recorded(&self) -> Option<&CodeAssessment> {
        match self {
            Self::Recorded(code)
                if !code.base_commit_sha.is_empty() && !code.head_commit_sha.is_empty() =>
            {
                Some(code)
            }
            Self::Recorded(_) | Self::Unavailable(_) => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CodeAssessment {
    pub id: Uuid,
    pub status: CodeAssessmentStatus,
    pub base_commit_sha: String,
    pub head_commit_sha: String,
    pub findings: Vec<Finding>,
    pub incompleteness_kind: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeAssessmentStatus {
    Pending,
    Running,
    Completed,
    Incomplete,
    Excluded,
}

impl CodeAssessmentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Incomplete => "INCOMPLETE",
            Self::Excluded => "EXCLUDED",
        }
    }
}

/// ENV findings the server still counts as open for the reviewed head, from the
/// current finding decisions. A finding a person dismissed or accepted as a
/// risk is not counted until that decision expires.
#[derive(Debug, Deserialize, Serialize)]
pub struct OpenItems {
    pub open_findings: u64,
    /// The `SERIOUS` findings among `open_findings`.
    pub serious_findings: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Assessment {
    pub id: Uuid,
    pub environment_display_name: String,
    pub status: String,
    pub findings: Vec<Finding>,
    pub checks: Checks,
    pub incompleteness_kind: Option<String>,
    pub reason_codes: Option<Vec<String>>,
    pub release_evidence_gap: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Checks {
    pub receipt_recorded: bool,
    pub status: String,
    pub families: Vec<Check>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Check {
    pub name: String,
    pub outcome: String,
    pub lifecycle: String,
    pub detail: Option<String>,
    pub unresolved_reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Finding {
    pub id: Uuid,
    /// The retained semantic identity that correlates this finding's
    /// occurrences across runs. An older server omits it, and the CLI derives
    /// none in its place.
    pub finding_fingerprint: Option<String>,
    pub severity: String,
    pub risk_domain: String,
    pub claim: String,
    pub impact: String,
    pub lifecycle_state: String,
    pub remediation: Option<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EvidenceRef {
    pub kind: String,
    pub label: String,
    pub provenance_status: Option<String>,
    pub repository_path: Option<String>,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    pub commit_sha: Option<String>,
    pub companion_repository: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RunNowResponse {
    pub review_id: Uuid,
    pub run_number: i64,
    pub existing: bool,
    pub automatic_reviews_paused: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StopResponse {
    pub review_id: Uuid,
    pub status: String,
}

/// Whether the server may reuse a settled review of the live pull-request head.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunNowMode {
    #[default]
    ExistingOrNew,
    Full,
    Extended,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunNowRequest {
    #[serde(default)]
    pub mode: RunNowMode,
    /// Optional investigation focus preserved by the review request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focus_text: Option<String>,
}

/// Local changes to review: a `git diff` against a commit GitHub has.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchReviewRequest {
    pub base_commit_sha: String,
    pub patch: String,
    /// The git hook sending the request. Omitted otherwise, so a server
    /// that predates the field still accepts a plain review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_source: Option<TriggerSource>,
    /// Open findings to re-verify against the patch. Omitted for a plain review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify_finding_ids: Vec<Uuid>,
}

/// The git hook that asked for a patch review.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TriggerSource {
    HookPreCommit,
    HookPrePush,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PatchReviewResponse {
    pub review_id: Uuid,
    pub existing: bool,
    pub patch_digest: String,
}

/// Complete selected files at one exact pushed commit.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileReviewRequest {
    pub commit_sha: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FileReviewResponse {
    pub review_id: Uuid,
    pub existing: bool,
}

/// Pushed commits to review: two exact commits GitHub has, the base an
/// ancestor of the head.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitReviewRequest {
    pub base_commit_sha: String,
    pub head_commit_sha: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitReviewResponse {
    pub review_id: Uuid,
    pub existing: bool,
}
