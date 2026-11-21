//! The parts of the public review API this CLI reads, from
//! `openapi.public.json`. Unknown fields are ignored so a
//! compatible server addition never breaks the CLI; `tests/contract.rs` holds
//! every field here to the committed document.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct CoverageUploadRequest {
    pub tested_sha: String,
    pub reports: Vec<UploadedReport>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UploadedReport {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CoverageUploadResponse {
    pub report_id: Uuid,
    pub tested_sha: String,
    pub created: bool,
    pub formats: Vec<String>,
    pub instrumented_lines: u64,
    pub covered_lines: u64,
}

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
    /// Set when this `REVISION_SCAN` is a repository audit, whose findings
    /// are in its report rather than the review's assessments.
    #[serde(default)]
    pub audit_mode: Option<String>,
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
    /// The review's repository. Set only on a single-review read, and
    /// absent there when the review names no repository. Stable across a
    /// repository rename, unlike `repository_full_name`.
    pub repository_id: Option<Uuid>,
    pub repository_full_name: Option<String>,
    pub run_number: Option<i64>,
    #[serde(default)]
    pub subjects: Vec<ReviewSubject>,
    /// The findings a `--verify` patch review re-verified locally. Absent on
    /// every other review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_reverifications: Vec<LocalReverification>,
}

/// One finding a patch review re-verified against the local changes. The
/// outcome is local: the pull request's finding is unchanged.
#[derive(Debug, Deserialize, Serialize)]
pub struct LocalReverification {
    pub finding_id: Uuid,
    pub iteration: i32,
    /// `RESOLVED_VERIFIED`, `STILL_PRESENT`, `NOT_VERIFIED` or `PENDING`.
    pub outcome: String,
    /// Each check the finding cited and its result on the patched head, kept
    /// as the API returned it for `--json`.
    #[serde(default)]
    pub checks: serde_json::Value,
    /// The check a code reproduction stored for the finding, which the
    /// pushed head runs again. The patch review does not run it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_check: Option<StoredCheck>,
}

/// A finding's stored check and the newest result it gave.
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredCheck {
    pub check_id: Uuid,
    /// The command the sandbox ran the test with. Untrusted text.
    pub command: String,
    pub last_result: Option<StoredCheckResult>,
}

/// The newest settled rerun of a stored check, or its reproduction's run.
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredCheckResult {
    /// `RERUN` or `REPRODUCTION`.
    pub source: String,
    /// `FAILED`, `DID_NOT_FAIL` or `UNAVAILABLE`.
    pub result: String,
    pub commit_sha: Option<String>,
    pub reason: Option<String>,
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
    /// Public causes of an incomplete result, such as `OUT_OF_CREDITS`.
    pub reason_codes: Option<Vec<String>>,
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

/// A whole-repository scan of one ref or exact commit. Sending the same
/// `request_id` again returns the first resolution instead of scanning again.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub request_id: Uuid,
    pub budget_credits: i64,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

/// What a scan request resolved to. `outcome` is `CREATED`, `EXISTING` or
/// `REPOSITORY_UNAVAILABLE`; only the first two name a review.
#[derive(Debug, Deserialize, Serialize)]
pub struct ScanResponse {
    pub resolution_id: Uuid,
    pub outcome: String,
    #[serde(default)]
    pub review_id: Option<Uuid>,
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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunNowRequest {
    #[serde(default)]
    pub mode: RunNowMode,
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
    /// Open findings of one pull request to re-verify against the patch.
    /// Omitted when empty, so a server that predates the field still accepts
    /// a plain review.
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
    #[serde(default)]
    pub verify: Vec<PatchVerification>,
}

/// One finding a patch review re-verifies, and the request's number among
/// those for its series on this patch.
#[derive(Debug, Deserialize, Serialize)]
pub struct PatchVerification {
    pub finding_id: Uuid,
    pub iteration: i32,
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

/// The deploys of one commit that Proofline recorded, across the
/// organization's environments.
#[derive(Debug, Deserialize, Serialize)]
pub struct CommitDeployVerifications {
    pub recorded: bool,
    pub deploys: Vec<CommitDeploy>,
}

/// One deploy of the commit. State, checkpoint, result and gap names stay
/// strings, so a value a newer server adds is read, and judged as nothing the
/// CLI recognizes, rather than refused.
#[derive(Debug, Deserialize, Serialize)]
pub struct CommitDeploy {
    pub environment_id: Uuid,
    #[serde(default)]
    pub github_environment: Option<String>,
    #[serde(default)]
    pub deployment_task: Option<String>,
    #[serde(default)]
    pub workflow_run_id: Option<i64>,
    #[serde(default)]
    pub workflow_run_attempt: Option<i64>,
    #[serde(default)]
    pub workflow_run_attempts: Vec<i64>,
    pub state: String,
    pub regressed: bool,
    pub checkpoints: Vec<DeployCheckpoint>,
    pub gaps: Vec<String>,
    #[serde(default)]
    pub deploy_url: Option<String>,
    /// Present when the deploy is a rollback: the previous deploy of the same
    /// task ran a commit merged into the branch after this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<CommitDeployRollback>,
}

/// The deploy a rollback restores, when the read names one, and the deploys
/// it rolls back, newest first.
#[derive(Debug, Deserialize, Serialize)]
pub struct CommitDeployRollback {
    #[serde(default)]
    pub restores: Option<RollbackDeploy>,
    #[serde(default)]
    pub rolls_back: Vec<RollbackDeploy>,
}

/// One deploy a rollback names. Every field is optional, so a shape a newer
/// server sends is read rather than refused.
#[derive(Debug, Deserialize, Serialize)]
pub struct RollbackDeploy {
    #[serde(default)]
    pub commit_sha: Option<String>,
    #[serde(default)]
    pub landed_at: Option<String>,
    #[serde(default)]
    pub deploy_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeployCheckpoint {
    pub checkpoint: String,
    #[serde(default)]
    pub result: Option<String>,
    pub due_at: String,
}
