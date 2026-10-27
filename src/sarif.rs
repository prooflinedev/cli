//! Read-only SARIF 2.1.0 for one retained pull-request review. This closed
//! projection never serializes the raw API document or World evidence values.

use std::collections::BTreeSet;

use serde::Serialize;
use uuid::Uuid;

use crate::model::{Assessment, CodeAssessment, EvidenceRef, Finding, ReviewDetail};
use crate::outcome::{self, Outcome};

const SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
// The domains-v5 public catalog. The CLI has no dependency on the server crate.
const DOMAINS: [&str; 18] = [
    "artifact_identity",
    "deployment_workflow",
    "runtime_configuration",
    "network_reachability",
    "iam_permissions",
    "datastore_compatibility",
    "resource_capacity",
    "rollout_topology",
    "runtime_architecture",
    "environment_binding",
    "dependency_reachability",
    "data_integrity",
    "external_side_effects",
    "application_security",
    "scalability",
    "availability_resilience",
    "observability",
    "source_coverage",
];
// code-categories-v2, the three deterministic CODE diff rule categories, and
// committed_secret, which the reviewer no longer produces but recorded
// findings keep.
const CODE_DOMAINS: [&str; 11] = [
    "logic",
    "edge_case",
    "error_handling",
    "state_transition",
    "concurrency",
    "resource_lifecycle",
    "credential_exposure",
    "test_marker",
    "removed_assertion",
    "debug_residue",
    "committed_secret",
];

#[derive(Debug, thiserror::Error)]
pub(super) enum SarifError {
    #[error(
        "requested review {requested}, but the server returned review {returned}; SARIF export refused"
    )]
    WrongReview { requested: Uuid, returned: Uuid },
    #[error(
        "review {review} has kind {kind}; SARIF export requires a retained pull-request review"
    )]
    UnsupportedSubject { review: Uuid, kind: String },
    #[error(
        "review {0} does not record a full commit SHA; SARIF export requires an immutable pull-request head"
    )]
    MissingHead(Uuid),
    #[error("finding {finding} has unsupported severity {severity}; SARIF export refused")]
    UnsupportedSeverity { finding: Uuid, severity: String },
    #[error("finding {finding} has unsupported risk domain {domain}; SARIF export refused")]
    UnsupportedDomain { finding: Uuid, domain: String },
}

#[derive(Debug, Serialize)]
pub(super) struct Report<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run<'a>; 1],
}

#[derive(Debug, Serialize)]
struct Run<'a> {
    tool: Tool,
    invocations: [Invocation; 1],
    results: Vec<FindingResult<'a>>,
    properties: ReviewProperties<'a>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
struct Driver {
    name: &'static str,
    version: &'static str,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
struct Rule {
    id: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    execution_successful: bool,
    tool_execution_notifications: Vec<Notification>,
}

#[derive(Debug, Serialize)]
struct Notification {
    level: Level,
    message: Message,
    properties: NotificationProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NotificationProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    assessment_id: Option<Uuid>,
    reason_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Level {
    Error,
    Warning,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

impl Message {
    fn literal(raw: &str) -> Self {
        // SARIF §§3.11.5/6 interpret braces and embedded links even in text.
        // Escape original characters once; JSON encoding happens afterward.
        let mut text = String::with_capacity(raw.len());
        for character in raw.chars() {
            match character {
                '{' => text.push_str("{{"),
                '}' => text.push_str("}}"),
                '\\' | '[' | ']' => {
                    text.push('\\');
                    text.push(character);
                }
                _ => text.push(character),
            }
        }
        Self { text }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingResult<'a> {
    rule_id: &'static str,
    rule_index: usize,
    level: Level,
    message: Message,
    locations: Vec<Location>,
    // The API's retained semantic fingerprint, for correlation across runs.
    // Omitted when an older server supplies none; none is derived here.
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_fingerprints: Option<PartialFingerprints<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    related_locations: Vec<Location>,
    properties: FindingProperties<'a>,
}

#[derive(Debug, Serialize)]
struct PartialFingerprints<'a> {
    #[serde(rename = "prooflineFinding/v1")]
    proofline_finding: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingProperties<'a> {
    // SARIF's guid schema cannot represent the recorded UUIDv7. Keep the
    // actual occurrence ID as data, not a fingerprint or correlation ID.
    finding_id: Uuid,
    assessment_id: Uuid,
    lane: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    lifecycle_state: &'a str,
    location_status: LocationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'a str>,
    evidence_references: Vec<EvidenceProperties<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceProperties<'a> {
    kind: &'a str,
    provenance_status: Option<&'a str>,
    commit_sha: Option<&'a str>,
    companion_repository: Option<&'a str>,
    repository_path: Option<&'a str>,
    start_line: Option<u32>,
    end_line: Option<u32>,
    location_status: LocationStatus,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LocationStatus {
    Located,
    NoVerifiedReviewedLocation,
    NonCodeReference,
    CompanionRepository,
    UnverifiedProvenance,
    CommitUnavailable,
    InvalidCommit,
    DifferentCommit,
    InvalidPath,
    InvalidRegion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
    uri_base_id: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u32,
    end_line: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewProperties<'a> {
    review_id: Uuid,
    organization_id: Uuid,
    review_url: String,
    head_commit_sha: String,
    repository: Option<&'a str>,
    pull_request_number: Option<i64>,
    run_number: Option<i64>,
    review_status: &'a str,
    outcome: Option<&'static str>,
    assessment_count: i64,
    assessments: Vec<AssessmentProperties<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_assessment: Option<CodeAssessmentProperties<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AssessmentProperties<'a> {
    id: Uuid,
    environment: &'a str,
    status: &'a str,
    gap_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CodeAssessmentProperties<'a> {
    id: Uuid,
    status: &'static str,
    base_commit_sha: &'a str,
    head_commit_sha: &'a str,
    gap_reasons: Vec<String>,
}

#[derive(Clone, Copy)]
enum AssessmentSource<'a> {
    Environment(&'a Assessment),
    Code(&'a CodeAssessment),
}

pub(super) fn validate_subject(detail: &ReviewDetail, requested: Uuid) -> Result<(), SarifError> {
    if detail.id != requested {
        return Err(SarifError::WrongReview {
            requested,
            returned: detail.id,
        });
    }
    if detail.kind != "PULL_REQUEST" {
        return Err(SarifError::UnsupportedSubject {
            review: detail.id,
            kind: crate::text::one_line(&detail.kind),
        });
    }
    if !detail.head_commit_sha.as_deref().is_some_and(|head| {
        matches!(head.len(), 40 | 64) && head.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(SarifError::MissingHead(detail.id));
    }
    Ok(())
}

pub(super) fn review<'a>(
    detail: &'a ReviewDetail,
    requested: Uuid,
    organization: Uuid,
    review_url: &str,
) -> Result<Report<'a>, SarifError> {
    validate_subject(detail, requested)?;
    let head = detail
        .head_commit_sha
        .as_deref()
        .ok_or(SarifError::MissingHead(detail.id))?
        .to_ascii_lowercase();
    let state = outcome::terminal(detail);
    let mut results = Vec::new();
    let mut notifications = Vec::new();
    let mut assessments = Vec::new();
    let code = outcome::code_assessment(detail);
    let code_assessment = if let Some(code) = code {
        for finding in &code.findings {
            results.push(finding_result(
                finding,
                AssessmentSource::Code(code),
                &head,
            )?);
        }
        let reasons: Vec<String> = outcome::code_gap(code)
            .map(str::to_owned)
            .into_iter()
            .collect();
        for reason in &reasons {
            notifications.push(Notification {
                level: Level::Error,
                message: Message::literal(&format!("Code-only: {reason}")),
                properties: NotificationProperties {
                    assessment_id: Some(code.id),
                    reason_code: reason.clone(),
                },
            });
        }
        Some(CodeAssessmentProperties {
            id: code.id,
            status: code.status.as_str(),
            base_commit_sha: &code.base_commit_sha,
            head_commit_sha: &code.head_commit_sha,
            gap_reasons: reasons,
        })
    } else {
        None
    };
    for assessment in &detail.assessments {
        for finding in &assessment.findings {
            results.push(finding_result(
                finding,
                AssessmentSource::Environment(assessment),
                &head,
            )?);
        }
        let reasons: BTreeSet<String> = outcome::gap(assessment)
            .unwrap_or_default()
            .into_iter()
            .collect();
        for reason in &reasons {
            notifications.push(Notification {
                level: Level::Error,
                message: Message::literal(&format!(
                    "{}: {reason}",
                    assessment.environment_display_name
                )),
                properties: NotificationProperties {
                    assessment_id: Some(assessment.id),
                    reason_code: reason.clone(),
                },
            });
        }
        assessments.push(AssessmentProperties {
            id: assessment.id,
            environment: &assessment.environment_display_name,
            status: &assessment.status,
            gap_reasons: reasons.into_iter().collect(),
        });
    }
    if state != Some(Outcome::Completed) {
        let reason = match state {
            None => "REVIEW_IN_PROGRESS",
            Some(Outcome::Failed) => "REVIEW_FAILED",
            Some(Outcome::Stopped) => "REVIEW_STOPPED",
            Some(Outcome::Incomplete | Outcome::Completed) => "REVIEW_RESULT_INCOMPLETE",
        };
        notifications.push(Notification {
            level: Level::Error,
            message: Message::literal(&format!("Review {}: {reason}", detail.id)),
            properties: NotificationProperties {
                assessment_id: None,
                reason_code: reason.to_owned(),
            },
        });
    }
    if outcome::code_unavailable(detail) {
        notifications.push(Notification {
            level: Level::Error,
            message: Message::literal("Code-only: CODE_ASSESSMENT_UNAVAILABLE"),
            properties: NotificationProperties {
                assessment_id: None,
                reason_code: "CODE_ASSESSMENT_UNAVAILABLE".to_owned(),
            },
        });
    }
    Ok(Report {
        schema: SCHEMA,
        version: "2.1.0",
        runs: [Run {
            tool: Tool {
                driver: Driver {
                    name: "Proofline",
                    // The exporting tool's version. The public review document
                    // does not expose the assessments' reviewer version.
                    version: env!("CARGO_PKG_VERSION"),
                    rules: DOMAINS
                        .iter()
                        .chain(code.into_iter().flat_map(|_| CODE_DOMAINS.iter()))
                        .map(|&id| Rule { id })
                        .collect(),
                },
            },
            invocations: [Invocation {
                execution_successful: state == Some(Outcome::Completed) && notifications.is_empty(),
                tool_execution_notifications: notifications,
            }],
            results,
            // The public API supplies no provider-qualified repository URI.
            // Keep the recorded SHA without inventing versionControlProvenance.
            properties: ReviewProperties {
                review_id: detail.id,
                organization_id: organization,
                review_url: review_url.to_owned(),
                head_commit_sha: head,
                repository: detail.repository_full_name.as_deref(),
                pull_request_number: detail.pull_request_number,
                run_number: detail.run_number,
                review_status: &detail.status,
                outcome: state.map(Outcome::as_str),
                assessment_count: detail.assessment_count,
                assessments,
                code_assessment,
            },
        }],
    })
}

fn finding_result<'a>(
    finding: &'a Finding,
    source: AssessmentSource<'a>,
    head: &str,
) -> Result<FindingResult<'a>, SarifError> {
    let level = match finding.severity.as_str() {
        "SERIOUS" => Level::Error,
        "WARNING" => Level::Warning,
        _ => {
            return Err(SarifError::UnsupportedSeverity {
                finding: finding.id,
                severity: crate::text::one_line(&finding.severity),
            });
        }
    };
    let (domains, rule_offset, assessment_id, environment, lane) = match source {
        AssessmentSource::Environment(assessment) => (
            DOMAINS.as_slice(),
            0,
            assessment.id,
            Some(assessment.environment_display_name.as_str()),
            "ENV",
        ),
        AssessmentSource::Code(code) => (
            CODE_DOMAINS.as_slice(),
            DOMAINS.len(),
            code.id,
            None,
            "CODE",
        ),
    };
    let domain_index = domains
        .iter()
        .position(|&domain| domain == finding.risk_domain)
        .ok_or_else(|| SarifError::UnsupportedDomain {
            finding: finding.id,
            domain: crate::text::one_line(&finding.risk_domain),
        })?;
    let mut locations = Vec::new();
    let mut seen = BTreeSet::new();
    let evidence_references = finding
        .evidence_refs
        .iter()
        .map(|reference| {
            let location_status = match code_location(reference, head) {
                Ok((path, start_line, end_line)) => {
                    if seen.insert((path, start_line, end_line)) {
                        locations.push(Location {
                            physical_location: PhysicalLocation {
                                artifact_location: ArtifactLocation {
                                    uri: path_uri(path),
                                    uri_base_id: "%SRCROOT%",
                                },
                                region: Region {
                                    start_line,
                                    end_line,
                                },
                            },
                        });
                    }
                    LocationStatus::Located
                }
                Err(status) => status,
            };
            EvidenceProperties {
                kind: &reference.kind,
                provenance_status: reference.provenance_status.as_deref(),
                commit_sha: reference.commit_sha.as_deref(),
                companion_repository: reference.companion_repository.as_deref(),
                repository_path: reference.repository_path.as_deref(),
                start_line: reference.start_line,
                end_line: reference.end_line,
                location_status,
            }
        })
        .collect();
    let location_status = if locations.is_empty() {
        LocationStatus::NoVerifiedReviewedLocation
    } else {
        LocationStatus::Located
    };
    // Supporting citations do not claim that correcting the finding requires
    // changing every file. The first eligible recorded citation is primary.
    let related_locations = locations.split_off(locations.len().min(1));
    let message = match source {
        AssessmentSource::Environment(_) => format!("{}\n\n{}", finding.claim, finding.impact),
        AssessmentSource::Code(_) => format!(
            "Code-only finding\n\n{}\n\n{}",
            finding.claim, finding.impact
        ),
    };
    Ok(FindingResult {
        rule_id: domains[domain_index],
        rule_index: rule_offset + domain_index,
        level,
        message: Message::literal(&message),
        locations,
        partial_fingerprints: finding
            .finding_fingerprint
            .as_deref()
            .map(|proofline_finding| PartialFingerprints { proofline_finding }),
        related_locations,
        properties: FindingProperties {
            finding_id: finding.id,
            assessment_id,
            lane,
            environment,
            lifecycle_state: &finding.lifecycle_state,
            location_status,
            remediation: finding.remediation.as_deref(),
            evidence_references,
        },
    })
}

fn code_location<'a>(
    reference: &'a EvidenceRef,
    head: &str,
) -> Result<(&'a str, u32, u32), LocationStatus> {
    if reference.kind == "companion_repository_file" || reference.companion_repository.is_some() {
        return Err(LocationStatus::CompanionRepository);
    }
    if reference.kind != "repository_file" {
        return Err(LocationStatus::NonCodeReference);
    }
    if reference.provenance_status.as_deref() != Some("VERIFIED_REPOSITORY_READ") {
        return Err(LocationStatus::UnverifiedProvenance);
    }
    let commit = reference
        .commit_sha
        .as_deref()
        .ok_or(LocationStatus::CommitUnavailable)?;
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LocationStatus::InvalidCommit);
    }
    if !commit.eq_ignore_ascii_case(head) {
        return Err(LocationStatus::DifferentCommit);
    }
    let path = reference
        .repository_path
        .as_deref()
        .filter(|path| valid_path(path))
        .ok_or(LocationStatus::InvalidPath)?;
    let start = reference
        .start_line
        .filter(|&line| line > 0)
        .ok_or(LocationStatus::InvalidRegion)?;
    let end = reference.end_line.unwrap_or(start);
    if end < start {
        return Err(LocationStatus::InvalidRegion);
    }
    Ok((path, start, end))
}

fn valid_path(path: &str) -> bool {
    !path.split('/').any(|part| matches!(part, "" | "." | ".."))
        && !path.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\\' | ':' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

fn path_uri(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut uri = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    uri
}
