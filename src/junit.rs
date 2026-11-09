//! Read-only `JUnit` XML for one retained pull-request review, for CI systems
//! that render a test report. Like the SARIF projection it is closed: it never
//! serializes the raw API document or World evidence values, and it reads no
//! clock.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::model::{Assessment, Check, CodeAssessment, Finding, ReviewDetail};
use crate::outcome::{self, Outcome};
use crate::sarif::{self, SubjectError};

const MESSAGE_CHARACTERS: usize = 200;

#[derive(Debug, thiserror::Error)]
pub(super) enum JunitError {
    #[error(transparent)]
    Subject(#[from] SubjectError),
    #[error("finding {finding} has unsupported severity {severity}; JUnit export refused")]
    UnsupportedSeverity { finding: Uuid, severity: String },
}

/// How one test case ended. Only an open finding or a blocked check fails; a
/// review that could not finish a lane is an error, mirroring exit code 2.
enum Status {
    Passed,
    Failed {
        kind: String,
        message: String,
        body: String,
    },
    Errored {
        kind: String,
        message: String,
    },
    Skipped {
        message: &'static str,
    },
}

struct Case {
    classname: String,
    name: String,
    status: Status,
    /// Plain lines for `<system-out>`: the schema allows no properties here.
    output: Vec<String>,
}

struct Suite {
    name: String,
    properties: Vec<(&'static str, String)>,
    cases: Vec<Case>,
}

impl Suite {
    fn count(&self, matching: impl Fn(&Status) -> bool) -> usize {
        self.cases
            .iter()
            .filter(|case| matching(&case.status))
            .count()
    }
}

pub(super) fn review(
    detail: &ReviewDetail,
    requested: Uuid,
    review_url: &str,
) -> Result<String, JunitError> {
    sarif::validate_subject(detail, requested, "JUnit")?;
    let head = detail
        .head_commit_sha
        .as_deref()
        .ok_or(SubjectError::MissingHead {
            review: detail.id,
            report: "JUnit",
        })?
        .to_ascii_lowercase();
    let state = outcome::terminal(detail);
    let mut suites = Vec::new();
    for assessment in &detail.assessments {
        suites.push(environment_suite(detail, assessment, &head, review_url)?);
    }
    if let Some(code) = outcome::code_assessment(detail) {
        suites.push(code_suite(detail, code, &head, review_url)?);
    } else if outcome::code_unavailable(detail) {
        suites.push(Suite {
            name: "Code-only".to_owned(),
            properties: review_properties(detail, &head, review_url),
            cases: vec![errored(
                "Code-only",
                "completeness",
                "CODE_ASSESSMENT_UNAVAILABLE".to_owned(),
            )],
        });
    }
    if state != Some(Outcome::Completed) {
        let reason = match state {
            None => "REVIEW_IN_PROGRESS",
            Some(Outcome::Failed) => "REVIEW_FAILED",
            Some(Outcome::Stopped) => "REVIEW_STOPPED",
            Some(Outcome::Incomplete | Outcome::Completed) => "REVIEW_RESULT_INCOMPLETE",
        };
        suites.push(Suite {
            name: "review".to_owned(),
            properties: review_properties(detail, &head, review_url),
            cases: vec![errored("review", "completion", reason.to_owned())],
        });
    }
    Ok(render(&suites))
}

fn review_properties(
    detail: &ReviewDetail,
    head: &str,
    review_url: &str,
) -> Vec<(&'static str, String)> {
    let mut properties = vec![
        ("review_id", detail.id.to_string()),
        ("review_url", review_url.to_owned()),
        ("head_commit_sha", head.to_owned()),
        ("review_status", detail.status.clone()),
    ];
    if let Some(repository) = &detail.repository_full_name {
        properties.push(("repository", repository.clone()));
    }
    if let Some(number) = detail.pull_request_number {
        properties.push(("pull_request_number", number.to_string()));
    }
    if let Some(run) = detail.run_number {
        properties.push(("run_number", run.to_string()));
    }
    properties
}

fn environment_suite(
    detail: &ReviewDetail,
    assessment: &Assessment,
    head: &str,
    review_url: &str,
) -> Result<Suite, JunitError> {
    // Prefixed so free text cannot take the name of a synthetic suite.
    let name = format!("environment: {}", assessment.environment_display_name);
    let name = name.as_str();
    let mut properties = review_properties(detail, head, review_url);
    properties.push(("lane", "ENV".to_owned()));
    properties.push(("assessment_id", assessment.id.to_string()));
    let mut cases = Vec::new();
    for check in &assessment.checks.families {
        cases.push(check_case(name, check));
    }
    let reasons: BTreeSet<String> = outcome::gap(assessment)
        .unwrap_or_default()
        .into_iter()
        .collect();
    cases.push(completeness(name, &reasons));
    for finding in &assessment.findings {
        cases.push(finding_case(name, finding, head, true)?);
    }
    Ok(Suite {
        name: name.to_owned(),
        properties,
        cases,
    })
}

fn code_suite(
    detail: &ReviewDetail,
    code: &CodeAssessment,
    head: &str,
    review_url: &str,
) -> Result<Suite, JunitError> {
    let name = "Code-only";
    let mut properties = review_properties(detail, head, review_url);
    properties.push(("lane", "CODE".to_owned()));
    properties.push(("assessment_id", code.id.to_string()));
    let reasons: BTreeSet<String> = outcome::code_gap(code)
        .map(str::to_owned)
        .into_iter()
        .collect();
    let mut cases = vec![completeness(name, &reasons)];
    for finding in &code.findings {
        // The API projects no decisions onto CODE findings.
        cases.push(finding_case(name, finding, head, false)?);
    }
    Ok(Suite {
        name: name.to_owned(),
        properties,
        cases,
    })
}

fn completeness(suite: &str, reasons: &BTreeSet<String>) -> Case {
    if reasons.is_empty() {
        Case {
            classname: suite.to_owned(),
            name: "completeness".to_owned(),
            status: Status::Passed,
            output: Vec::new(),
        }
    } else {
        errored(
            suite,
            "completeness",
            reasons.iter().cloned().collect::<Vec<_>>().join(", "),
        )
    }
}

fn errored(suite: &str, name: &str, message: String) -> Case {
    Case {
        classname: suite.to_owned(),
        name: name.to_owned(),
        status: Status::Errored {
            kind: "INCOMPLETE".to_owned(),
            message,
        },
        output: Vec::new(),
    }
}

/// One environment check family. Only its name and outcome are read; the
/// detail text can quote evidence and stays out of the report.
fn check_case(suite: &str, check: &Check) -> Case {
    let status = match check.outcome.as_str() {
        "READY" => Status::Passed,
        "NOT_APPLICABLE" => Status::Skipped {
            message: "NOT_APPLICABLE",
        },
        "BLOCKED" => Status::Failed {
            kind: "BLOCKED".to_owned(),
            message: format!("check {} is BLOCKED", check.name),
            body: format!("check: {}\noutcome: BLOCKED", check.name),
        },
        other => Status::Errored {
            kind: "INCOMPLETE".to_owned(),
            message: format!("check {} is {other}", check.name),
        },
    };
    Case {
        classname: suite.to_owned(),
        name: format!("check {}", check.name),
        status,
        output: Vec::new(),
    }
}

/// One finding. An open finding fails. A resolved finding, and one a person
/// dismissed or accepted as a risk, passes and records why in its output.
fn finding_case(
    suite: &str,
    finding: &Finding,
    head: &str,
    decisions: bool,
) -> Result<Case, JunitError> {
    if !matches!(finding.severity.as_str(), "SERIOUS" | "WARNING") {
        return Err(JunitError::UnsupportedSeverity {
            finding: finding.id,
            severity: crate::text::one_line(&finding.severity),
        });
    }
    let state = if finding.lifecycle_state == "RESOLVED" {
        Some("RESOLVED")
    } else if decisions {
        finding
            .validation
            .as_deref()
            .filter(|decision| matches!(*decision, "DISMISSED" | "ACCEPTED_RISK"))
    } else {
        None
    };
    // The retained fingerprint keeps the case name stable across runs; an
    // older server omits it and the occurrence ID stands in.
    let identity = finding
        .finding_fingerprint
        .clone()
        .unwrap_or_else(|| finding.id.to_string());
    let name = format!("{} {identity}", finding.risk_domain);
    if let Some(state) = state {
        return Ok(Case {
            classname: suite.to_owned(),
            name,
            status: Status::Passed,
            output: vec![
                format!("state: {}", state.to_lowercase().replace('_', "-")),
                format!("finding: {}", finding.id),
                format!("severity: {}", finding.severity),
            ],
        });
    }
    let mut lines = vec![
        format!("finding: {}", finding.id),
        format!("domain: {}", finding.risk_domain),
    ];
    for reference in &finding.evidence_refs {
        if let Ok((path, start, end)) = sarif::code_location(reference, head) {
            lines.push(if start == end {
                format!("cited: {path}:{start}")
            } else {
                format!("cited: {path}:{start}-{end}")
            });
        }
    }
    lines.push(format!("claim: {}", finding.claim));
    let body = lines.join("\n");
    Ok(Case {
        classname: suite.to_owned(),
        name,
        status: Status::Failed {
            kind: finding.severity.clone(),
            message: title(&finding.claim),
            body,
        },
        output: Vec::new(),
    })
}

/// The API gives a finding no title: its claim's first line stands in.
fn title(claim: &str) -> String {
    claim
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .chars()
        .take(MESSAGE_CHARACTERS)
        .collect()
}

fn render(suites: &[Suite]) -> String {
    let total = |count: fn(&Suite) -> usize| suites.iter().map(count).sum::<usize>();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites");
    attribute(&mut out, "name", "proofline");
    number(&mut out, "tests", total(|suite| suite.cases.len()));
    number(
        &mut out,
        "failures",
        total(|suite| suite.count(|status| matches!(status, Status::Failed { .. }))),
    );
    number(
        &mut out,
        "errors",
        total(|suite| suite.count(|status| matches!(status, Status::Errored { .. }))),
    );
    out.push_str(">\n");
    for suite in suites {
        out.push_str("  <testsuite");
        attribute(&mut out, "name", &suite.name);
        number(&mut out, "tests", suite.cases.len());
        number(
            &mut out,
            "failures",
            suite.count(|status| matches!(status, Status::Failed { .. })),
        );
        number(
            &mut out,
            "errors",
            suite.count(|status| matches!(status, Status::Errored { .. })),
        );
        number(
            &mut out,
            "skipped",
            suite.count(|status| matches!(status, Status::Skipped { .. })),
        );
        out.push_str(">\n");
        properties(&mut out, "    ", &suite.properties);
        for case in &suite.cases {
            render_case(&mut out, case);
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

fn render_case(out: &mut String, case: &Case) {
    out.push_str("    <testcase");
    attribute(out, "classname", &case.classname);
    attribute(out, "name", &case.name);
    if case.output.is_empty() && matches!(case.status, Status::Passed) {
        out.push_str("/>\n");
        return;
    }
    out.push_str(">\n");
    match &case.status {
        Status::Passed => {}
        Status::Skipped { message } => {
            out.push_str("      <skipped");
            attribute(out, "message", message);
            out.push_str("/>\n");
        }
        Status::Errored { kind, message } => {
            out.push_str("      <error");
            attribute(out, "message", message);
            attribute(out, "type", kind);
            out.push_str("/>\n");
        }
        Status::Failed {
            kind,
            message,
            body,
        } => {
            out.push_str("      <failure");
            attribute(out, "message", message);
            attribute(out, "type", kind);
            out.push('>');
            text(out, body);
            out.push_str("</failure>\n");
        }
    }
    if !case.output.is_empty() {
        out.push_str("      <system-out>");
        text(out, &case.output.join("\n"));
        out.push_str("</system-out>\n");
    }
    out.push_str("    </testcase>\n");
}

fn properties(out: &mut String, indent: &str, properties: &[(&'static str, String)]) {
    if properties.is_empty() {
        return;
    }
    out.push_str(indent);
    out.push_str("<properties>\n");
    for (name, value) in properties {
        out.push_str(indent);
        out.push_str("  <property");
        attribute(out, "name", name);
        attribute(out, "value", value);
        out.push_str("/>\n");
    }
    out.push_str(indent);
    out.push_str("</properties>\n");
}

fn number(out: &mut String, name: &str, value: usize) {
    attribute(out, name, &value.to_string());
}

fn attribute(out: &mut String, name: &str, value: &str) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    escape(out, value, true);
    out.push('"');
}

fn text(out: &mut String, value: &str) {
    escape(out, value, false);
}

/// Characters XML 1.0 allows. Others (most control characters, lone
/// surrogates cannot occur in a `str`, U+FFFE and U+FFFF) are dropped.
const fn allowed(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

/// Escapes `value` for an attribute or a text node. `>` is always escaped, so
/// `]]>` cannot occur, and no CDATA section is ever written. In an attribute
/// a tab, newline or carriage return becomes a character reference, which an
/// XML parser would otherwise normalize to a space.
fn escape(out: &mut String, value: &str, attribute: bool) {
    for character in value.chars().filter(|&character| allowed(character)) {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            '\'' if attribute => out.push_str("&apos;"),
            '\r' => out.push_str("&#13;"),
            '\t' if attribute => out.push_str("&#9;"),
            '\n' if attribute => out.push_str("&#10;"),
            _ => out.push(character),
        }
    }
}
