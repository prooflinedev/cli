//! Findings as GitHub Actions workflow commands. The runner reads each
//! `::error file=...,line=...::message` line from a step's output and shows it
//! on the pull request's diff, on every GitHub plan. Findings quote reviewer
//! output and repository content, so every value is escaped: a newline in a
//! claim must never start a second command.

use std::io::Write;

use crate::model::{EarlierFinding, Finding, InvestigationFinding, ReviewDetail};
use crate::severity::Severity;
use crate::{outcome, sarif, text};

/// Writes one annotation per finding that is not resolved, then the
/// [`unlisted`] ones, so every finding `--fail-on` measures is on the job. A
/// finding with a verified location at
/// the review's head is placed on that file and line; any other finding is
/// annotated on the job without a location.
pub(super) fn write(detail: &ReviewDetail, out: &mut impl Write) -> std::io::Result<()> {
    let head = detail.head_commit_sha.as_deref().unwrap_or_default();
    if let Some(code) = outcome::code_assessment(detail) {
        for finding in &code.findings {
            annotate(out, finding, "code", head)?;
        }
    }
    for assessment in &detail.assessments {
        for finding in &assessment.findings {
            annotate(out, finding, &assessment.environment_display_name, head)?;
        }
    }
    unlisted(detail, out)
}

/// The open findings the review counts but lists in no assessment.
fn unlisted(detail: &ReviewDetail, out: &mut impl Write) -> std::io::Result<()> {
    for finding in &detail.investigation_findings {
        investigation(out, detail, finding)?;
    }
    for finding in detail
        .open_items
        .iter()
        .flat_map(|open| &open.earlier_findings)
    {
        earlier(out, finding)?;
    }
    Ok(())
}

/// A severity this CLI does not know yet is still shown, as a notice.
fn command(severity: &str) -> &'static str {
    match Severity::parse(severity) {
        Some(Severity::Serious) => "error",
        Some(Severity::Warning) => "warning",
        None => "notice",
    }
}

/// An environment finding with no severity is a notice on the job, its title
/// ending with what published it.
fn investigation(
    out: &mut impl Write,
    detail: &ReviewDetail,
    finding: &InvestigationFinding,
) -> std::io::Result<()> {
    let environment = detail
        .assessments
        .iter()
        .find(|assessment| assessment.id == finding.assessment_id)
        .map_or("environment", |assessment| {
            &assessment.environment_display_name
        });
    let title = format!(
        "Proofline {environment}: {} ({})",
        finding.area,
        finding.published_by()
    );
    emit(out, "notice", &[titled(&title)], &finding.title)
}

fn earlier(out: &mut impl Write, finding: &EarlierFinding) -> std::io::Result<()> {
    let title = format!("Proofline earlier run {}", finding.run_number);
    let message = finding
        .title
        .as_deref()
        .unwrap_or("A finding of an earlier run is still open.");
    emit(out, command(&finding.severity), &[titled(&title)], message)
}

fn annotate(
    out: &mut impl Write,
    finding: &Finding,
    lane: &str,
    head: &str,
) -> std::io::Result<()> {
    if outcome::resolved(finding) {
        return Ok(());
    }
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
    let decision = finding
        .latest_validation
        .as_ref()
        .map(|decision| format!(" ({})", decision.validation))
        .unwrap_or_default();
    let title = format!("Proofline {lane}: {}{decision}", finding.risk_domain);
    properties.push(titled(&title));
    let message = format!("{}\n\n{}", finding.claim, finding.impact);
    emit(out, command(&finding.severity), &properties, &message)
}

fn titled(title: &str) -> String {
    format!("title={}", escape_property(title))
}

fn emit(
    out: &mut impl Write,
    command: &str,
    properties: &[String],
    message: &str,
) -> std::io::Result<()> {
    writeln!(
        out,
        "::{command} {}::{}",
        properties.join(","),
        escape_data(message)
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

    fn written(write: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
        let mut out = Vec::new();
        write(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn an_environment_finding_of_an_unlisted_assessment_still_reaches_the_job() {
        let detail: ReviewDetail = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "kind": "PULL_REQUEST",
            "status": "RUNNING",
            "assessment_count": 1,
            "assessments": [],
            "code_assessment": null,
            "base_commit_sha": null,
            "head_commit_sha": null,
            "open_items": null,
            "pull_request_number": 1,
            "repository_id": null,
            "repository_full_name": null,
            "run_number": 1,
        }))
        .unwrap();
        let mut finding = InvestigationFinding {
            assessment_id: uuid::Uuid::nil(),
            area: "network".to_owned(),
            title: "egress is blocked".to_owned(),
            source: None,
        };
        assert_eq!(
            written(|out| investigation(out, &detail, &finding)),
            "::notice title=Proofline environment%3A network (ENVIRONMENT)::egress is blocked\n"
        );
        finding.source = Some("SHARED_IDENTITY".to_owned());
        assert_eq!(
            written(|out| investigation(out, &detail, &finding)),
            "::notice title=Proofline environment%3A network (SHARED_IDENTITY)::egress is blocked\n"
        );
    }

    #[test]
    fn an_earlier_finding_of_an_unknown_severity_is_a_notice() {
        let finding = EarlierFinding {
            review_id: uuid::Uuid::nil(),
            run_number: 2,
            severity: "CRITICAL".to_owned(),
            title: Some("Disk fills".to_owned()),
        };
        assert_eq!(
            written(|out| earlier(out, &finding)),
            "::notice title=Proofline earlier run 2::Disk fills\n"
        );
    }

    #[test]
    fn an_untitled_earlier_finding_says_what_it_is() {
        let finding = EarlierFinding {
            review_id: uuid::Uuid::nil(),
            run_number: 3,
            severity: "WARNING".to_owned(),
            title: None,
        };
        assert_eq!(
            written(|out| earlier(out, &finding)),
            "::warning title=Proofline earlier run 3::A finding of an earlier run is still open.\n"
        );
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
}
