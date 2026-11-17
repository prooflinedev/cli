//! Findings as GitHub Actions workflow commands. The runner reads each
//! `::error file=...,line=...::message` line from a step's output and shows it
//! on the pull request's diff, on every GitHub plan. Findings quote reviewer
//! output and repository content, so every value is escaped: a newline in a
//! claim must never start a second command.

use std::io::Write;

use crate::model::{Finding, ReviewDetail};
use crate::severity::Severity;
use crate::{outcome, sarif, text};

/// Writes one annotation per finding that is not resolved. A finding with a
/// verified location at the review's head is placed on that file and line;
/// any other finding is annotated on the job without a location.
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
    Ok(())
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
    // A severity this CLI does not know yet is still shown, as a notice.
    let command = match Severity::parse(&finding.severity) {
        Some(Severity::Serious) => "error",
        Some(Severity::Warning) => "warning",
        None => "notice",
    };
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
    let title = format!("Proofline {lane}: {}", finding.risk_domain);
    properties.push(format!("title={}", escape_property(&title)));
    let message = format!("{}\n\n{}", finding.claim, finding.impact);
    writeln!(
        out,
        "::{command} {}::{}",
        properties.join(","),
        escape_data(&message)
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
