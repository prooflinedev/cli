//! Finding severities: the order the renderer prints them in, the Git hooks'
//! `failOn` comparison, and the names `ci review --fail-on` takes.

use clap::ValueEnum;

/// A finding severity this CLI knows, least severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub(crate) enum Severity {
    Warning,
    Serious,
}

impl Severity {
    /// The severity as the review API spells it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "WARNING",
            Self::Serious => "SERIOUS",
        }
    }

    /// Reads the review API's spelling. `None` is a severity this CLI does
    /// not know, which a newer server can send.
    pub(crate) fn parse(severity: &str) -> Option<Self> {
        match severity {
            "WARNING" => Some(Self::Warning),
            "SERIOUS" => Some(Self::Serious),
            _ => None,
        }
    }

    /// Whether a finding of `severity` is at or above this threshold. A
    /// severity this CLI does not know reaches every threshold: unknown is
    /// never read as below one.
    pub(crate) fn reached_by(self, severity: &str) -> bool {
        Self::parse(severity).is_none_or(|known| known >= self)
    }
}

#[cfg(test)]
mod tests {
    use super::Severity::{Serious, Warning};

    #[test]
    fn a_threshold_is_reached_by_its_own_severity_a_higher_one_and_an_unknown_one() {
        for (threshold, severity, reached) in [
            (Warning, "WARNING", true),
            (Warning, "SERIOUS", true),
            (Serious, "WARNING", false),
            (Serious, "SERIOUS", true),
            (Serious, "CRITICAL", true),
            (Warning, "NOTE", true),
            (Serious, "NOTE", true),
            (Serious, "", true),
        ] {
            assert_eq!(
                threshold.reached_by(severity),
                reached,
                "{threshold:?} by {severity:?}"
            );
        }
    }
}
