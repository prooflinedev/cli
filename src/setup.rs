//! Setup from a shell: the hosted setup reads, and the setup instructions.

use clap::Subcommand;
use serde_json::{Value, json};

/// The setup loop that both agent plugins share, below the commands that stand
/// for its hosted tools. `tools/ci/check_onboarding_skill.py` keeps the loop
/// equal to the plugins', so the text matches this release.
pub(crate) const GUIDE: &str = include_str!("setup_guide.md");

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Read the current setup step, readiness and blockers as JSON.
    Status,
    /// List the repositories and deployments a setup answer may name, as JSON.
    Candidates {
        /// Keep the candidates whose name matches, 1 to 100 characters.
        #[arg(long)]
        query: Option<String>,
    },
    /// Print the setup instructions for a coding agent. Needs no sign-in.
    Guide,
}

impl Command {
    /// The hosted tool and arguments of a read, or `None` for the guide.
    pub(crate) fn request(self) -> Option<(&'static str, Value)> {
        match self {
            Self::Status => Some(("get_setup_status", json!({}))),
            Self::Candidates { query } => {
                let mut arguments = json!({});
                if let Some(query) = query {
                    arguments["query"] = json!(query);
                }
                Some(("list_setup_candidates", arguments))
            }
            Self::Guide => None,
        }
    }
}
