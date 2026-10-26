//! Read captured fix context and request verification of an explicitly pushed commit.
use crate::git;
use clap::Subcommand;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Subcommand)]
pub(crate) enum FixCommand {
    /// List open ENV findings at a pull request's live head, retaining availability and gaps.
    List {
        #[arg(long)]
        repo: String,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        pr: u64,
    },
    /// Read captured source excerpts and untrusted remediation for one finding.
    Context { finding_id: Uuid },
    /// Request re-verification after pushing this exact commit. Makes one attempt.
    Verify {
        #[arg(long)]
        review: Uuid,
        #[arg(long, num_args = 1..=20, required = true)]
        findings: Vec<Uuid>,
        /// Full pushed commit SHA; the server requires the pull request's live head.
        #[arg(long)]
        commit: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Read recorded outcomes. `PENDING` and `NOT_VERIFIED` do not establish a fix.
    Status { request_id: Uuid },
}

impl FixCommand {
    pub fn request(self) -> anyhow::Result<(&'static str, Value)> {
        Ok(match self {
            Self::List { repo, pr } => (
                "list_open_findings",
                json!({"repository": repo, "pull_request_number": pr}),
            ),
            Self::Context { finding_id } => ("get_fix_context", json!({"finding_id": finding_id})),
            Self::Verify {
                review,
                findings,
                commit,
                note,
            } => {
                git::commit_sha(&commit)?;
                let mut unique = findings.clone();
                unique.sort_unstable();
                unique.dedup();
                anyhow::ensure!(
                    unique.len() == findings.len(),
                    "finding IDs must be distinct"
                );
                let mut args =
                    json!({"review_id": review, "finding_ids": findings, "commit_sha": commit});
                if let Some(note) = note {
                    anyhow::ensure!(
                        (1..=2000).contains(&note.chars().count()),
                        "note must contain 1 to 2000 characters"
                    );
                    args["note"] = json!(note);
                }
                ("request_reverification", args)
            }
            Self::Status { request_id } => {
                ("get_reverification", json!({"request_id": request_id}))
            }
        })
    }
}
