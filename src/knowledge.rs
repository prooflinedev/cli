//! Native knowledge commands over the existing MCP authorization boundary.
use crate::{Verdict, api::Http, credentials, git, mcp, origin::Origin, tools};
use clap::{Args, Subcommand};
use secrecy::SecretString;
use serde_json::{Value, json};
use uuid::Uuid;

type Request = (&'static str, Value);

#[derive(Debug, Args)]
pub(crate) struct Repository {
    #[arg(long)]
    repo: String,
    /// Full indexed commit SHA; omit to use the newest completed build.
    #[arg(long)]
    commit: Option<String>,
}
impl Repository {
    fn arguments(&self) -> anyhow::Result<Value> {
        let mut value = json!({"repository": self.repo});
        if let Some(commit) = &self.commit {
            git::commit_sha(commit)?;
            value["commit"] = json!(commit);
        }
        Ok(value)
    }
}
#[derive(Debug, Subcommand)]
pub(crate) enum WikiCommand {
    List(Repository),
    Get {
        page_key: String,
        #[command(flatten)]
        repository: Repository,
    },
}
impl WikiCommand {
    pub fn request(self) -> anyhow::Result<Request> {
        match self {
            Self::List(repository) => Ok(("list_wiki_pages", repository.arguments()?)),
            Self::Get {
                page_key,
                repository,
            } => {
                let mut args = repository.arguments()?;
                args["page_key"] = json!(page_key);
                Ok(("get_wiki_page", args))
            }
        }
    }
}
#[derive(Debug, Args)]
pub(crate) struct AskArgs {
    question: String,
    #[command(flatten)]
    repository: Repository,
}
impl AskArgs {
    pub fn request(self) -> anyhow::Result<Request> {
        let mut args = self.repository.arguments()?;
        args["question"] = json!(self.question);
        Ok(("ask_codebase", args))
    }
}
#[derive(Debug, Subcommand)]
pub(crate) enum PlanCommand {
    Get {
        plan_id: Uuid,
    },
    /// Start implementation of this exact approved, published plan version.
    Implement {
        plan_id: Uuid,
    },
    Implementation {
        implementation_id: Uuid,
    },
}
impl PlanCommand {
    pub fn request(self) -> Request {
        match self {
            Self::Get { plan_id } => ("get_plan", json!({"plan_id": plan_id})),
            Self::Implement { plan_id } => {
                ("start_plan_implementation", json!({"plan_id": plan_id}))
            }
            Self::Implementation { implementation_id } => (
                "get_plan_implementation",
                json!({"implementation_id": implementation_id}),
            ),
        }
    }
}
pub(crate) async fn run(
    origin: Origin,
    token: Option<SecretString>,
    org: Option<Uuid>,
    (name, arguments): Request,
) -> anyhow::Result<Verdict> {
    let credential = credentials::load(&origin, token, org).await?;
    let value = mcp::call(&Http::new(origin)?, &credential.token, name, arguments).await?;
    tools::json(&value)?;
    Ok(
        if value.get("isError").and_then(Value::as_bool) == Some(true) {
            Verdict::Blocked
        } else {
            Verdict::Done
        },
    )
}
