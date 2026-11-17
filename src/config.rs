//! Configuration commands over the hosted MCP authorization boundary.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Subcommand;
use secrecy::SecretString;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    Verdict,
    api::{Http, McpHttpError},
    credentials, mcp,
    origin::Origin,
    tools,
};

/// The one sign-in that the installer, the skills and the documentation name.
/// `/mcp` admits only a token holding `reviews:read`, so the configuration
/// scopes alone are refused before any tool runs.
pub(crate) const LOGIN: &str = "proofline login --scope reviews:read --scope findings:read --scope guidance:read --scope reviews:request --scope setup:write --scope org:configure";

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Read effective configuration and setup problems as JSON.
    Get {
        #[arg(long, value_name = "ID")]
        environment: Option<Uuid>,
        #[arg(long, value_name = "OWNER/NAME")]
        repo: Option<String>,
    },
    /// List configuration operations and their sensitivity as JSON.
    Operations {
        #[arg(long)]
        area: Option<String>,
        #[arg(long)]
        subject: Option<String>,
    },
    /// Read an operation's schema, current value and revision as JSON.
    Describe {
        operation: String,
        /// Route parameter; repeat for several parameters.
        #[arg(long = "param", value_name = "NAME=VALUE", value_parser = parameter)]
        parameters: Vec<(String, String)>,
    },
    /// Propose a JSON change file without applying it.
    /// A file `organization_id` must match the selected organization.
    Propose { file: PathBuf },
    /// Apply an ordinary proposal, or print its browser approval link.
    Apply { change_id: Uuid },
}

fn parameter(value: &str) -> Result<(String, String), String> {
    let (name, value) = value
        .split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .ok_or_else(|| "expected NAME=VALUE".to_owned())?;
    Ok((name.to_owned(), value.to_owned()))
}

impl Command {
    async fn request(self) -> anyhow::Result<(&'static str, Value)> {
        match self {
            Self::Get { environment, repo } => {
                let mut arguments = json!({});
                if let Some(id) = environment {
                    arguments["environment_id"] = json!(id);
                }
                if let Some(repository) = repo {
                    arguments["repository"] = json!(repository);
                }
                Ok(("get_configuration", arguments))
            }
            Self::Operations { area, subject } => {
                let mut arguments = json!({});
                if let Some(area) = area {
                    arguments["area"] = json!(area);
                }
                if let Some(subject) = subject {
                    arguments["subject"] = json!(subject);
                }
                Ok(("list_operations", arguments))
            }
            Self::Describe {
                operation,
                parameters,
            } => {
                let parameters: serde_json::Map<String, Value> = parameters
                    .into_iter()
                    .map(|(name, value)| (name, Value::String(value)))
                    .collect();
                Ok((
                    "describe_operation",
                    json!({"operation": operation, "parameters": parameters}),
                ))
            }
            Self::Propose { file } => {
                let bytes = tokio::fs::read(&file)
                    .await
                    .with_context(|| format!("could not read {}", file.display()))?;
                let mut arguments: Value = serde_json::from_slice(&bytes).with_context(|| {
                    format!("{} must contain a JSON change object", file.display())
                })?;
                let object = arguments
                    .as_object_mut()
                    .context("the change file must contain a JSON object")?;
                object.insert("request_id".to_owned(), json!(Uuid::now_v7()));
                Ok(("propose_change", arguments))
            }
            Self::Apply { change_id } => Ok(("apply_change", json!({"change_id": change_id}))),
        }
    }
}

pub(crate) async fn run(
    origin: Origin,
    token: Option<SecretString>,
    org: Option<Uuid>,
    command: Command,
) -> anyhow::Result<Verdict> {
    let credential = credentials::load(&origin, token, org)
        .await
        .with_context(|| format!("sign in for configuration with `{LOGIN}`"))?;
    let (name, arguments) = command.request().await?;
    let value = match mcp::call(&Http::new(origin)?, &credential, name, arguments).await {
        // MCP admission refuses a sign-in without `reviews:read` before any
        // tool runs, so no tool refusal names the missing scope.
        Err(error @ mcp::McpError::Http(McpHttpError::Http(401 | 403))) => {
            return Err(anyhow::Error::new(error).context(format!("sign in again with `{LOGIN}`")));
        }
        result => result?,
    };
    tools::json(&value)?;
    let refused = value.get("isError").and_then(Value::as_bool) == Some(true);
    if value
        .pointer("/structuredContent/error/code")
        .and_then(Value::as_str)
        == Some("NOT_AUTHORIZED")
    {
        eprintln!("If a required scope is missing, run `{LOGIN}`.");
    }
    let held = name == "apply_change"
        && value
            .pointer("/structuredContent/data/applied")
            .and_then(Value::as_bool)
            == Some(false);
    Ok(if refused || held {
        Verdict::Blocked
    } else {
        Verdict::Done
    })
}
