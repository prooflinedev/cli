//! Static inspection never starts the configured MCP server.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use clap::{CommandFactory as _, ValueEnum as _, parser::ValueSource};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::{Client, InstallError, config, store};
use crate::origin::{DEFAULT_ORIGIN, Origin};
use crate::{Cli, Verdict};

#[derive(Debug)]
enum Status {
    Missing(&'static str),
    Invalid(&'static str),
    Valid,
    Unverified(&'static str),
}

impl Status {
    const fn message(&self) -> (&'static str, &'static str) {
        match self {
            Self::Missing(reason) => ("Missing registration", reason),
            Self::Invalid(reason) => ("Invalid registration", reason),
            Self::Valid => ("Configuration valid", "local stdio MCP registration."),
            Self::Unverified(reason) => ("Unable to verify", reason),
        }
    }
}

#[derive(Debug)]
struct Report {
    status: Status,
    origin: Option<(Origin, &'static str)>,
}

impl From<Status> for Report {
    fn from(status: Status) -> Self {
        Self {
            status,
            origin: None,
        }
    }
}

pub(super) fn run(client: Client) -> anyhow::Result<Verdict> {
    let mut output = io::stdout().lock();
    let report = match target(client) {
        Ok(path) => {
            writeln!(output, "User-level configuration ({client}): {path:?}")?;
            inspect(client, &path).unwrap_or_else(Report::from)
        }
        Err(reason) => {
            writeln!(
                output,
                "User-level configuration ({client}): path unresolved"
            )?;
            Report::from(Status::Unverified(reason))
        }
    };
    let (label, reason) = report.status.message();
    writeln!(output, "{label}: {reason}")?;
    if let Some((origin, source)) = report.origin {
        writeln!(output, "Origin: {origin} ({source})")?;
    }
    if matches!(report.status, Status::Missing(_))
        && let Some(name) = client.to_possible_value()
    {
        if client == Client::Codex && std::env::var_os("CODEX_HOME").is_some() {
            writeln!(
                output,
                "Next: use `proofline agent install codex --print` and add the entry to the inspected CODEX_HOME configuration."
            )?;
        } else {
            writeln!(
                output,
                "Next: use `proofline agent install {}` to add a user-level entry.",
                name.get_name()
            )?;
        }
    }
    writeln!(
        output,
        "User-level configuration only; local/project scopes, connectivity and authentication were not checked."
    )?;
    Ok(
        if matches!(report.status, Status::Missing(_) | Status::Invalid(_)) {
            Verdict::Blocked
        } else {
            Verdict::Done
        },
    )
}

fn target(client: Client) -> Result<PathBuf, &'static str> {
    if client == Client::ClaudeCode && std::env::var_os("CLAUDE_CONFIG_DIR").is_some() {
        return Err("CLAUDE_CONFIG_DIR selects custom configuration; inspect it manually.");
    }
    if client == Client::Codex
        && let Some(home) = std::env::var_os("CODEX_HOME")
    {
        return Ok(PathBuf::from(home).join("config.toml"));
    }
    let home = std::env::home_dir()
        .filter(|home| home.is_absolute())
        .ok_or("Could not resolve an absolute user home directory; check the client configuration manually.")?;
    Ok(home.join(client.relative_path()))
}

fn inspect(client: Client, path: &Path) -> Result<Report, Status> {
    if !path.is_absolute() {
        return Err(Status::Unverified(
            "The configuration path is relative; the agent's working directory is unknown.",
        ));
    }
    let bytes = match store::inspect(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(Status::Missing(
                "Configuration file not found in the inspected user-level scope.",
            ));
        }
        Err(InstallError::TooLarge) => {
            return Err(Status::Unverified(
                "Configuration exceeds the 1 MiB inspection limit; inspect it manually.",
            ));
        }
        Err(InstallError::File(_)) => {
            return Err(Status::Unverified(
                "Configuration is not a readable regular file; check the file or symlink target.",
            ));
        }
        Err(InstallError::Changed(_)) => {
            return Err(Status::Unverified(
                "Configuration changed while reading; retry the command.",
            ));
        }
        Err(_) => {
            return Err(Status::Unverified(
                "Could not read configuration; check the file and its permissions.",
            ));
        }
    };
    let registration = match config::registration(client, &bytes) {
        Ok(Some(registration)) => registration,
        Ok(None) => {
            return Err(Status::Missing(
                "No Proofline MCP entry in the inspected user-level scope.",
            ));
        }
        Err(InstallError::ConfigShape { member: "root", .. }) => {
            return Err(Status::Invalid(
                "Configuration root must be an object or table; correct the document structure.",
            ));
        }
        Err(InstallError::ConfigShape { .. }) => {
            return Err(Status::Invalid(
                "MCP container must be an object or table; correct its structure.",
            ));
        }
        Err(_) => {
            return Err(Status::Invalid(
                "Could not parse configuration; check its JSON/TOML syntax and nesting depth.",
            ));
        }
    };
    validate(&registration)
}

fn validate(registration: &Value) -> Result<Report, Status> {
    let Some(server) = registration.as_object() else {
        return Err(Status::Invalid(
            "Proofline entry must be an object or table; replace the invalid entry manually.",
        ));
    };
    if server.contains_key("url")
        || server.contains_key("httpUrl")
        || server
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| {
                matches!(kind, "http" | "sse" | "streamable-http" | "streamable_http")
            })
    {
        return Err(Status::Unverified(
            "Remote HTTP/SSE MCP registration; only local stdio launchers are supported by this diagnostic.",
        ));
    }
    let Some(command) = server
        .get("command")
        .and_then(Value::as_str)
        .filter(|command| !command.trim().is_empty() && !command.contains('\0'))
    else {
        return Err(Status::Invalid(
            "command must be a non-empty executable string; correct the Proofline entry.",
        ));
    };
    let args: Vec<&str> = match server.get("args") {
        None => Vec::new(),
        Some(Value::Array(args)) => {
            let Some(args) = args.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
                return Err(Status::Invalid(
                    "args must contain only strings; correct the Proofline entry.",
                ));
            };
            if args.iter().any(|arg| arg.contains('\0')) {
                return Err(Status::Invalid(
                    "args must not contain NUL characters; correct the Proofline entry.",
                ));
            }
            args
        }
        Some(_) => {
            return Err(Status::Invalid(
                "args must be an array of strings; correct the Proofline entry.",
            ));
        }
    };
    if server
        .get("type")
        .is_some_and(|kind| kind.as_str() != Some("stdio"))
    {
        return Err(Status::Invalid(
            "Expected a stdio MCP registration; correct its transport fields.",
        ));
    }
    for key in ["enabled", "disabled"] {
        if server.get(key).is_some_and(|value| !value.is_boolean()) {
            return Err(Status::Invalid(
                "enabled and disabled must be booleans; correct the Proofline entry.",
            ));
        }
    }
    let env = match server.get("env") {
        None => None,
        Some(Value::Object(env)) if env.values().all(Value::is_string) => Some(env),
        Some(_) => {
            return Err(Status::Invalid(
                "env must be an object or table of strings; correct the Proofline entry.",
            ));
        }
    };
    if env.is_some_and(|env| {
        env.iter().any(|(key, value)| {
            key.contains('\0') || value.as_str().is_some_and(|value| value.contains('\0'))
        })
    }) {
        return Err(Status::Invalid(
            "env keys and values must not contain NUL characters; correct the registration environment.",
        ));
    }
    if !inspect_executable(command)? {
        return Err(Status::Unverified(
            "Custom executable or launcher; verify its MCP arguments and origin manually. It was not executed.",
        ));
    }
    let disabled = server.get("enabled").and_then(Value::as_bool) == Some(false)
        || server.get("disabled").and_then(Value::as_bool) == Some(true);
    validate_invocation(Path::new(command), &args, env, disabled)
}

fn inspect_executable(command: &str) -> Result<bool, Status> {
    let executable = Path::new(command);
    if command.contains("${") {
        return Err(Status::Unverified(
            "Executable uses variable expansion; verify the agent's resolved path manually.",
        ));
    }
    if executable.is_absolute() {
        let metadata = match fs::metadata(executable) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Status::Invalid(
                    "Configured executable is missing; update command to an existing executable.",
                ));
            }
            Err(_) => {
                return Err(Status::Unverified(
                    "Could not inspect the configured executable; check its permissions.",
                ));
            }
        };
        if !metadata.is_file() {
            return Err(Status::Invalid(
                "command does not point to a regular file; select an executable.",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(Status::Invalid(
                    "Configured file has no execute permission; fix permissions or select an executable.",
                ));
            }
        }
    }
    Ok(executable.file_name().is_some_and(|name| {
        name == "proofline" || (cfg!(windows) && name.eq_ignore_ascii_case("proofline.exe"))
    }) || std::env::current_exe().is_ok_and(|current| current == executable))
}

fn validate_invocation(
    executable: &Path,
    args: &[&str],
    env: Option<&Map<String, Value>>,
    disabled: bool,
) -> Result<Report, Status> {
    if args.iter().any(|arg| arg.contains("${")) {
        return Err(Status::Unverified(
            "Arguments use variable expansion; verify the agent's resolved MCP arguments and origin manually.",
        ));
    }
    // Ignore this process's environment: the registration belongs to another process.
    let parser = Cli::command()
        .mut_arg("base_url", |arg| arg.env(None::<&str>))
        .mut_arg("org", |arg| arg.env(None::<&str>));
    let matches = match parser
        .try_get_matches_from(std::iter::once("proofline").chain(args.iter().copied()))
    {
        Ok(matches) if matches.subcommand_name() == Some("mcp") => matches,
        _ => {
            return Err(Status::Invalid(
                "args must invoke `proofline mcp` with valid CLI options; correct the MCP subcommand and arguments.",
            ));
        }
    };
    if matches.get_one::<Uuid>("org").is_none() {
        organization(environment(
            env,
            "PROOFLINE_ORGANIZATION_ID",
            cfg!(windows),
        )?)?;
    }
    let (raw_origin, source) = if matches.value_source("base_url") == Some(ValueSource::CommandLine)
    {
        (
            matches
                .get_one::<String>("base_url")
                .map_or(DEFAULT_ORIGIN, String::as_str),
            "registration args --base-url",
        )
    } else if let Some(origin) = environment(env, "PROOFLINE_BASE_URL", cfg!(windows))? {
        (origin, "registration env PROOFLINE_BASE_URL")
    } else {
        (DEFAULT_ORIGIN, "CLI default")
    };
    if raw_origin.contains("${") {
        return Err(Status::Unverified(
            "Origin uses variable expansion; verify the agent's resolved origin manually.",
        ));
    }
    let origin = Origin::parse(raw_origin).map_err(|_| Status::Invalid(
        "Origin must be HTTPS or loopback HTTP, without credentials, path, query or fragment; correct the configured base URL."
    ))?;
    let status = if disabled {
        Status::Unverified("Registration is disabled; enable it in the coding agent if intended.")
    } else if !executable.is_absolute() {
        Status::Unverified(
            "Executable depends on PATH or the agent's working directory; use an absolute path or verify it manually.",
        )
    } else {
        Status::Valid
    };
    Ok(Report {
        status,
        origin: Some((origin, source)),
    })
}

fn organization(value: Option<&str>) -> Result<(), Status> {
    if let Some(value) = value {
        if value.contains("${") {
            return Err(Status::Unverified(
                "Organization ID uses variable expansion; verify its resolved UUID manually.",
            ));
        }
        Uuid::parse_str(value).map_err(|_| {
            Status::Invalid(
                "PROOFLINE_ORGANIZATION_ID must be a UUID; correct the registration environment.",
            )
        })?;
    }
    Ok(())
}

fn environment<'a>(
    env: Option<&'a Map<String, Value>>,
    name: &str,
    windows: bool,
) -> Result<Option<&'a str>, Status> {
    let mut found = None;
    if let Some(env) = env {
        for (key, value) in env {
            if key == name || (windows && key.eq_ignore_ascii_case(name)) {
                let value = value.as_str();
                if found.is_some() && found != value {
                    return Err(Status::Unverified(
                        "Environment has conflicting case variants of a variable; resolve the ambiguity manually.",
                    ));
                }
                found = value;
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
