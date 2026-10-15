//! User-level configuration for the existing credential-free MCP launcher.

mod config;
mod store;

#[cfg(test)]
mod tests;

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, BufRead, Read as _, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};

use crate::origin::Origin;

#[derive(Debug, Args)]
pub(crate) struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Add Proofline to a coding agent's user configuration after confirmation.
    Install(InstallArgs),
}

#[derive(Debug, Args)]
struct InstallArgs {
    /// Coding agent whose user configuration receives the MCP server.
    #[arg(value_enum)]
    client: Client,
    /// Print the credential-free server entry without writing any file.
    #[arg(long)]
    print: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Client {
    Codex,
    Cursor,
    Gemini,
    Kiro,
}

impl Client {
    const fn relative_path(self) -> &'static str {
        match self {
            Self::Codex => ".codex/config.toml",
            Self::Cursor => ".cursor/mcp.json",
            Self::Gemini => ".gemini/settings.json",
            Self::Kiro => ".kiro/settings/mcp.json",
        }
    }
}

impl fmt::Display for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::Gemini => "Gemini CLI",
            Self::Kiro => "Kiro",
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum InstallError {
    #[error("could not find an absolute user home directory")]
    Home,
    #[error(
        "CODEX_HOME selects a different directory; use --print and add the entry to that user configuration manually"
    )]
    CustomCodexHome,
    #[error(
        "could not parse the {0} configuration; leave it unchanged and use --print for the server entry"
    )]
    InvalidConfig(Client),
    #[error(
        "the {client} configuration's {member} must be an object or table; the file stays unchanged"
    )]
    ConfigShape {
        client: Client,
        member: &'static str,
    },
    #[error(
        "the configuration exceeds the 1 MiB installer limit; use --print and add the entry manually"
    )]
    TooLarge,
    #[error("refusing to write a configuration inside a Git working tree: {0:?}")]
    Repository(PathBuf),
    #[error(
        "could not determine whether {0:?} is inside a Git working tree; no configuration was written"
    )]
    GitProbe(PathBuf),
    #[error("refusing a symlink or non-directory configuration path: {0:?}")]
    Directory(PathBuf),
    #[error("refusing a symlink or non-regular configuration file: {0:?}")]
    File(PathBuf),
    #[error("the configuration is read-only: {0:?}")]
    ReadOnly(PathBuf),
    #[error(
        "another Proofline installer holds the configuration lock: {0:?}; retry after it finishes"
    )]
    Busy(PathBuf),
    #[error(
        "the configuration or its directory changed during installation: {0:?}; run the command again for a fresh preview"
    )]
    Changed(PathBuf),
    #[error("could not {operation} {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("could not {operation}: {source}")]
    Console {
        operation: &'static str,
        source: io::Error,
    },
    #[error("the configuration installer could not finish: {0}")]
    Task(tokio::task::JoinError),
}

impl InstallError {
    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_owned(),
            source,
        }
    }

    const fn console(operation: &'static str, source: io::Error) -> Self {
        Self::Console { operation, source }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Printed,
    Cancelled,
    Existing,
    Installed,
}

pub(crate) async fn run(args: AgentArgs, origin: Origin) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        let AgentCommand::Install(args) = args.command;
        let home = std::env::home_dir().ok_or(InstallError::Home)?;
        let codex_home = std::env::var_os("CODEX_HOME");
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        install(
            &home,
            codex_home.as_deref(),
            &args,
            &origin,
            &mut stdin.lock(),
            &mut stdout.lock(),
            &mut stderr.lock(),
        )
    })
    .await
    .map_err(InstallError::Task)??;
    Ok(())
}

fn install(
    home: &Path,
    codex_home: Option<&OsStr>,
    args: &InstallArgs,
    origin: &Origin,
    input: &mut impl BufRead,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<Outcome, InstallError> {
    let snippet = config::snippet(args.client, origin)?;
    if args.print {
        output
            .write_all(snippet.as_bytes())
            .map_err(|error| InstallError::console("print the server entry", error))?;
        return Ok(Outcome::Printed);
    }
    if !home.is_absolute() {
        return Err(InstallError::Home);
    }
    if args.client == Client::Codex
        && codex_home.is_some_and(|selected| Path::new(selected) != home.join(".codex"))
    {
        return Err(InstallError::CustomCodexHome);
    }
    let layout = store::Layout::new(home, args.client)?;
    let before = layout.read()?;
    let config::Update::Change(bytes) = config::prepare(args.client, before.bytes(), origin)?
    else {
        existing(&layout, diagnostics)?;
        return Ok(Outcome::Existing);
    };
    layout.writable(&before)?;
    writeln!(
        diagnostics,
        "Add this {0} server to {1:?}:\n{snippet}",
        args.client,
        layout.target()
    )
    .map_err(|error| InstallError::console("show the proposed server entry", error))?;
    write!(diagnostics, "Write this entry? [y/N] ")
        .and_then(|()| diagnostics.flush())
        .map_err(|error| InstallError::console("ask for confirmation", error))?;
    let mut answer = String::new();
    input
        .take(65)
        .read_line(&mut answer)
        .map_err(|error| InstallError::console("read confirmation", error))?;
    if answer.len() > 64
        || !answer.ends_with('\n')
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        writeln!(diagnostics, "No configuration was written.")
            .map_err(|error| InstallError::console("report the unchanged configuration", error))?;
        return Ok(Outcome::Cancelled);
    }
    match layout.save(&before, &bytes, origin)? {
        store::Saved::Existing => {
            existing(&layout, diagnostics)?;
            Ok(Outcome::Existing)
        }
        store::Saved::Installed => {
            writeln!(diagnostics, "Added Proofline to {:?}. Sign in to the same console with `proofline login --scope reviews:read`, using the same `--base-url`; the coding agent uses the CLI's existing credential.", layout.target())
                .map_err(|error| InstallError::console("report the saved configuration", error))?;
            Ok(Outcome::Installed)
        }
    }
}

fn existing(layout: &store::Layout, diagnostics: &mut impl Write) -> Result<(), InstallError> {
    writeln!(
        diagnostics,
        "A proofline entry already exists in {:?}; it stays unchanged.",
        layout.target()
    )
    .map_err(|error| InstallError::console("report the existing entry", error))
}
