//! The `proofline` binary.

use std::process::ExitCode;

use clap::Parser as _;
use proofline_cli::{Cli, Verdict, run};
use secrecy::SecretString;

fn main() -> ExitCode {
    if let Err(error) = use_user_session_bus() {
        eprintln!("proofline: could not connect to the user session bus: {error}");
        return ExitCode::FAILURE;
    }
    proofline_cli::update::on_invocation();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if error.print().is_err() {
                // A closed stream leaves nothing to report the failure to.
            }
            // `--help` and `--version` arrive here and are not failures. For a
            // refused command line clap exits 2, which this CLI keeps for a
            // review without a complete result.
            return if error.use_stderr() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    // Read here rather than through clap, so the value never appears in help.
    let token = std::env::var("PROOFLINE_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(SecretString::from);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("proofline: could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli, token)) {
        Ok(Verdict::Done) => ExitCode::SUCCESS,
        // Distinct from a failure to run: the review exists but is not a
        // complete result.
        Ok(Verdict::NotComplete) => ExitCode::from(2),
        // Proofline gave no answer in time; distinct from the caller's error.
        Ok(Verdict::Unavailable) => ExitCode::from(4),
        // `ci review --fail-on`: the review is complete and a finding reaches
        // the caller's threshold.
        Ok(Verdict::ThresholdReached) => ExitCode::from(3),
        Ok(Verdict::Blocked) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("proofline: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// The keychain library reads its bus address from the environment. Restart
/// with the discovered address before initialization, keeping environment
/// mutation out of this process. The explicit address ends discovery on restart.
#[cfg(target_os = "linux")]
fn use_user_session_bus() -> std::io::Result<()> {
    use std::os::unix::process::CommandExt as _;

    if let Some(address) = proofline_cli::credentials::default_session_bus() {
        let executable = std::env::current_exe()?;
        return Err(std::process::Command::new(executable)
            .args(std::env::args_os().skip(1))
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .exec());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn use_user_session_bus() -> std::io::Result<()> {
    Ok(())
}
