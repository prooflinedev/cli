//! `proofline completions` prints a usable script for each supported shell
//! without a token, an origin or the network.
use std::process::{Command, Output};

fn completions(shell: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_proofline"))
        .args(["--base-url", "invalid", "completions", shell])
        .env("PROOFLINE_NO_UPDATE_CHECK", "1")
        .env_remove("PROOFLINE_TOKEN")
        .env_remove("PROOFLINE_ORGANIZATION_ID")
        .output()
        .unwrap()
}

#[test]
fn every_shell_gets_a_script_naming_the_visible_commands() {
    for (shell, marker) in [
        ("zsh", "#compdef proofline"),
        ("bash", "complete -F _proofline"),
        ("fish", "complete -c proofline"),
        ("powershell", "Register-ArgumentCompleter"),
    ] {
        let output = completions(shell);
        assert!(output.status.success(), "{shell}: {output:?}");
        assert!(output.stderr.is_empty(), "{shell}: {output:?}");
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(script.contains(marker), "{shell} script lacks {marker:?}");
        for visible in ["review", "findings", "login", "completions", "base-url"] {
            assert!(script.contains(visible), "{shell} script lacks {visible:?}");
        }
        assert!(
            !script.contains("__update-check"),
            "{shell} script offers a hidden command"
        );
    }
}

#[test]
fn an_unknown_shell_is_refused() {
    let output = completions("tcsh");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr).unwrap().contains("zsh"));
}

#[test]
fn the_bash_script_completes_subcommands() {
    let Ok(probe) = Command::new("bash").arg("--version").output() else {
        return;
    };
    if !probe.status.success() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("proofline.bash");
    std::fs::write(&path, completions("bash").stdout).unwrap();
    let output = Command::new("bash")
        .arg("-c")
        .arg(
            r#"source "$1"
COMP_WORDS=(proofline comp)
COMP_CWORD=1
COMP_LINE="proofline comp"
COMP_POINT=${#COMP_LINE}
_proofline proofline comp proofline
printf '%s\n' "${COMPREPLY[@]}""#,
        )
        .arg("bash")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "completions\n");
}
