//! The noninteractive install contract exercised through the shipped binary.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;

fn command(binary: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("CODEX_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env("PROOFLINE_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::null());
    command
}

#[test]
fn unattended_registration_preserves_settings_and_uses_the_installed_binary() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("home");
    let directory = root.path().join("install with spaces 東京");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&directory).unwrap();
    let binary = directory.join(if cfg!(windows) {
        "proofline.exe"
    } else {
        "proofline"
    });
    fs::copy(env!("CARGO_BIN_EXE_proofline"), &binary).unwrap();
    let executable = binary.canonicalize().unwrap();
    for (client, relative) in [
        ("claude-code", ".claude.json"),
        ("cursor", ".cursor/mcp.json"),
        ("codex", ".codex/config.toml"),
    ] {
        let path = home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = if client == "codex" {
            "# preserved\nmodel = 'chosen-model'\n".to_owned()
        } else {
            json!({"projects": {"private-project": {"hasTrustDialogAccepted": false}},
                "mcpServers": {"other": {"command": "other-server"}}})
            .to_string()
        };
        fs::write(&path, &original).unwrap();
        let installed = command(&binary, &home)
            .args(["agent", "install", client, "--yes"])
            .output()
            .unwrap();
        assert!(
            installed.status.success(),
            "{}",
            String::from_utf8_lossy(&installed.stderr)
        );
        let bytes = fs::read_to_string(&path).unwrap();
        let server = if client == "codex" {
            assert!(bytes.starts_with(&original));
            let config: toml::Value = toml::from_str(&bytes).unwrap();
            serde_json::to_value(&config["mcp_servers"]["proofline"]).unwrap()
        } else {
            let mut config: Value = serde_json::from_str(&bytes).unwrap();
            let server = config["mcpServers"]
                .as_object_mut()
                .unwrap()
                .remove("proofline")
                .unwrap();
            assert_eq!(config, serde_json::from_str::<Value>(&original).unwrap());
            server
        };
        assert_eq!(
            Path::new(server["command"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            executable
        );
        assert_eq!(
            server["args"],
            json!(["--base-url", "https://proofline.sh", "mcp"])
        );
        let replay = command(&binary, &home)
            .args(["agent", "install", client, "--yes"])
            .output()
            .unwrap();
        assert!(replay.status.success());
        assert_eq!(fs::read_to_string(&path).unwrap(), bytes);
    }
}

#[test]
fn unattended_confirmation_keeps_refusals_and_manual_preview() {
    let home = TempDir::new().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_proofline"));
    let path = home.path().join(".claude.json");
    let private = "{\"private-canary\":true,\"mcpServers\":[]}";
    fs::write(&path, private).unwrap();
    let refused = command(binary, home.path())
        .args(["agent", "install", "claude", "--yes"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("private-canary"));
    assert_eq!(fs::read_to_string(&path).unwrap(), private);
    fs::remove_file(&path).unwrap();
    let custom = home.path().join("custom");
    let refused = command(binary, home.path())
        .env("CLAUDE_CONFIG_DIR", &custom)
        .args(["agent", "install", "claude-code", "--yes"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!path.exists());
    assert!(!custom.exists());
    let preview = command(binary, home.path())
        .env("CLAUDE_CONFIG_DIR", &custom)
        .args(["agent", "install", "claude-code", "--print"])
        .output()
        .unwrap();
    assert!(preview.status.success());
    assert!(serde_json::from_slice::<Value>(&preview.stdout).is_ok());
    assert!(!path.exists());
    assert!(!custom.exists());
}

#[cfg(unix)]
#[test]
fn without_git_registration_names_the_recovery_and_a_repository_still_refuses() {
    let root = TempDir::new().unwrap();
    let no_git = root.path().join("no-git");
    let home = root.path().join("home");
    fs::create_dir_all(&no_git).unwrap();
    fs::create_dir_all(&home).unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_proofline"));
    let run = |args: &[&str]| {
        command(binary, &home)
            .env("PATH", &no_git)
            .args(args)
            .output()
            .unwrap()
    };
    let missing = run(&["agent", "install", "codex", "--yes"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("install Git"));
    assert_eq!(fs::read_dir(&home).unwrap().count(), 0);
    let preview = run(&["agent", "install", "codex", "--print"]);
    assert!(preview.status.success());
    assert!(toml::from_str::<toml::Value>(std::str::from_utf8(&preview.stdout).unwrap()).is_ok());
    fs::create_dir_all(home.join(".git")).unwrap();
    let repository = run(&["agent", "install", "codex", "--yes"]);
    assert!(!repository.status.success());
    let refused = String::from_utf8_lossy(&repository.stderr);
    assert!(refused.contains("Git working tree") && !refused.contains("install Git"));
    assert_eq!(fs::read_dir(&home).unwrap().count(), 1);
}
