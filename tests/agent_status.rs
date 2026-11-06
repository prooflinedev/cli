//! Process-level contracts; semantic cases live beside the validator and parsers.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};

use serde_json::{Value, json};
use tempfile::TempDir;

const SECRET: &str = "private-status-canary";
const CLIENTS: [(&str, &str); 5] = [
    ("claude-code", ".claude.json"),
    ("codex", ".codex/config.toml"),
    ("cursor", ".cursor/mcp.json"),
    ("gemini", ".gemini/settings.json"),
    ("kiro", ".kiro/settings/mcp.json"),
];

fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proofline"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("LOCALAPPDATA", home.join("cache"))
        .env_remove("CODEX_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("PROOFLINE_NO_UPDATE_CHECK")
        .env_remove("PROOFLINE_ORGANIZATION_ID")
        .env("PROOFLINE_TOKEN", SECRET)
        .env("PROOFLINE_BASE_URL", "invalid-invoking-process-origin")
        .stdin(Stdio::null());
    command
}

fn entries(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    fn visit(root: &Path, path: &Path, entries: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            if path.is_dir() {
                entries.push((relative, None));
                visit(root, &path, entries);
            } else {
                entries.push((relative, Some(fs::read(path).unwrap())));
            }
        }
    }
    let mut found = Vec::new();
    visit(root, root, &mut found);
    found.sort();
    found
}

fn check(home: &Path, command: &mut Command, code: i32, expected: &str) -> String {
    let before = entries(home);
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(expected), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(
        text.contains("local/project scopes, connectivity and authentication were not checked")
    );
    assert_eq!(entries(home), before);
    text
}

fn status(home: &Path, client: &str, code: i32, expected: &str) -> String {
    check(
        home,
        command(home).args(["agent", "status", client]),
        code,
        expected,
    )
}

fn seed(home: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = home.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn registration(home: &Path, client: &str, relative: &str, server: Value) -> PathBuf {
    let key = if client == "codex" {
        "mcp_servers"
    } else {
        "mcpServers"
    };
    let document = json!({key: {"proofline":server}, "private":SECRET});
    let bytes = if client == "codex" {
        toml::to_string(&document).unwrap()
    } else {
        document.to_string()
    };
    seed(home, relative, bytes.as_bytes())
}

fn server() -> Value {
    json!({"command":env!("CARGO_BIN_EXE_proofline"),"args":["mcp"]})
}

#[test]
fn all_clients_report_missing_then_accept_installer_generated_entries_without_writes() {
    let home = TempDir::new().unwrap();
    for (client, relative) in CLIENTS {
        let path = home.path().join(relative);
        let missing = status(home.path(), client, 1, "Missing registration:");
        assert!(missing.contains(&format!("{path:?}")));
        assert!(missing.contains(&format!("proofline agent install {client}")));
        assert!(!missing.contains("CLIENT"));
        let preview = command(home.path())
            .env("PROOFLINE_NO_UPDATE_CHECK", "1")
            .env_remove("PROOFLINE_BASE_URL")
            .args(["agent", "install", client, "--print"])
            .output()
            .unwrap();
        assert!(preview.status.success(), "{preview:?}");
        seed(home.path(), relative, &preview.stdout);
        let metadata = fs::metadata(&path).unwrap();
        let text = status(home.path(), client, 0, "Configuration valid:");
        assert!(text.contains("Origin: https://proofline.sh (registration args --base-url)"));
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            metadata.modified().unwrap()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions(),
            metadata.permissions()
        );
    }
    status(home.path(), "claude", 0, "Configuration valid:");
}

#[test]
fn deeply_nested_toml_returns_invalid_without_aborting_or_disclosing_contents() {
    let home = TempDir::new().unwrap();
    let key = vec!["x"; 60].join(".");
    for nesting in [10, 100] {
        let config = format!(
            "a = {}1{}\nprivate = '{SECRET}'\n",
            format!("{{{key} = ").repeat(nesting),
            "}".repeat(nesting),
        );
        seed(home.path(), ".codex/config.toml", config.as_bytes());
        status(
            home.path(),
            "codex",
            1,
            "Invalid registration: Could not parse configuration; check its JSON/TOML syntax and nesting depth.",
        );
    }
}

#[test]
fn invalid_and_unverified_entries_have_explicit_exit_codes_and_redacted_diagnostics() {
    let home = TempDir::new().unwrap();
    let mut bad_origin = server();
    bad_origin["args"] = json!([
        "mcp",
        "--base-url",
        format!("https://user:{SECRET}@example.com")
    ]);
    for (entry, code, label) in [
        (json!(42), 1, "Invalid registration: Proofline entry"),
        (bad_origin, 1, "Invalid registration: Origin must"),
        (
            json!({"command":env!("CARGO_BIN_EXE_proofline"),"args":["mcp"],"env":{"PROOFLINE_ORGANIZATION_ID":SECRET}}),
            1,
            "Invalid registration: PROOFLINE_ORGANIZATION_ID",
        ),
        (
            json!({"command":"custom-launcher","args":[SECRET],"env":{"PROOFLINE_ORGANIZATION_ID":SECRET}}),
            0,
            "Unable to verify: Custom executable or launcher",
        ),
        (
            json!({"url":format!("https://user:{SECRET}@example.com/mcp")}),
            0,
            "Unable to verify: Remote HTTP/SSE",
        ),
    ] {
        registration(home.path(), "codex", ".codex/config.toml", entry);
        let text = status(home.path(), "codex", code, label);
        assert_eq!(text.matches(label).count(), 1);
    }
}

#[test]
fn status_ignores_invoking_organization_but_rejects_explicit_global_overrides() {
    let home = TempDir::new().unwrap();
    registration(home.path(), "claude-code", ".claude.json", server());
    check(
        home.path(),
        command(home.path())
            .env("PROOFLINE_ORGANIZATION_ID", SECRET)
            .args(["agent", "status", "claude"]),
        0,
        "Configuration valid:",
    );
    for args in [
        vec!["--base-url", SECRET, "agent", "status", "claude"],
        vec!["agent", "status", "claude", "--base-url", SECRET],
        vec!["agent", "--base-url", SECRET, "status", "claude"],
        vec![
            "agent",
            "status",
            "claude",
            "--base-url=private-status-canary",
        ],
        vec!["--org", SECRET, "agent", "status", "claude"],
        vec!["agent", "status", "claude", "--org", SECRET],
        vec!["agent", "status", "claude", "--org=private-status-canary"],
    ] {
        let before = entries(home.path());
        let output = command(home.path())
            .env("PROOFLINE_ORGANIZATION_ID", SECRET)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(
            text.contains("--base-url and --org are not supported"),
            "{text}"
        );
        assert!(!text.contains(SECRET));
        assert_eq!(entries(home.path()), before);
    }
    for (args, code) in [
        (vec!["agent", "status", "--help"], 0),
        (vec!["agent", "status", "unsupported"], 1),
        (vec!["agent", "status"], 1),
    ] {
        let before = entries(home.path());
        let output = command(home.path())
            .env("PROOFLINE_ORGANIZATION_ID", SECRET)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        if code == 0 {
            let help = String::from_utf8(output.stdout).unwrap();
            assert!(help.contains("Status does not accept --base-url or --org"));
            assert!(!help.contains(SECRET));
        }
        assert_eq!(entries(home.path()), before);
    }
}

#[cfg(unix)]
#[test]
fn status_ignores_non_utf8_invoking_origin_without_changing_other_commands() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let home = TempDir::new().unwrap();
    registration(home.path(), "claude-code", ".claude.json", server());
    let origin = OsString::from_vec(vec![0xff]);
    check(
        home.path(),
        command(home.path())
            .env("PROOFLINE_BASE_URL", &origin)
            .env("PROOFLINE_ORGANIZATION_ID", SECRET)
            .args(["agent", "status", "claude"]),
        0,
        "Configuration valid:",
    );
    for args in [
        vec!["setup", "--print"],
        vec!["agent", "install", "claude", "--print"],
    ] {
        let before = entries(home.path());
        let output = command(home.path())
            .env("PROOFLINE_NO_UPDATE_CHECK", "1")
            .env("PROOFLINE_BASE_URL", &origin)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid UTF-8"));
        assert_eq!(entries(home.path()), before);
    }
}

#[test]
fn other_commands_keep_invoking_organization_validation() {
    let home = TempDir::new().unwrap();
    for args in [
        vec!["setup", "--print"],
        vec!["agent", "install", "claude", "--print"],
    ] {
        let invalid = command(home.path())
            .env("PROOFLINE_NO_UPDATE_CHECK", "1")
            .env("PROOFLINE_BASE_URL", "https://proofline.sh")
            .env("PROOFLINE_ORGANIZATION_ID", SECRET)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(invalid.status.code(), Some(1));
        assert!(invalid.stdout.is_empty());
        let valid = command(home.path())
            .env("PROOFLINE_NO_UPDATE_CHECK", "1")
            .env("PROOFLINE_BASE_URL", "https://proofline.sh")
            .env(
                "PROOFLINE_ORGANIZATION_ID",
                "00000000-0000-0000-0000-000000000000",
            )
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(valid.status.code(), Some(0), "{valid:?}");
    }
    for args in [["review", "--help"], ["help", "review"]] {
        let output = command(home.path())
            .env("PROOFLINE_NO_UPDATE_CHECK", "1")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--help"));
        assert!(help.contains("PROOFLINE_ORGANIZATION_ID"));
    }
}

#[test]
fn origin_and_organization_precedence_survive_parsing_and_rendering() {
    let home = TempDir::new().unwrap();
    for (args, env, expected) in [
        (
            json!([
                "mcp",
                "--base-url=https://alternate.example",
                "--org",
                "00000000-0000-0000-0000-000000000000"
            ]),
            json!({"PROOFLINE_BASE_URL":SECRET,"PROOFLINE_ORGANIZATION_ID":SECRET,"PROOFLINE_TOKEN":SECRET}),
            "Origin: https://alternate.example (registration args --base-url)",
        ),
        (
            json!(["mcp"]),
            json!({"PROOFLINE_BASE_URL":"http://127.0.0.1:3000","PROOFLINE_ORGANIZATION_ID":"00000000-0000-0000-0000-000000000000","PROOFLINE_TOKEN":SECRET}),
            "Origin: http://127.0.0.1:3000 (registration env PROOFLINE_BASE_URL)",
        ),
        (
            json!(["mcp"]),
            json!({}),
            "Origin: https://proofline.sh (CLI default)",
        ),
    ] {
        registration(
            home.path(),
            "cursor",
            ".cursor/mcp.json",
            json!({"command":env!("CARGO_BIN_EXE_proofline"),"args":args,"env":env}),
        );
        status(home.path(), "cursor", 0, expected);
    }
}

#[test]
fn json_inspection_and_installation_keep_separate_duplicate_policies() {
    let home = TempDir::new().unwrap();
    let bytes = format!(
        "{{\"mcpServers\":{{\"proofline\":null,\"proofline\":{}}}}}",
        server()
    );
    let path = seed(home.path(), ".claude.json", bytes.as_bytes());
    status(home.path(), "claude", 0, "Configuration valid:");
    let refused = command(home.path())
        .env("PROOFLINE_NO_UPDATE_CHECK", "1")
        .env_remove("PROOFLINE_BASE_URL")
        .args(["agent", "install", "claude", "--yes"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&refused.stderr).contains(SECRET));
    assert_eq!(fs::read_to_string(path).unwrap(), bytes);
}

#[test]
fn inspection_keeps_configurations_and_stale_update_state_unchanged_without_http() {
    let home = TempDir::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    registration(
        home.path(),
        "claude-code",
        ".claude.json",
        json!({"command":env!("CARGO_BIN_EXE_proofline"),"args":["mcp","--base-url",origin]}),
    );
    for stale_cache in [false, true] {
        if stale_cache {
            seed(
                home.path(),
                "cache/proofline/update.json",
                b"{\"checked\":0,\"latest\":\"9.0.0\"}",
            );
        }
        check(
            home.path(),
            command(home.path())
                .env("PROOFLINE_BASE_URL", &origin)
                .args(["agent", "status", "claude"]),
            0,
            "Configuration valid:",
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn custom_homes_do_not_fall_back_to_default_configuration_or_misleading_hints() {
    let home = TempDir::new().unwrap();
    registration(home.path(), "codex", ".codex/config.toml", server());
    let custom = home.path().join("custom");
    let text = check(
        home.path(),
        command(home.path())
            .env("CODEX_HOME", &custom)
            .args(["agent", "status", "codex"]),
        1,
        "Missing registration:",
    );
    assert!(text.contains(&format!("{:?}", custom.join("config.toml"))));
    assert!(text.contains("proofline agent install codex --print"));
    registration(home.path(), "codex", "custom/config.toml", server());
    check(
        home.path(),
        command(home.path())
            .env("CODEX_HOME", &custom)
            .args(["agent", "status", "codex"]),
        0,
        "Configuration valid:",
    );
    check(
        home.path(),
        command(home.path())
            .env("CODEX_HOME", "relative")
            .args(["agent", "status", "codex"]),
        0,
        "Unable to verify: The configuration path is relative",
    );
    check(
        home.path(),
        command(home.path())
            .env("CLAUDE_CONFIG_DIR", custom)
            .args(["agent", "status", "claude"]),
        0,
        "Unable to verify: CLAUDE_CONFIG_DIR",
    );
}

#[cfg(unix)]
#[test]
fn executable_marker_and_external_symlink_targets_are_never_modified() {
    let home = TempDir::new().unwrap();
    let targets = TempDir::new().unwrap();
    let executable = targets.path().join("proofline");
    fs::write(
        &executable,
        b"#!/bin/sh\nprintf executed > \"$0.executed\"\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    for (client, relative) in [
        ("claude-code", ".claude.json"),
        ("codex", ".codex/config.toml"),
    ] {
        let target = registration(
            targets.path(),
            client,
            relative,
            json!({"command":executable,"args":["mcp"]}),
        );
        let path = home.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(&target, &path).unwrap();
        let before = entries(targets.path());
        let metadata = fs::metadata(&target).unwrap();
        status(home.path(), client, 0, "Configuration valid:");
        assert_eq!(entries(targets.path()), before);
        assert_eq!(
            fs::metadata(&target).unwrap().modified().unwrap(),
            metadata.modified().unwrap()
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions(),
            metadata.permissions()
        );
        assert_eq!(fs::read_link(&path).unwrap(), target);
        fs::write(&target, vec![b' '; 1024 * 1024 + 1]).unwrap();
        let before = entries(targets.path());
        status(
            home.path(),
            client,
            0,
            "Unable to verify: Configuration exceeds",
        );
        assert_eq!(entries(targets.path()), before);
    }
    let launcher = targets.path().join("custom launcher");
    fs::rename(executable, &launcher).unwrap();
    registration(
        home.path(),
        "cursor",
        ".cursor/mcp.json",
        json!({"command":launcher,"args":[SECRET],"env":{"PROOFLINE_ORGANIZATION_ID":SECRET}}),
    );
    let before = entries(targets.path());
    status(
        home.path(),
        "cursor",
        0,
        "Unable to verify: Custom executable or launcher",
    );
    assert_eq!(entries(targets.path()), before);
}

#[cfg(windows)]
#[test]
fn windows_paths_and_environment_casing_work_together() {
    let home = TempDir::new().unwrap();
    let executable = home.path().join("install with spaces 東京/PROOFLINE.EXE");
    fs::create_dir_all(executable.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_proofline"), &executable).unwrap();
    let mut entry = json!({"command":executable,"args":["mcp"],"env":{"proofline_base_url":"https://alternate.example","Proofline_Organization_ID":"00000000-0000-0000-0000-000000000000"}});
    registration(home.path(), "codex", ".codex/config.toml", entry.clone());
    status(
        home.path(),
        "codex",
        0,
        "Origin: https://alternate.example (registration env PROOFLINE_BASE_URL)",
    );
    entry["env"]["Proofline_Organization_ID"] = json!(SECRET);
    registration(home.path(), "codex", ".codex/config.toml", entry);
    status(
        home.path(),
        "codex",
        1,
        "Invalid registration: PROOFLINE_ORGANIZATION_ID",
    );
}
