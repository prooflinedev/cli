//! Cached discovery preserves process output contracts and installed files.
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn cached_update_preserves_schema_help_and_source_installation() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("proofline");
    std::fs::create_dir_all(&cache).unwrap();
    let checked = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(
        cache.join("update.json"),
        format!("{{\"checked\":{checked},\"latest\":\"9.0.0\"}}"),
    )
    .unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_proofline"))
            .args(args)
            .env_remove("PROOFLINE_NO_UPDATE_CHECK")
            .env("HOME", directory.path())
            .env("XDG_CACHE_HOME", directory.path())
            .env("LOCALAPPDATA", directory.path())
            .env_remove("PROOFLINE_TOKEN")
            .env_remove("PROOFLINE_ORGANIZATION_ID")
            .env_remove("PROOFLINE_INSTALL_DIR")
            .output()
            .unwrap()
    };
    let schema = invoke(&["--base-url", "invalid", "review", "--schema"]);
    assert!(schema.status.success());
    assert!(schema.stderr.is_empty());
    let parsed: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
    assert!(parsed["properties"].is_object());
    let help = invoke(&["--help"]);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("update"));
    assert!(!help.contains("__update-check"));
    let installed = directory.path().join(".local/bin/proofline");
    std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
    std::fs::write(&installed, b"keep this installed CLI").unwrap();
    let update = invoke(&["--base-url", "invalid", "update"]);
    assert!(!update.status.success());
    assert!(update.stdout.is_empty());
    assert_eq!(
        std::fs::read(installed).unwrap(),
        b"keep this installed CLI"
    );
}
