use std::fs;

use serde_json::{Value, json};
use tempfile::TempDir;

use super::{Report, Status, environment, inspect, organization, validate};

const SECRET: &str = "private-status-canary";

fn entry() -> Value {
    json!({"command": std::env::current_exe().unwrap(), "args": ["mcp"]})
}

fn check(value: &Value, label: &str, reason: &str) -> Report {
    let report = validate(value).unwrap_or_else(Report::from);
    assert_eq!(report.status.message().0, label, "{report:?}");
    assert!(report.status.message().1.contains(reason), "{report:?}");
    assert!(!report.status.message().1.contains(SECRET));
    report
}

#[test]
fn registration_shape_is_validated_before_local_invocation_semantics() {
    for value in [Value::Null, json!(42), json!([])] {
        check(&value, "Invalid registration", "Proofline entry");
    }
    check(&json!({}), "Invalid registration", "command must");
    for (field, replacement, reason) in [
        ("command", json!(42), "command must"),
        ("command", json!("  "), "command must"),
        ("command", json!("proofline\0"), "command must"),
        ("args", json!(SECRET), "args must"),
        ("args", json!(["mcp", 42]), "args must"),
        ("args", json!(["mcp\0"]), "NUL"),
        ("type", json!("unsupported"), "stdio MCP"),
        ("type", json!(42), "stdio MCP"),
        ("env", json!([]), "env must"),
        ("env", json!({"SECRET":42}), "env must"),
        ("enabled", json!(SECRET), "must be booleans"),
        ("disabled", json!(SECRET), "must be booleans"),
    ] {
        let mut registration = entry();
        registration[field] = replacement;
        check(&registration, "Invalid registration", reason);
    }
}

#[test]
fn remote_transports_do_not_require_a_local_executable() {
    for value in [
        json!({"url":format!("https://user:{SECRET}@example.com/mcp")}),
        json!({"httpUrl":"https://example.com/mcp"}),
        json!({"type":"sse"}),
        json!({"type":"http","command":"missing-executable"}),
        json!({"type":"streamable-http"}),
        json!({"type":"streamable_http"}),
    ] {
        check(&value, "Unable to verify", "Remote HTTP/SSE");
    }
}

#[test]
fn direct_invocations_require_mcp_and_valid_cli_arguments() {
    for args in [
        json!([]),
        json!(["review"]),
        json!(["mcp", "--unknown", SECRET]),
        json!(["--base-url"]),
        json!(["mcp", "--help"]),
        json!(["mcp", "--version"]),
    ] {
        let mut value = entry();
        value["args"] = args;
        check(&value, "Invalid registration", "args must invoke");
    }
    let mut value = entry();
    value.as_object_mut().unwrap().remove("args");
    check(&value, "Invalid registration", "args must invoke");
}

#[test]
fn direct_origins_follow_argument_environment_and_default_precedence() {
    for (args, env, expected, source) in [
        (
            json!(["--base-url", "https://alternate.example:8443", "mcp"]),
            json!({"PROOFLINE_BASE_URL":SECRET}),
            "https://alternate.example:8443",
            "registration args --base-url",
        ),
        (
            json!(["mcp", "--base-url=http://[::1]:8080"]),
            json!({}),
            "http://[::1]:8080",
            "registration args --base-url",
        ),
        (
            json!(["mcp"]),
            json!({"PROOFLINE_BASE_URL":"https://alternate.example"}),
            "https://alternate.example",
            "registration env PROOFLINE_BASE_URL",
        ),
        (
            json!(["mcp"]),
            json!({}),
            "https://proofline.sh",
            "CLI default",
        ),
    ] {
        let mut value = entry();
        value["args"] = args;
        value["env"] = env;
        let report = check(&value, "Configuration valid", "stdio");
        let (origin, actual_source) = report.origin.unwrap();
        assert_eq!(origin.to_string(), expected);
        assert_eq!(actual_source, source);
    }
    for origin in [
        "invalid",
        "http://example.com",
        "https://proofline.sh/api",
        "https://proofline.sh/?token=private-status-canary",
        "https://user:private-status-canary@proofline.sh",
    ] {
        let mut value = entry();
        value["args"] = json!(["mcp", "--base-url", origin]);
        check(&value, "Invalid registration", "Origin must");
        value["args"] = json!(["mcp"]);
        value["env"] = json!({"PROOFLINE_BASE_URL":origin});
        check(&value, "Invalid registration", "Origin must");
    }
}

#[test]
fn direct_organization_environment_and_argument_precedence_use_cli_uuid_formats() {
    for organization in [
        "00000000-0000-0000-0000-000000000000",
        "0190F3A0000070008000000000000001",
        "urn:uuid:0190f3a0-0000-7000-8000-000000000001",
    ] {
        let mut value = entry();
        value["env"] = json!({"PROOFLINE_ORGANIZATION_ID": organization});
        check(&value, "Configuration valid", "stdio");
        value["args"] = json!(["mcp", "--org", organization]);
        value["env"]["PROOFLINE_ORGANIZATION_ID"] = json!(SECRET);
        check(&value, "Configuration valid", "stdio");
    }
    for organization in [SECRET, ""] {
        let mut value = entry();
        value["env"] = json!({"PROOFLINE_ORGANIZATION_ID": organization});
        check(&value, "Invalid registration", "must be a UUID");
    }
}

#[test]
fn custom_launchers_do_not_inherit_proofline_specific_environment_validation() {
    for organization in [SECRET, "${LAUNCHER_TENANT}"] {
        let value = json!({"command":"custom-launcher", "args":[SECRET], "env":{"PROOFLINE_ORGANIZATION_ID":organization,"PROOFLINE_BASE_URL":SECRET}});
        let report = check(&value, "Unable to verify", "Custom executable or launcher");
        assert!(report.origin.is_none());
    }
}

#[test]
fn process_environment_keys_and_values_must_be_representable() {
    for env in [
        json!({format!("{SECRET}\0KEY"): "value"}),
        json!({"KEY": format!("{SECRET}\0value")}),
    ] {
        for command in [entry()["command"].clone(), json!("custom-launcher")] {
            let mut value = entry();
            value["command"] = command;
            value["env"] = env.clone();
            check(
                &value,
                "Invalid registration",
                "env keys and values must not contain NUL",
            );
        }
    }
    let mut value = entry();
    value["env"] = json!({"KEY WITH SPACES": "value=with=equals", "東京": ""});
    check(&value, "Configuration valid", "stdio");
}

#[test]
fn disabled_relative_and_expanded_invocations_remain_unverified() {
    for (field, replacement, reason) in [
        ("disabled", json!(true), "Registration is disabled"),
        ("enabled", json!(false), "Registration is disabled"),
        ("command", json!("proofline"), "depends on PATH"),
        (
            "command",
            json!("${BIN}/proofline"),
            "Executable uses variable expansion",
        ),
        (
            "args",
            json!(["${MCP_SUBCOMMAND}"]),
            "Arguments use variable expansion",
        ),
        (
            "env",
            json!({"PROOFLINE_ORGANIZATION_ID":"${ORG}"}),
            "Organization ID uses variable expansion",
        ),
        (
            "env",
            json!({"PROOFLINE_BASE_URL":"${ORIGIN}"}),
            "Origin uses variable expansion",
        ),
    ] {
        let mut value = entry();
        value[field] = replacement;
        check(&value, "Unable to verify", reason);
    }
}

#[test]
fn executable_files_and_read_failures_are_classified_without_execution() {
    let root = TempDir::new().unwrap();
    let mut value = entry();
    value["command"] = json!(root.path().join("proofline"));
    check(&value, "Invalid registration", "executable is missing");
    value["command"] = json!(root.path());
    check(&value, "Invalid registration", "regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let file = root.path().join("proofline");
        fs::write(&file, b"not executed").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        value["command"] = json!(file);
        check(&value, "Invalid registration", "execute permission");
    }
    let file = root.path().join("config.json");
    for bytes in [b"{}".as_slice(), br#"{"mcpServers":{}}"#.as_slice()] {
        fs::write(&file, bytes).unwrap();
        assert!(matches!(
            inspect(super::Client::ClaudeCode, &file),
            Err(Status::Missing(_))
        ));
    }
    for (bytes, label, reason) in [
        (b"[]".as_slice(), "Invalid registration", "root"),
        (b"\xff".as_slice(), "Invalid registration", "parse"),
    ] {
        fs::write(&file, bytes).unwrap();
        let error = inspect(super::Client::ClaudeCode, &file).unwrap_err();
        assert_eq!(error.message().0, label);
        assert!(error.message().1.contains(reason));
    }
    fs::remove_file(&file).unwrap();
    fs::create_dir_all(&file).unwrap();
    assert!(matches!(
        inspect(super::Client::ClaudeCode, &file),
        Err(Status::Unverified(_))
    ));
}

#[cfg(unix)]
#[test]
fn dangling_looping_special_and_unreadable_configs_remain_unverifiable() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = TempDir::new().unwrap();
    let path = root.path().join("config.json");
    for target in [
        root.path().join("missing"),
        path.clone(),
        root.path().to_owned(),
        std::path::PathBuf::from("/dev/null"),
    ] {
        symlink(&target, &path).unwrap();
        assert!(matches!(
            inspect(super::Client::ClaudeCode, &path),
            Err(Status::Unverified(_))
        ));
        assert_eq!(fs::read_link(&path).unwrap(), target);
        fs::remove_file(&path).unwrap();
    }
    fs::write(
        &path,
        serde_json::to_vec(&json!({"mcpServers":{"proofline":entry()}})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::File::open(&path).is_ok();
    let report = inspect(super::Client::ClaudeCode, &path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    if readable {
        assert!(matches!(report.unwrap().status, Status::Valid));
    } else {
        assert!(matches!(report, Err(Status::Unverified(_))));
    }
}

#[test]
fn environment_lookup_matches_windows_and_unix_semantics() {
    let mut env = json!({"proofline_base_url": "https://alternate.example"});
    assert_eq!(
        environment(env.as_object(), "PROOFLINE_BASE_URL", false).unwrap(),
        None
    );
    assert_eq!(
        environment(env.as_object(), "PROOFLINE_BASE_URL", true).unwrap(),
        Some("https://alternate.example")
    );
    env["PROOFLINE_BASE_URL"] = json!("https://different.example");
    assert!(matches!(
        environment(env.as_object(), "PROOFLINE_BASE_URL", true),
        Err(Status::Unverified(_))
    ));
    assert_eq!(
        environment(env.as_object(), "PROOFLINE_BASE_URL", false).unwrap(),
        Some("https://different.example")
    );
    env["PROOFLINE_BASE_URL"] = json!("https://alternate.example");
    assert_eq!(
        environment(env.as_object(), "PROOFLINE_BASE_URL", true).unwrap(),
        Some("https://alternate.example")
    );
    let env = json!({"Proofline_Organization_ID": "00000000-0000-0000-0000-000000000000"});
    assert!(
        organization(environment(env.as_object(), "PROOFLINE_ORGANIZATION_ID", true).unwrap())
            .is_ok()
    );
    let env = json!({"proofline_organization_id": "invalid"});
    assert!(matches!(
        organization(environment(env.as_object(), "PROOFLINE_ORGANIZATION_ID", true).unwrap()),
        Err(Status::Invalid(_))
    ));
}
