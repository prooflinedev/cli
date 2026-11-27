use std::net::TcpListener;
use std::process::Command;

const TOKEN: &str = "pld_secretsecretsecret";

fn stderr(flag: bool, env: Option<&str>) -> String {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_proofline"));
    command
        .args(["--base-url", &format!("http://127.0.0.1:{port}"), "reviews"])
        .env("PROOFLINE_NO_UPDATE_CHECK", "1")
        .env("PROOFLINE_TOKEN", TOKEN)
        .env(
            "PROOFLINE_ORGANIZATION_ID",
            "0190f3a0-0000-7000-8000-000000000001",
        )
        .env_remove("PROOFLINE_DEBUG");
    if flag {
        command.arg("--debug");
    }
    if let Some(value) = env {
        command.env("PROOFLINE_DEBUG", value);
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn the_flag_or_a_truthy_variable_prints_each_request_without_the_token() {
    for (flag, env) in [(true, None), (false, Some("1")), (false, Some("yes"))] {
        let stderr = stderr(flag, env);
        assert!(
            stderr.contains("proofline debug: → GET /api/v1/organizations/"),
            "{flag} {env:?}: {stderr}"
        );
        assert!(
            stderr.contains("proofline debug: ← failed after"),
            "{flag} {env:?}: {stderr}"
        );
        assert!(!stderr.contains(TOKEN), "{flag} {env:?}: {stderr}");
    }
}

#[test]
fn no_flag_and_a_falsey_variable_print_nothing() {
    for env in [None, Some(""), Some("0"), Some("false"), Some("off")] {
        let stderr = stderr(false, env);
        assert!(!stderr.contains("proofline debug"), "{env:?}: {stderr}");
        assert!(
            stderr.starts_with("proofline: could not reach"),
            "{env:?}: {stderr}"
        );
    }
}
