use std::process::Command;

use serde_json::Value;

fn proofline_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proofline")
}

#[test]
fn doctor_offline_json_succeeds_with_env_token_and_org_without_leaking_secret() {
    let secret = "pl_test_secret_token_do_not_leak";
    let org_id = "11111111-1111-4111-8111-111111111111";

    let output = Command::new(proofline_bin())
        .args(["--org", org_id, "doctor", "--offline", "--json"])
        .env("PROOFLINE_TOKEN", secret)
        .output()
        .expect("run proofline doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(secret) && !stderr.contains(secret),
        "secret leaked in output"
    );
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}; stderr={stderr}",
        output.status.code()
    );

    let report: Value = serde_json::from_str(&stdout).expect("valid doctor JSON");
    assert_eq!(report["ok"], Value::Bool(true));
    assert_eq!(report["offline"], Value::Bool(true));
    let checks = report["checks"].as_array().expect("checks array");
    assert!(
        checks
            .iter()
            .any(|c| c["id"] == "origin" && c["status"] == "pass")
    );
    assert!(
        checks
            .iter()
            .any(|c| c["id"] == "credentials" && c["status"] == "pass")
    );
    assert!(
        checks
            .iter()
            .any(|c| c["id"] == "server_auth" && c["status"] == "skip")
    );
}

#[test]
fn doctor_reports_invalid_origin_and_missing_ca_cert_with_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let missing_ca = dir.path().join("absent-ca.pem");

    let output = Command::new(proofline_bin())
        .args([
            "--base-url",
            "http://example.com",
            "--ca-cert",
            missing_ca.to_str().unwrap(),
            "--org",
            "11111111-1111-4111-8111-111111111111",
            "doctor",
            "--offline",
            "--json",
        ])
        .env("PROOFLINE_TOKEN", "pl_dummy_token")
        .output()
        .expect("run proofline doctor");

    assert!(
        !output.status.success(),
        "expected nonzero exit when origin and ca-cert fail"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout).expect("valid doctor JSON");
    assert_eq!(report["ok"], Value::Bool(false));
    let checks = report["checks"].as_array().expect("checks array");
    assert!(
        checks
            .iter()
            .any(|c| c["id"] == "origin" && c["status"] == "fail")
    );
    assert!(
        checks
            .iter()
            .any(|c| c["id"] == "tls_ca_cert" && c["status"] == "fail")
    );
}
