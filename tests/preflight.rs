//! Offline `proofline preflight` inspection and credential detection tests.

use std::path::Path;
use std::process::Output;

use serde_json::Value;
use tempfile::TempDir;
use tokio::process::Command;

struct TempRepo {
    dir: TempDir,
}

impl TempRepo {
    async fn new(_label: &str) -> Self {
        let dir = TempDir::new().expect("create temp dir");
        run_git(dir.path(), &["init", "-b", "main"]).await;
        run_git(dir.path(), &["config", "user.email", "dev@example.com"]).await;
        run_git(dir.path(), &["config", "user.name", "Dev"]).await;
        std::fs::write(dir.path().join("app.rs"), "fn main() {}\n").expect("write app.rs");
        run_git(dir.path(), &["add", "app.rs"]).await;
        run_git(dir.path(), &["commit", "-m", "initial"]).await;
        let head = run_git(dir.path(), &["rev-parse", "HEAD"]).await;
        run_git(
            dir.path(),
            &["update-ref", "refs/remotes/origin/main", head.trim()],
        )
        .await;
        run_git(
            dir.path(),
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ],
        )
        .await;
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.dir.path().join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(full, content).expect("write file");
    }

    async fn run_cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_proofline"))
            .current_dir(self.dir.path())
            // Unreachable origin and empty token prove preflight never needs auth or HTTP.
            .env_remove("PROOFLINE_TOKEN")
            .env("PROOFLINE_BASE_URL", "http://127.0.0.1:1")
            .env("PROOFLINE_NO_UPDATE_CHECK", "1")
            .args(args)
            .output()
            .await
            .expect("run proofline binary")
    }
}

async fn run_git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .await
        .expect("run git");
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test]
async fn preflight_passes_offline_for_clean_changes_in_text_and_json() {
    let repo = TempRepo::new("clean").await;
    repo.write("app.rs", "fn main() { println!(\"hello\"); }\n");

    let text_out = repo.run_cli(&["preflight"]).await;
    assert!(
        text_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&text_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&text_out.stdout);
    assert!(
        stdout.contains("Preflight passed: 1 changed file"),
        "{stdout}"
    );
    assert!(stdout.contains("app.rs"), "{stdout}");

    let json_out = repo.run_cli(&["preflight", "--json"]).await;
    assert!(json_out.status.success());
    let report: Value = serde_json::from_slice(&json_out.stdout).expect("valid json");
    assert_eq!(report["passed"], true);
    assert_eq!(report["files"], 1);
    assert_eq!(report["paths"], serde_json::json!(["app.rs"]));
    assert!(report["patch_bytes"].as_u64().unwrap_or(0) > 0);
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn preflight_reports_all_findings_including_azure_and_registry_tokens_without_leaking_values()
{
    let repo = TempRepo::new("secrets").await;
    let azure_key = format!("{}==;", "A".repeat(86));
    let gitlab_token = format!("glpat-{}", "b".repeat(20));
    let npm_token = format!("npm_{}", "c".repeat(36));
    let hf_token = format!("hf_{}", "d".repeat(34));
    let pypi_token = format!("pypi-AgEIcHlwaS5vcmc{}", "e".repeat(50));

    repo.write(".env", "APP_ENV=local\n");
    repo.write(
        "app.rs",
        &format!(
            "const AZ: &str = \"DefaultEndpointsProtocol=https;AccountName=demo;AccountKey={azure_key}EndpointSuffix=core.windows.net\";\n\
             const GL: &str = \"{gitlab_token}\";\n\
             const NPM: &str = \"{npm_token}\";\n\
             const HF: &str = \"{hf_token}\";\n\
             const PYPI: &str = \"{pypi_token}\";\n"
        ),
    );

    let out = repo
        .run_cli(&["preflight", "--include-untracked", "--json"])
        .await;
    assert!(
        !out.status.success(),
        "preflight must fail when secrets exist"
    );

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let stderr_str = String::from_utf8_lossy(&out.stderr);
    for secret in [
        &azure_key,
        &gitlab_token,
        &npm_token,
        &hf_token,
        &pypi_token,
    ] {
        assert!(!stdout_str.contains(secret), "secret leaked to stdout");
        assert!(!stderr_str.contains(secret), "secret leaked to stderr");
    }

    let report: Value = serde_json::from_slice(&out.stdout).expect("valid json");
    assert_eq!(report["passed"], false);
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(
        findings.len(),
        6,
        "expected .env + 5 secret findings: {report}"
    );
    let kinds: Vec<&str> = findings.iter().filter_map(|f| f["kind"].as_str()).collect();
    assert_eq!(
        kinds,
        vec![
            "an Azure Storage account key",
            "a GitLab personal access token",
            "an npm access token",
            "a Hugging Face token",
            "a PyPI API token",
        ]
    );
    assert_eq!(findings[0]["category"], "environment_path");
    assert_eq!(findings[0]["path"], ".env");
}

#[tokio::test]
async fn preflight_respects_allow_path_and_staged_selection() {
    let repo = TempRepo::new("allow-staged").await;
    let gitlab_token = format!("glpat-{}", "z".repeat(20));

    // Stage a clean change to app.rs while leaving a secret unstaged in another tracked file.
    repo.write("notes.txt", "safe\n");
    run_git(repo.path(), &["add", "notes.txt"]).await;
    run_git(repo.path(), &["commit", "-m", "add notes"]).await;
    let head = run_git(repo.path(), &["rev-parse", "HEAD"]).await;
    run_git(
        repo.path(),
        &["update-ref", "refs/remotes/origin/main", head.trim()],
    )
    .await;

    repo.write("app.rs", "fn main() { println!(\"staged\"); }\n");
    run_git(repo.path(), &["add", "app.rs"]).await;
    repo.write("notes.txt", &format!("token={gitlab_token}\n"));

    let unstaged_fail = repo.run_cli(&["preflight", "--json"]).await;
    assert!(!unstaged_fail.status.success());

    let staged_out = repo.run_cli(&["preflight", "--staged", "--json"]).await;
    assert!(staged_out.status.success());
    let staged_report: Value = serde_json::from_slice(&staged_out.stdout).expect("valid json");
    assert_eq!(staged_report["passed"], true);
    assert_eq!(staged_report["paths"], serde_json::json!(["app.rs"]));

    let allowed_out = repo
        .run_cli(&["preflight", "--allow-path", "notes.txt", "--json"])
        .await;
    assert!(allowed_out.status.success());
    let allowed_report: Value = serde_json::from_slice(&allowed_out.stdout).expect("valid json");
    assert_eq!(allowed_report["passed"], true);
}
