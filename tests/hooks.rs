//! Git hooks against real checkouts: what install and uninstall touch, the
//! exit policy, and the base each pushed branch is reviewed against.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::process::Command;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-000000000022";
const REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";
const TOKEN: &str = "hook-test-token";

type Uploads = Arc<Mutex<Vec<Value>>>;

/// One finding of `severity` in `lifecycle_state`, in the CODE lane's domain
/// catalog when `code_only`.
fn findings(severity: &str, code_only: bool, lifecycle_state: &str) -> Value {
    json!([{
        "id": "0190f3a0-0000-7000-8000-000000000055",
        "severity": severity,
        "risk_domain": if code_only { "logic" } else { "data_integrity" },
        "claim": "Orders are dropped on retry. The handler acknowledges first.",
        "impact": "orders are lost",
        "lifecycle_state": lifecycle_state,
        "evidence_refs": [{
            "kind": "CODE",
            "label": "handler",
            "repository_path": "orders.rs",
            "start_line": 1,
        }],
    }])
}

/// A console whose every patch review completes with one finding of `severity`.
async fn serve(uploads: Uploads, severity: &str, code_only: bool) -> String {
    serve_review(
        uploads,
        "COMPLETED",
        u8::from(!code_only),
        findings(severity, code_only, "ACTIVE"),
        code_only.then_some("COMPLETED"),
    )
    .await
}

/// A console whose every patch review has `status`, counts `assessment_count`
/// assessments, and lists one complete assessment that holds `findings`. With
/// `code_status`, a CODE record in that status holds them instead, beside the
/// assessment only when one is counted.
async fn serve_review(
    uploads: Uploads,
    status: &'static str,
    assessment_count: u8,
    findings: Value,
    code_status: Option<&'static str>,
) -> String {
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/web" }] }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/patch-reviews"),
            post(
                |State(uploads): State<Uploads>, Json(body): Json<Value>| async move {
                    uploads.lock().unwrap().push(body);
                    Json(json!({ "review_id": REVIEW, "existing": false, "patch_digest": "a".repeat(64) }))
                },
            ),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{REVIEW}"),
            get(move || {
                let findings = findings.clone();
                async move {
                    let mut document = json!({
                        "id": REVIEW,
                        "kind": "PATCH",
                        "status": status,
                        "assessment_count": assessment_count,
                        "assessments": [{
                            "id": "0190f3a0-0000-7000-8000-000000000044",
                            "environment_display_name": "production",
                            "status": "COMPLETED",
                            "findings": findings,
                            "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
                        }],
                    });
                    if let Some(code_status) = code_status {
                        document["code_assessment"] = json!({
                            "id": "0190f3a0-0000-7000-8000-000000000066",
                            "status": code_status,
                            "base_commit_sha": "0123456789abcdef0123456789abcdef01234567",
                            "head_commit_sha": "89abcdef0123456789abcdef0123456789abcdef",
                            "findings": document["assessments"][0]["findings"],
                        });
                        if assessment_count == 0 {
                            document["assessments"] = json!([]);
                        } else {
                            document["assessments"][0]["findings"] = json!([]);
                        }
                    }
                    Json(document)
                }
            }),
        )
        .with_state(uploads);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    origin
}

struct Checkout {
    temporary: tempfile::TempDir,
    base: String,
}

impl Checkout {
    async fn new() -> Self {
        let checkout = Self {
            temporary: tempfile::tempdir().unwrap(),
            base: String::new(),
        };
        tokio::fs::create_dir_all(checkout.root()).await.unwrap();
        tokio::fs::write(checkout.temporary.path().join("gitconfig"), "")
            .await
            .unwrap();
        checkout.git(&["init", "-q", "-b", "main"]).await;
        checkout.git(&["config", "user.name", "Hook test"]).await;
        checkout
            .git(&["config", "user.email", "hook@example.test"])
            .await;
        checkout
            .git(&["remote", "add", "origin", "https://github.com/acme/web.git"])
            .await;
        let base = checkout.commit("orders.rs", "fn main() {}\n").await;
        checkout
            .git(&["update-ref", "refs/remotes/origin/main", &base])
            .await;
        checkout
            .git(&[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ])
            .await;
        Self { base, ..checkout }
    }

    fn root(&self) -> PathBuf {
        self.temporary.path().join("repo")
    }

    fn hook(&self, name: &str) -> PathBuf {
        self.root().join(".git/hooks").join(name)
    }

    fn environment(&self, command: &mut Command) {
        command
            .current_dir(self.root())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.temporary.path().join("gitconfig"))
            .env_remove("PROOFLINE_HOOK");
    }

    async fn git(&self, args: &[&str]) -> String {
        let mut command = Command::new("git");
        command.args(args);
        self.environment(&mut command);
        let output = command.output().await.unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    async fn commit(&self, path: &str, text: &str) -> String {
        tokio::fs::write(self.root().join(path), text)
            .await
            .unwrap();
        self.git(&["add", path]).await;
        self.git(&["commit", "-qm", path]).await;
        self.git(&["rev-parse", "HEAD"]).await
    }

    async fn proofline(&self, origin: &str, args: &[&str], stdin: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_proofline"));
        command
            .env("PROOFLINE_TOKEN", TOKEN)
            .args(["--base-url", origin, "--org", ORG])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        self.environment(&mut command);
        let mut child = command.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut input, stdin.as_bytes())
            .await
            .unwrap();
        drop(input);
        child.wait_with_output().await.unwrap()
    }

    /// Run the official framework with the real CLI on PATH, without installing
    /// a Git hook or changing any of the developer's configuration.
    async fn pre_commit(&self, origin: &str) -> Output {
        let protected = [
            self.root().join(".pre-commit-config.yaml"),
            self.root().join(".git/config"),
            self.hook("pre-commit"),
        ];
        let mut before = Vec::new();
        for path in &protected {
            before.push(tokio::fs::read(path).await.unwrap());
        }
        let status = self.git(&["status", "--porcelain"]).await;
        let staged = self.git(&["diff", "--cached"]).await;
        let path = std::env::join_paths(std::iter::once(self.temporary.path().join("bin")).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap();
        let mut command = Command::new("pre-commit");
        command
            .args([
                "run",
                "proofline-pre-commit",
                "--hook-stage",
                "pre-commit",
                "--color",
                "never",
            ])
            .env("PATH", path)
            .env(
                "PRE_COMMIT_HOME",
                self.temporary.path().join("pre-commit-cache"),
            )
            .env("PROOFLINE_BASE_URL", origin)
            .env("PROOFLINE_ORGANIZATION_ID", ORG)
            .env("PROOFLINE_TOKEN", TOKEN)
            .env_remove("SKIP")
            .stdin(std::process::Stdio::null());
        self.environment(&mut command);
        let output = command
            .output()
            .await
            .expect("install official pre-commit >=3.2.0 on PATH to run the framework integration");
        for (path, bytes) in protected.iter().zip(before) {
            assert_eq!(
                tokio::fs::read(path).await.unwrap(),
                bytes,
                "{} changed",
                path.display()
            );
        }
        assert_eq!(self.git(&["status", "--porcelain"]).await, status);
        assert_eq!(self.git(&["diff", "--cached"]).await, staged);
        assert!(
            !tokio::fs::try_exists(self.hook("pre-commit.legacy"))
                .await
                .unwrap()
        );
        output
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[tokio::test]
async fn install_writes_only_its_own_scripts_and_uninstall_removes_only_them() {
    let checkout = Checkout::new().await;
    let unused = "http://127.0.0.1:9";
    let output = checkout.proofline(unused, &["hooks", "install"], "").await;
    assert!(output.status.success(), "{}", stderr(&output));
    let script = read(&checkout.hook("pre-commit")).unwrap();
    assert!(script.contains("exec proofline hook run pre-commit \"$@\""));
    assert!(read(&checkout.hook("pre-push")).is_some());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(checkout.hook("pre-commit"))
            .unwrap()
            .permissions()
            .mode();
        // The owner's hook must run even when umask removes group/other access.
        assert_eq!(mode & 0o100, 0o100);
    }

    // A second install changes nothing, and the checkout stays clean.
    let again = checkout.proofline(unused, &["hooks", "install"], "").await;
    assert!(stderr(&again).contains("already installed"));
    assert_eq!(read(&checkout.hook("pre-commit")).unwrap(), script);
    assert_eq!(checkout.git(&["status", "--porcelain"]).await, "");

    // Another tool's hook is never replaced or removed.
    let foreign = "#!/bin/sh\nnpx lint-staged\n";
    std::fs::write(checkout.hook("pre-push"), foreign).unwrap();
    let install = checkout
        .proofline(unused, &["hooks", "install", "--pre-push"], "")
        .await;
    assert!(stderr(&install).contains("proofline hook run pre-push \"$@\""));
    let uninstall = checkout
        .proofline(unused, &["hooks", "uninstall"], "")
        .await;
    assert!(uninstall.status.success(), "{}", stderr(&uninstall));
    assert_eq!(read(&checkout.hook("pre-commit")), None);
    assert_eq!(read(&checkout.hook("pre-push")).as_deref(), Some(foreign));

    // A hooks path, as Husky sets, gets the line to add and no file.
    checkout.git(&["config", "core.hooksPath", ".husky"]).await;
    let husky = checkout.proofline(unused, &["hooks", "install"], "").await;
    assert!(husky.status.success(), "{}", stderr(&husky));
    assert!(stderr(&husky).contains("proofline hook run pre-commit \"$@\""));
    assert!(!checkout.root().join(".husky").exists());
    assert_eq!(read(&checkout.hook("pre-commit")), None);
}

#[tokio::test]
async fn the_exit_policy_blocks_only_on_request_and_never_reads_a_gap_as_clean() {
    let checkout = Checkout::new().await;
    let uploads = Uploads::default();
    let origin = serve(uploads.clone(), "SERIOUS", false).await;
    let run = ["hook", "run", "pre-commit"];

    let nothing = checkout.proofline(&origin, &run, "").await;
    assert_eq!(nothing.status.code(), Some(0), "{}", stderr(&nothing));
    assert!(stderr(&nothing).contains("nothing to review"));
    assert!(uploads.lock().unwrap().is_empty());

    tokio::fs::write(checkout.root().join("orders.rs"), "fn main() { retry() }\n")
        .await
        .unwrap();
    checkout.git(&["add", "orders.rs"]).await;
    let unreachable = "http://127.0.0.1:9";
    let warning = serve(Uploads::default(), "WARNING", false).await;
    let unknown = serve(Uploads::default(), "CRITICAL", false).await;
    let code_origin = serve(Uploads::default(), "SERIOUS", true).await;
    let code_warning = serve(Uploads::default(), "WARNING", true).await;
    let code_resolved = serve_review(
        Uploads::default(),
        "COMPLETED",
        0,
        findings("SERIOUS", true, "RESOLVED"),
        Some("COMPLETED"),
    )
    .await;
    let code_partial = serve_review(
        Uploads::default(),
        "COMPLETED",
        0,
        findings("SERIOUS", true, "ACTIVE"),
        Some("INCOMPLETE"),
    )
    .await;
    let code_partial_beside_environment = serve_review(
        Uploads::default(),
        "COMPLETED",
        1,
        findings("SERIOUS", true, "ACTIVE"),
        Some("INCOMPLETE"),
    )
    .await;
    for (settings, server, code, expected) in [
        (
            vec![],
            origin.as_str(),
            0,
            "SERIOUS  orders.rs:1  Orders are dropped on retry.",
        ),
        (
            vec![],
            code_origin.as_str(),
            0,
            "Code-only: COMPLETED, 1 findings",
        ),
        (
            vec![("mode", "block")],
            code_origin.as_str(),
            1,
            "a finding at or above SERIOUS",
        ),
        (
            vec![("mode", "block")],
            code_warning.as_str(),
            0,
            "Code-only: COMPLETED, 1 findings",
        ),
        (
            vec![("mode", "block"), ("failOn", "WARNING")],
            code_warning.as_str(),
            1,
            "a finding at or above WARNING",
        ),
        // As in `ci review`, a resolved CODE finding prints but is not open.
        (
            vec![("mode", "block")],
            code_resolved.as_str(),
            0,
            "Code-only: COMPLETED, 1 findings",
        ),
        // Severity blocks only a complete review. A partial CODE finding
        // prints, and the commit proceeds unless `onIncomplete` is `block`.
        (
            vec![("mode", "block"), ("onIncomplete", "warn")],
            code_partial.as_str(),
            0,
            "SERIOUS  orders.rs:1  Orders are dropped on retry.",
        ),
        (
            vec![("mode", "block"), ("onIncomplete", "block")],
            code_partial.as_str(),
            1,
            "blocked this commit: no complete review.",
        ),
        // A complete environment completes the review. The partial CODE
        // finding beside it prints and still blocks nothing.
        (
            vec![("mode", "block"), ("onIncomplete", "warn")],
            code_partial_beside_environment.as_str(),
            0,
            "Code-only: INCOMPLETE (incomplete: CODE_ASSESSMENT_STATE_UNAVAILABLE)",
        ),
        (
            vec![("mode", "block")],
            origin.as_str(),
            1,
            "git commit --no-verify",
        ),
        (
            vec![("failOn", "WARNING")],
            origin.as_str(),
            0,
            "COMPLETED, 1 findings",
        ),
        (
            vec![],
            unreachable,
            0,
            "The commit proceeds without a complete review.",
        ),
        (
            vec![("onIncomplete", "block")],
            unreachable,
            1,
            "no complete review",
        ),
        // A finding below `failOn` does not block.
        (
            vec![("mode", "block")],
            warning.as_str(),
            0,
            "WARNING  orders.rs:1",
        ),
        (
            vec![("mode", "block"), ("failOn", "WARNING")],
            warning.as_str(),
            1,
            "a finding at or above WARNING",
        ),
        // A severity this CLI does not know is never below `failOn`.
        (
            vec![("mode", "block")],
            unknown.as_str(),
            1,
            "a finding at or above SERIOUS",
        ),
    ] {
        // Fails harmlessly when the section is absent.
        let mut reset = Command::new("git");
        reset.args(["config", "--remove-section", "proofline.hook.pre-commit"]);
        checkout.environment(&mut reset);
        reset.output().await.unwrap();
        for (key, value) in &settings {
            let key = format!("proofline.hook.pre-commit.{key}");
            checkout.git(&["config", &key, value]).await;
        }
        let output = checkout.proofline(server, &run, "").await;
        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(code), "{settings:?}: {text}");
        assert!(text.contains(expected), "{settings:?}: {text}");
        // No CODE record here reads as clean. Only the complete environment
        // beside the partial CODE record has no findings.
        assert!(
            !text.contains("Code-only: COMPLETED, no findings"),
            "{settings:?}: {text}"
        );
    }
    let staged = uploads.lock().unwrap()[0]["patch"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(staged.contains("+fn main() { retry() }"));
}

#[tokio::test]
async fn only_a_complete_review_prints_no_findings() {
    let checkout = Checkout::new().await;
    tokio::fs::write(checkout.root().join("orders.rs"), "fn main() { retry() }\n")
        .await
        .unwrap();
    checkout.git(&["add", "orders.rs"]).await;
    // Read the result once, so a running review is still running.
    checkout
        .git(&["config", "proofline.hook.pre-commit.timeout", "0"])
        .await;
    // Each review lists one finished environment that has no findings.
    for (status, assessment_count, complete) in [
        ("COMPLETED", 1, true),
        ("RUNNING", 2, false),
        ("COMPLETED", 2, false),
        ("FAILED", 1, false),
    ] {
        let origin = serve_review(
            Uploads::default(),
            status,
            assessment_count,
            json!([]),
            None,
        )
        .await;
        let output = checkout
            .proofline(&origin, &["hook", "run", "pre-commit"], "")
            .await;
        let text = stderr(&output);
        let case = format!("{status} with {assessment_count} assessments: {text}");
        assert_eq!(output.status.code(), Some(0), "{case}");
        assert!(text.contains("production: COMPLETED"), "{case}");
        assert_eq!(text.contains("no findings"), complete, "{case}");
        assert_eq!(
            text.contains("The commit proceeds without a complete review."),
            !complete,
            "{case}"
        );
    }
    for (status, complete) in [
        ("COMPLETED", true),
        ("INCOMPLETE", false),
        ("FUTURE_STATE", false),
    ] {
        let origin =
            serve_review(Uploads::default(), "COMPLETED", 0, json!([]), Some(status)).await;
        let output = checkout
            .proofline(&origin, &["hook", "run", "pre-commit"], "")
            .await;
        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{status}: {text}");
        assert!(text.contains("Code-only:"), "{status}: {text}");
        assert_eq!(text.contains("no findings"), complete, "{status}: {text}");
        assert_eq!(
            text.contains("The commit proceeds without a complete review."),
            !complete,
            "{status}: {text}"
        );
    }
}

#[tokio::test]
async fn each_pushed_branch_is_reviewed_against_the_commit_the_remote_has() {
    let checkout = Checkout::new().await;
    let uploads = Uploads::default();
    let origin = serve(uploads.clone(), "SERIOUS", false).await;
    let pushed = checkout
        .commit("orders.rs", "fn main() { pushed() }\n")
        .await;
    let head = checkout
        .commit("orders.rs", "fn main() { local() }\n")
        .await;
    let zero = "0".repeat(40);
    let input = format!(
        "refs/heads/feature {head} refs/heads/feature {zero}\n\
         refs/heads/main {head} refs/heads/main {pushed}\n"
    );
    let output = checkout
        .proofline(
            &origin,
            &[
                "hook",
                "run",
                "pre-push",
                "origin",
                "https://github.com/acme/web.git",
            ],
            &input,
        )
        .await;
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let uploads = uploads.lock().unwrap();
    let bases: Vec<&str> = uploads
        .iter()
        .map(|upload| upload["base_commit_sha"].as_str().unwrap())
        .collect();
    assert_eq!(bases, [checkout.base.as_str(), pushed.as_str()]);
    assert!(
        uploads[1]["patch"]
            .as_str()
            .unwrap()
            .contains("-fn main() { pushed() }")
    );
}

#[tokio::test]
#[ignore = "requires official pre-commit >=3.2.0 on PATH; run this suite with --include-ignored"]
async fn the_pre_commit_framework_preserves_selection_policy_and_existing_configuration() {
    let checkout = Checkout::new().await;
    let base = checkout
        .commit(
            ".pre-commit-config.yaml",
            include_str!("fixtures/pre-commit-config.yaml"),
        )
        .await;
    checkout
        .git(&["update-ref", "refs/remotes/origin/main", &base])
        .await;
    checkout
        .git(&["config", "fixture.preserved", "existing value"])
        .await;
    tokio::fs::write(
        checkout.hook("pre-commit"),
        "#!/bin/sh\n# Existing developer hook.\nexit 0\n",
    )
    .await
    .unwrap();
    let bin = checkout.temporary.path().join("bin");
    tokio::fs::create_dir_all(&bin).await.unwrap();
    tokio::fs::copy(
        env!("CARGO_BIN_EXE_proofline"),
        bin.join(format!("proofline{}", std::env::consts::EXE_SUFFIX)),
    )
    .await
    .unwrap();
    let uploads = Uploads::default();
    let complete = serve(uploads.clone(), "SERIOUS", false).await;
    let empty = checkout.pre_commit(&complete).await;
    let text = String::from_utf8_lossy(&empty.stdout);
    assert_eq!(empty.status.code(), Some(0), "{empty:?}");
    assert!(text.contains("nothing to review"), "{empty:?}");
    assert!(uploads.lock().unwrap().is_empty());

    tokio::fs::write(
        checkout.root().join("orders.rs"),
        "fn main() { staged() }\n",
    )
    .await
    .unwrap();
    tokio::fs::write(
        checkout.root().join("not a remote.rs"),
        "fn second() { staged_second() }\n",
    )
    .await
    .unwrap();
    checkout.git(&["add", "orders.rs", "not a remote.rs"]).await;
    tokio::fs::write(
        checkout.root().join("orders.rs"),
        "fn main() { unstaged() }\n",
    )
    .await
    .unwrap();
    let staged = checkout.pre_commit(&complete).await;
    assert_eq!(staged.status.code(), Some(0), "{staged:?}");
    {
        let uploads = uploads.lock().unwrap();
        // Appended filenames would be interpreted as a Git remote, preventing
        // this actual CLI upload. The two paths must stay in one staged review.
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0]["base_commit_sha"], base);
        assert_eq!(uploads[0]["trigger_source"], "HOOK_PRE_COMMIT");
        let patch = uploads[0]["patch"].as_str().unwrap();
        assert!(patch.contains("+fn main() { staged() }"));
        assert!(patch.contains("+fn second() { staged_second() }"));
        assert!(!patch.contains("unstaged()"));
    }

    for (setting, expected_exit) in [("warn", 0), ("block", 1)] {
        checkout
            .git(&["config", "proofline.hook.pre-commit.onIncomplete", setting])
            .await;
        let origin = serve_review(Uploads::default(), "INCOMPLETE", 1, json!([]), None).await;
        let output = checkout.pre_commit(&origin).await;
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(expected_exit), "{output:?}");
        assert!(text.contains("INCOMPLETE"), "{output:?}");
        assert!(!text.contains("no findings"), "{output:?}");
        if setting == "warn" {
            assert!(text.contains("without a complete review"), "{output:?}");
        } else {
            assert!(text.contains("git commit --no-verify"), "{output:?}");
        }
    }
    checkout
        .git(&["config", "proofline.hook.pre-commit.mode", "block"])
        .await;
    let blocked = checkout.pre_commit(&complete).await;
    assert_eq!(blocked.status.code(), Some(1), "{blocked:?}");
    assert!(String::from_utf8_lossy(&blocked.stdout).contains("a finding at or above SERIOUS"));
}
