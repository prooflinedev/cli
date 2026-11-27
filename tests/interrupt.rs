#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::Path as AxumPath;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::process::Command;
use uuid::Uuid;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-000000000022";
const REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";
const TOKEN: &str = "pld_secretsecretsecret";

struct MockCheckout {
    temporary: tempfile::TempDir,
}

impl MockCheckout {
    async fn new() -> Self {
        let checkout = Self {
            temporary: tempfile::tempdir().unwrap(),
        };
        tokio::fs::create_dir_all(checkout.root()).await.unwrap();
        tokio::fs::write(checkout.config(), "").await.unwrap();
        checkout.git(&["init", "-q", "-b", "main"]).await;
        checkout
            .git(&["config", "user.name", "Interrupt Test"])
            .await;
        checkout
            .git(&["config", "user.email", "interrupt@example.test"])
            .await;
        checkout
            .git(&["remote", "add", "origin", "https://github.com/acme/web.git"])
            .await;
        tokio::fs::write(checkout.root().join("hello.txt"), "one\n")
            .await
            .unwrap();
        checkout.git(&["add", "--all"]).await;
        checkout.git(&["commit", "-qm", "base"]).await;
        let base = String::from_utf8(checkout.git(&["rev-parse", "HEAD"]).await)
            .unwrap()
            .trim()
            .to_owned();
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
        tokio::fs::write(checkout.root().join("hello.txt"), "one\ntwo\n")
            .await
            .unwrap();
        checkout
    }

    fn root(&self) -> PathBuf {
        self.temporary.path().join("repo")
    }

    fn config(&self) -> PathBuf {
        self.temporary.path().join("gitconfig")
    }

    fn home(&self) -> PathBuf {
        self.temporary.path().join("home")
    }

    async fn git(&self, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(self.root())
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.config())
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }
}

async fn run_local_review_and_interrupt(existing: bool) -> (std::process::Output, usize) {
    let polled = Arc::new(AtomicBool::new(false));
    let stops = Arc::new(AtomicUsize::new(0));
    let observed_poll = Arc::clone(&polled);
    let observed_stop = Arc::clone(&stops);

    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|headers: HeaderMap| async move {
                assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                Json(json!({
                    "repositories": [{ "id": REPOSITORY, "full_name": "acme/web" }],
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/patch-reviews"),
            post(
                move |headers: HeaderMap, Json(_body): Json<Value>| async move {
                    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                    Json(json!({
                        "review_id": REVIEW,
                        "existing": existing,
                        "patch_digest": "a".repeat(64),
                        "verify": [],
                    }))
                },
            ),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{REVIEW}"),
            get(move |headers: HeaderMap| {
                let observed_poll = Arc::clone(&observed_poll);
                async move {
                    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                    observed_poll.store(true, Ordering::SeqCst);
                    Json(json!({
                        "id": REVIEW,
                        "kind": "PATCH",
                        "status": "RUNNING",
                        "assessment_count": 0,
                        "assessments": [],
                        "code_assessment": null,
                        "base_commit_sha": "b".repeat(40),
                        "head_commit_sha": "c".repeat(40),
                        "open_items": null,
                        "pull_request_number": null,
                        "repository_full_name": "acme/web",
                        "run_number": null,
                    }))
                }
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{{id}}/stop"),
            post(move |AxumPath(id): AxumPath<Uuid>, headers: HeaderMap| {
                let observed_stop = Arc::clone(&observed_stop);
                async move {
                    assert_eq!(id.to_string(), REVIEW);
                    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                    observed_stop.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::OK,
                        Json(json!({
                            "review_id": id,
                            "status": "STOPPED",
                            "stopped_by": {"github_user_id": 123, "login": "reviewer"},
                            "stopped_at": "2026-01-01T00:00:00Z",
                        })),
                    )
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let checkout = MockCheckout::new().await;
    tokio::fs::create_dir_all(checkout.home()).await.unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_proofline"))
        .current_dir(checkout.root())
        .args(["--base-url", &origin, "--org", ORG, "review", "--json"])
        .env("HOME", checkout.home())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", checkout.config())
        .env("PROOFLINE_TOKEN", TOKEN)
        .env_remove("PROOFLINE_BASE_URL")
        .env_remove("PROOFLINE_ORGANIZATION_ID")
        .env_remove("PROOFLINE_CA_CERT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let pid = child.id().expect("child should have a pid");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !polled.load(Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for first review poll"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let kill_status = std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .unwrap();
    assert!(kill_status.success());

    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("proofline did not exit promptly after SIGINT")
        .unwrap();

    server.abort();
    (output, stops.load(Ordering::SeqCst))
}

#[tokio::test]
async fn sigint_stops_newly_requested_local_review_and_exits_130() {
    let (output, stops) = run_local_review_and_interrupt(false).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(130), "stderr: {stderr}");
    assert!(
        output.stdout.is_empty(),
        "stdout must stay empty under --json on interrupt: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(stops, 1, "stderr: {stderr}");
    assert!(stderr.contains("Stopped review"), "stderr: {stderr}");
}

#[tokio::test]
async fn sigint_detaches_reused_local_review_without_stopping_and_exits_130() {
    let (output, stops) = run_local_review_and_interrupt(true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(130), "stderr: {stderr}");
    assert!(
        output.stdout.is_empty(),
        "stdout must stay empty under --json on interrupt: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(stops, 0, "stderr: {stderr}");
    assert!(stderr.contains("continues at"), "stderr: {stderr}");
    assert!(
        stderr.contains(&format!("proofline findings --review {REVIEW} --wait")),
        "stderr: {stderr}"
    );
}
