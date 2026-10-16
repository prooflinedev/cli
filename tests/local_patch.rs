//! Real checkout collection and the local refusal boundary before any HTTP.

use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::sync::oneshot;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-000000000022";
const REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";
const TOKEN: &str = "local-patch-test-token";

#[derive(Clone)]
struct Fixture {
    requests: Arc<AtomicUsize>,
    uploads: Arc<Mutex<Vec<Value>>>,
    commit_requests: Arc<Mutex<Vec<Value>>>,
    file_requests: Arc<Mutex<Vec<Value>>>,
    authorized: bool,
}

async fn observe(State(fixture): State<Fixture>, request: Request, next: Next) -> Response {
    fixture.requests.fetch_add(1, Ordering::SeqCst);
    next.run(request).await
}

async fn repositories(State(fixture): State<Fixture>, headers: HeaderMap) -> Response {
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    if !fixture.authorized {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "title": "Repository access refused",
                "status": 403,
                "detail": "This token cannot read the connected repository.",
            })),
        )
            .into_response();
    }
    Json(json!({
        "repositories": [{ "id": REPOSITORY, "full_name": "acme/web" }],
    }))
    .into_response()
}

async fn upload(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert!(fixture.authorized);
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    fixture.uploads.lock().unwrap().push(body);
    Json(json!({
        "review_id": REVIEW,
        "existing": false,
        "patch_digest": "a".repeat(64),
    }))
}

async fn commit_review(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    fixture.commit_requests.lock().unwrap().push(body);
    Json(json!({ "review_id": REVIEW, "existing": false }))
}

async fn file_review(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert!(fixture.authorized);
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    fixture.file_requests.lock().unwrap().push(body);
    Json(json!({ "review_id": REVIEW, "existing": false }))
}

struct Server {
    origin: String,
    fixture: Fixture,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(authorized: bool) -> Self {
        let fixture = Fixture {
            requests: Arc::default(),
            uploads: Arc::default(),
            commit_requests: Arc::default(),
            file_requests: Arc::default(),
            authorized,
        };
        let app = Router::new()
            .route(
                &format!("/api/v1/organizations/{ORG}/repository-names"),
                get(repositories),
            )
            .route(
                &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/patch-reviews"),
                post(upload),
            )
            .route(
                &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/commit-reviews"),
                post(commit_review),
            )
            .route(
                &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/file-reviews"),
                post(file_review),
            )
            .fallback(|| async { StatusCode::NOT_FOUND })
            .with_state(fixture.clone())
            .layer(middleware::from_fn_with_state(fixture.clone(), observe));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move { stopped.await.unwrap() })
                .await
                .unwrap();
        });
        Self {
            origin,
            fixture,
            shutdown,
            task,
        }
    }

    fn assert_no_requests(&self) {
        assert_eq!(self.fixture.requests.load(Ordering::SeqCst), 0);
        assert!(self.fixture.uploads.lock().unwrap().is_empty());
    }

    async fn close(self) {
        self.shutdown.send(()).unwrap();
        self.task.await.unwrap();
    }
}

struct Checkout {
    temporary: tempfile::TempDir,
    base: String,
}

impl Checkout {
    async fn new(files: &[(&str, &str)]) -> Self {
        let mut checkout = Self {
            temporary: tempfile::tempdir().unwrap(),
            base: String::new(),
        };
        tokio::fs::create_dir_all(checkout.root()).await.unwrap();
        tokio::fs::write(checkout.config(), "").await.unwrap();
        checkout.git(&["init", "-q", "-b", "main"]).await;
        checkout
            .git(&["config", "user.name", "Local patch test"])
            .await;
        checkout
            .git(&["config", "user.email", "local-patch@example.test"])
            .await;
        for (path, text) in files {
            checkout.write(path, text).await;
        }
        checkout.git(&["add", "--all"]).await;
        checkout
            .git(&["commit", "--allow-empty", "-qm", "base"])
            .await;
        checkout.base = String::from_utf8(checkout.git(&["rev-parse", "HEAD"]).await)
            .unwrap()
            .trim()
            .to_owned();
        checkout
            .git(&["update-ref", "refs/remotes/origin/main", &checkout.base])
            .await;
        checkout
            .git(&[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ])
            .await;
        checkout
    }

    fn root(&self) -> PathBuf {
        self.temporary.path().join("repo")
    }

    fn config(&self) -> PathBuf {
        self.temporary.path().join("gitconfig")
    }

    async fn write(&self, path: &str, text: &str) {
        let file = self.root().join(path);
        tokio::fs::create_dir_all(file.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(file, text).await.unwrap();
    }

    fn git_environment(&self, command: &mut Command) {
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.config());
    }

    async fn git(&self, args: &[&str]) -> Vec<u8> {
        let mut command = Command::new("git");
        command.current_dir(self.root()).args(args);
        self.git_environment(&mut command);
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    async fn index(&self) -> Vec<u8> {
        tokio::fs::read(self.root().join(".git/index"))
            .await
            .unwrap()
    }

    async fn review(&self, server: &Server, allowed: &[&str], flags: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_proofline"));
        command
            .current_dir(self.root())
            .env("PROOFLINE_TOKEN", TOKEN)
            .args([
                "--base-url",
                &server.origin,
                "--org",
                ORG,
                "review",
                "--repo",
                "acme/web",
                "--no-wait",
            ])
            .args(flags);
        self.git_environment(&mut command);
        for path in allowed {
            command.args(["--allow-path", path]);
        }
        command.output().await.unwrap()
    }

    // Independent plain-patch producer: raw metadata must never reach HTTP.
    async fn staged_patch(&self) -> String {
        self.git(&["add", "--all"]).await;
        self.index_patch().await
    }

    async fn index_patch(&self) -> String {
        String::from_utf8(
            self.git(&[
                "-c",
                "core.quotePath=false",
                "-c",
                "diff.renames=true",
                "-c",
                "diff.suppressBlankEmpty=false",
                "diff",
                "--cached",
                "--find-renames",
                "--no-relative",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                &self.base,
                "--",
            ])
            .await,
        )
        .unwrap()
    }
}

fn assert_refusal(output: &Output, diagnostic: &str, secret: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(diagnostic), "{stderr}");
    assert!(stderr.contains("--allow-path"), "{stderr}");
    assert!(!stderr.contains(secret));
    assert!(!stderr.contains(TOKEN));
}

#[tokio::test]
async fn asynchronous_patch_acknowledgment_respects_json_without_polling() {
    let checkout = Checkout::new(&[("kept.txt", "base\n")]).await;
    checkout.write("kept.txt", "changed\n").await;
    for json_output in [false, true] {
        let server = Server::start(true).await;
        let mut flags = vec!["--timeout", "18446744073709551615"];
        if json_output {
            flags.push("--json");
        }
        let output = checkout.review(&server, &[], &flags).await;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let url = format!("{}/orgs/by-id/{ORG}/reviews/{REVIEW}", server.origin);
        if json_output {
            let acknowledgment: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                acknowledgment,
                json!({ "review_id": REVIEW, "review_url": url })
            );
        } else {
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{url}\n")
            );
        }
        assert_eq!(server.fixture.requests.load(Ordering::SeqCst), 2);
        assert_eq!(server.fixture.uploads.lock().unwrap().len(), 1);
        server.close().await;
    }
}

#[tokio::test]
async fn local_selection_uploads_only_selected_bytes_and_refuses_before_http() {
    let github = format!("ghp_{}", "S".repeat(36));
    let checkout = Checkout::new(&[("kept.txt", "base\n"), (".gitignore", "ignored/\n")]).await;
    checkout.write("kept.txt", "staged version\n").await;
    checkout.git(&["add", "kept.txt"]).await;
    let staged_patch = checkout.index_patch().await;
    checkout
        .write("kept.txt", &format!("unstaged {github}\n"))
        .await;
    checkout.write(".env.local", "SETTING=local\n").await;
    checkout.write("new file.txt", "explicit addition\n").await;
    checkout
        .write("ignored/secret.txt", &format!("{github}\n"))
        .await;
    let index = checkout.index().await;
    let server = Server::start(true).await;

    for flags in [
        vec!["--staged", "--include-untracked"],
        vec!["--staged", "--pr", "7"],
        vec!["--include-untracked", "--pr", "7"],
    ] {
        let output = checkout.review(&server, &[], &flags).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
        server.assert_no_requests();
        assert_eq!(checkout.index().await, index);
    }

    let output = checkout.review(&server, &[], &[]).await;
    assert_refusal(&output, "\"kept.txt\":1 (new line)", &github);
    server.assert_no_requests();
    let output = checkout.review(&server, &[], &["--staged"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        *server.fixture.uploads.lock().unwrap(),
        vec![json!({ "base_commit_sha": checkout.base, "patch": staged_patch })]
    );
    assert_eq!(checkout.index().await, index);

    checkout.write("kept.txt", "working-tree version\n").await;
    let output = checkout.review(&server, &[".env.local"], &[]).await;
    assert!(output.status.success(), "{output:?}");
    let uploads = server.fixture.uploads.lock().unwrap().clone();
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[1]["base_commit_sha"], checkout.base);
    let patch = uploads[1]["patch"].as_str().unwrap();
    assert!(patch.contains("+working-tree version\n"));
    for unselected in [".env.local", "new file.txt", "ignored/secret.txt", &github] {
        assert!(!patch.contains(unselected), "{patch}");
    }

    let requests = server.fixture.requests.load(Ordering::SeqCst);
    let output = checkout
        .review(&server, &[], &["--include-untracked"])
        .await;
    assert_refusal(&output, "sensitive .env path \".env.local\"", &github);
    assert_eq!(server.fixture.requests.load(Ordering::SeqCst), requests);
    assert_eq!(*server.fixture.uploads.lock().unwrap(), uploads);
    assert_eq!(checkout.index().await, index);
    let output = checkout
        .review(&server, &[".env.local"], &["--include-untracked"])
        .await;
    assert!(output.status.success(), "{output:?}");
    let uploads = server.fixture.uploads.lock().unwrap().clone();
    assert_eq!(uploads.len(), 3);
    assert_eq!(uploads[2]["base_commit_sha"], checkout.base);
    let patch = uploads[2]["patch"].as_str().unwrap();
    assert!(patch.contains("diff --git a/.env.local b/.env.local"));
    assert!(patch.contains("diff --git a/new file.txt b/new file.txt"));
    assert!(patch.contains("+explicit addition\n"));
    assert!(!patch.contains("ignored/secret.txt"));
    assert!(!patch.contains(&github));
    assert_eq!(checkout.index().await, index);
    server.close().await;

    let checkout = Checkout::new(&[]).await;
    for number in 0..3_001 {
        checkout
            .write(&format!("generated/{number}.txt"), "public text\n")
            .await;
    }
    let index = checkout.index().await;
    let server = Server::start(true).await;
    let output = checkout.review(&server, &[], &[]).await;
    assert!(output.status.success(), "{output:?}");
    let output = checkout
        .review(&server, &[], &["--include-untracked"])
        .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("3,000 files"));
    server.assert_no_requests();
    assert_eq!(checkout.index().await, index);
    server.close().await;
}

#[tokio::test]
async fn added_context_deleted_and_quoted_content_refuses_before_http() {
    let github = format!("ghp_{}", "A".repeat(36));
    let private = "-----BEGIN RSA PRIVATE KEY-----";
    let base = format!("first\n{private}\nthird\nfourth\n");
    let context = format!("first\n{private}\nthird\nchanged\n");
    let added = format!("first\n{github}\n");
    let quoted = "src/clé\t\"quoted\".txt";
    for (path, before, after, diagnostic, secret) in [
        (
            "new.txt",
            None,
            added.as_str(),
            "\"new.txt\":2 (new line)",
            github.as_str(),
        ),
        (
            "context.txt",
            Some(base.as_str()),
            context.as_str(),
            "\"context.txt\":2 (new line)",
            private,
        ),
        (
            "deleted.txt",
            Some(base.as_str()),
            "first\nthird\nfourth\n",
            "\"deleted.txt\":2 (base line)",
            private,
        ),
        (
            quoted,
            None,
            added.as_str(),
            "\"src/clé\\t\\\"quoted\\\".txt\":2 (new line)",
            github.as_str(),
        ),
    ] {
        let files: Vec<_> = before.into_iter().map(|text| (path, text)).collect();
        let checkout = Checkout::new(&files).await;
        checkout.write(path, after).await;
        let index = checkout.index().await;
        let server = Server::start(true).await;
        let flags: &[&str] = if before.is_none() {
            &["--include-untracked"]
        } else {
            &[]
        };
        let output = checkout.review(&server, &[], flags).await;
        assert_refusal(&output, diagnostic, secret);
        assert!(!output.stderr.contains(&b'\t'));
        server.assert_no_requests();
        assert_eq!(checkout.index().await, index);
        server.close().await;
    }
}

#[tokio::test]
async fn exact_overrides_keep_other_paths_blocked_and_upload_the_original_patch() {
    let github = format!("ghp_{}", "B".repeat(36));
    let checkout = Checkout::new(&[]).await;
    checkout.write(".env.local", "SETTING=value\n").await;
    checkout
        .write("nested/token.txt", &format!("first\n{github}\n"))
        .await;
    let expected = checkout.staged_patch().await;
    let index = checkout.index().await;
    let server = Server::start(true).await;
    for (allowed, diagnostic) in [
        (vec![], "sensitive .env path \".env.local\""),
        (vec![".env.local"], "\"nested/token.txt\":2 (new line)"),
        (vec!["*"], "sensitive .env path \".env.local\""),
        (
            vec![".env.local", "nested"],
            "\"nested/token.txt\":2 (new line)",
        ),
    ] {
        let output = checkout.review(&server, &allowed, &[]).await;
        assert_refusal(&output, diagnostic, &github);
        server.assert_no_requests();
        assert_eq!(checkout.index().await, index);
    }
    let output = checkout
        .review(&server, &[".env.local", "nested/token.txt"], &[])
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(REVIEW));
    assert_eq!(server.fixture.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        *server.fixture.uploads.lock().unwrap(),
        vec![json!({ "base_commit_sha": checkout.base, "patch": expected })]
    );
    assert_eq!(checkout.index().await, index);
    server.close().await;
}

#[tokio::test]
async fn a_sensitive_rename_requires_both_exact_endpoints() {
    let private = "-----BEGIN PRIVATE KEY-----";
    let checkout = Checkout::new(&[(".env.old", private)]).await;
    tokio::fs::create_dir_all(checkout.root().join("config"))
        .await
        .unwrap();
    tokio::fs::rename(
        checkout.root().join(".env.old"),
        checkout.root().join("config/.env.prod"),
    )
    .await
    .unwrap();
    let expected = checkout.staged_patch().await;
    assert!(expected.contains("rename from .env.old"));
    assert!(expected.contains("rename to config/.env.prod"));
    assert!(!expected.contains(private));
    let index = checkout.index().await;
    let server = Server::start(true).await;
    for (allowed, diagnostic) in [
        (vec![], "sensitive .env path \".env.old\""),
        (vec![".env.old"], "sensitive .env path \"config/.env.prod\""),
    ] {
        let output = checkout.review(&server, &allowed, &[]).await;
        assert_refusal(&output, diagnostic, private);
        server.assert_no_requests();
    }
    let output = checkout
        .review(&server, &[".env.old", "config/.env.prod"], &[])
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *server.fixture.uploads.lock().unwrap(),
        vec![json!({ "base_commit_sha": checkout.base, "patch": expected })]
    );
    assert_eq!(checkout.index().await, index);
    server.close().await;
}

/// Pushed commits are named once in the checkout and sent as two exact SHAs:
/// no patch leaves the machine, and a conflicting selection or a name the
/// checkout cannot resolve is refused before any request.
#[tokio::test]
async fn pushed_commits_send_two_exact_shas_and_no_patch() {
    let github = format!("ghp_{}", "C".repeat(36));
    let checkout = Checkout::new(&[("kept.txt", "base\n")]).await;
    checkout.write("kept.txt", &format!("{github}\n")).await;
    checkout.git(&["commit", "-qam", "pushed"]).await;
    let head = String::from_utf8(checkout.git(&["rev-parse", "HEAD"]).await)
        .unwrap()
        .trim()
        .to_owned();
    // An unpushed edit stays local: a commit review reads GitHub's commits.
    checkout.write("kept.txt", "unpushed working tree\n").await;
    let server = Server::start(true).await;
    for flags in [
        vec!["--commit", "HEAD", "--range", "main~1..main"],
        vec!["--commit", "HEAD", "--staged"],
        vec!["--range", "main~1..main", "--pr", "7"],
        vec!["--range", "main...main~1"],
        vec!["--commit", "no-such-branch"],
        vec!["--commit", "HEAD~1"],
    ] {
        let output = checkout.review(&server, &[], &flags).await;
        assert_eq!(output.status.code(), Some(1), "{flags:?}");
        assert!(output.stdout.is_empty(), "{flags:?}");
        server.assert_no_requests();
    }
    let output = checkout
        .review(&server, &["kept.txt"], &["--commit", "HEAD"])
        .await;
    assert_eq!(output.status.code(), Some(1));
    server.assert_no_requests();

    for flags in [vec!["--commit", "HEAD"], vec!["--range", "main~1..main"]] {
        let output = checkout.review(&server, &[], &flags).await;
        assert!(
            output.status.success(),
            "{flags:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let expected = json!({ "base_commit_sha": checkout.base, "head_commit_sha": head });
    assert_eq!(
        *server.fixture.commit_requests.lock().unwrap(),
        vec![expected.clone(), expected]
    );
    assert!(server.fixture.uploads.lock().unwrap().is_empty());
    server.close().await;
}

/// Even the root commit is a valid whole-file subject; the index and working
/// tree cannot change its selected paths or contribute source bytes.
#[tokio::test]
async fn named_files_send_one_pinned_commit_and_ignore_local_changes() {
    let checkout = Checkout::new(&[("kept.txt", "committed\n"), ("other.txt", "other\n")]).await;
    checkout
        .write("kept.txt", "unpushed text must not leave this checkout\n")
        .await;
    checkout.write("untracked.txt", "local only\n").await;
    let before = checkout.index().await;
    let server = Server::start(true).await;
    for flags in [
        vec!["--files", "kept.txt"],
        vec!["--commit", "HEAD", "--files", "untracked.txt"],
        vec!["--commit", "HEAD", "--files", "kept.txt", "--staged"],
        vec!["--range", "HEAD~1..HEAD", "--files", "kept.txt"],
        vec!["--commit", "HEAD", "--files", "../kept.txt"],
    ] {
        let output = checkout.review(&server, &[], &flags).await;
        assert!(!output.status.success(), "{flags:?}");
        server.assert_no_requests();
    }
    let output = checkout
        .review(
            &server,
            &[],
            &[
                "--commit",
                "HEAD",
                "--files",
                "other.txt",
                "kept.txt",
                "kept.txt",
            ],
        )
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *server.fixture.file_requests.lock().unwrap(),
        vec![json!({
            "commit_sha": checkout.base, "paths": ["kept.txt", "other.txt"],
        })]
    );
    assert!(server.fixture.uploads.lock().unwrap().is_empty());
    assert!(server.fixture.commit_requests.lock().unwrap().is_empty());
    assert_eq!(checkout.index().await, before);
    server.close().await;
}

#[tokio::test]
async fn a_local_override_still_requires_repository_authorization() {
    let checkout = Checkout::new(&[]).await;
    checkout.write(".env", "SETTING=value\n").await;
    let index = checkout.index().await;
    let server = Server::start(false).await;
    let output = checkout
        .review(&server, &[".env"], &["--include-untracked"])
        .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("This token cannot read the connected repository.")
    );
    assert_eq!(server.fixture.requests.load(Ordering::SeqCst), 1);
    assert!(server.fixture.uploads.lock().unwrap().is_empty());
    assert_eq!(checkout.index().await, index);
    server.close().await;
}
