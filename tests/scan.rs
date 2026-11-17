//! `proofline scan` against a loopback stand-in for the console: the wire
//! body, the one-attempt POST, and every way a scan request can resolve.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use uuid::Uuid;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const TOKEN: &str = "pld_secretsecretsecret";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-000000000022";
const REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";
const RESOLUTION: &str = "0190f3a0-0000-7000-8000-000000000055";
const REQUEST: &str = "0190f3a0-0000-7000-8000-000000000066";

#[derive(Clone)]
struct Fake {
    bodies: Arc<Mutex<Vec<Value>>>,
    reply: Arc<dyn Fn() -> Response + Send + Sync>,
}

async fn scan(State(fake): State<Fake>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    fake.bodies.lock().unwrap().push(body);
    (fake.reply)()
}

async fn review(Path(id): Path<Uuid>) -> Json<Value> {
    Json(json!({
        "id": id,
        "kind": "REVISION_SCAN",
        "status": "COMPLETED",
        "publication": "PUBLISHED",
        "assessment_count": 1,
        "assessments": [{
            "id": "0190f3a0-0000-7000-8000-000000000044",
            "environment_display_name": "production",
            "status": "COMPLETED",
            "incompleteness_kind": null,
            "findings": [],
            "checks": {"receipt_recorded": true, "status": "READY", "families": []},
        }],
        "head_commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "repository_full_name": "acme/web",
    }))
}

fn created(outcome: &'static str) -> Arc<dyn Fn() -> Response + Send + Sync> {
    Arc::new(move || {
        Json(json!({"resolution_id": RESOLUTION, "outcome": outcome, "review_id": REVIEW}))
            .into_response()
    })
}

fn refused(status: StatusCode, detail: &'static str) -> Arc<dyn Fn() -> Response + Send + Sync> {
    Arc::new(move || {
        (
            status,
            Json(json!({"title": "invalid request", "status": status.as_u16(), "detail": detail})),
        )
            .into_response()
    })
}

async fn serve(reply: Arc<dyn Fn() -> Response + Send + Sync>) -> (String, Fake) {
    let fake = Fake {
        bodies: Arc::default(),
        reply,
    };
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/web" }] }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/scans"),
            post(scan),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{{id}}"),
            get(review),
        )
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), fake)
}

async fn cli(origin: &str, args: &[&str]) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"));
    command
        .args([
            "--base-url",
            origin,
            "--org",
            ORG,
            "scan",
            "--repo",
            "acme/web",
        ])
        .args(args)
        .env("PROOFLINE_TOKEN", TOKEN)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/proofline-test-unavailable-bus",
        )
        .env("PROOFLINE_NO_UPDATE_CHECK", "1")
        .env("PATH", "")
        .current_dir(directory.path());
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        command.kill_on_drop(true).output(),
    )
    .await
    .unwrap()
    .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn a_ref_scan_sends_exactly_the_named_fields_and_prints_the_link() {
    let (origin, fake) = serve(created("CREATED")).await;
    let output = cli(
        &origin,
        &[
            "--ref",
            "main",
            "--budget",
            "50",
            "--request-id",
            REQUEST,
            "--no-wait",
            "--json",
        ],
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        *fake.bodies.lock().unwrap(),
        [json!({"request_id": REQUEST, "budget_credits": 50, "ref": "main"})]
    );
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed["outcome"], "CREATED");
    assert_eq!(printed["resolution_id"], RESOLUTION);
    assert_eq!(printed["review_id"], REVIEW);
    assert!(
        printed["review_url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/orgs/by-id/{ORG}/reviews/{REVIEW}"))
    );
    assert!(stderr(&output).contains(REQUEST), "{}", stderr(&output));
}

#[tokio::test]
async fn a_commit_scan_waits_for_the_scan_review() {
    let sha = "ABCDEF0123456789abcdef0123456789ABCDEF01";
    let (origin, fake) = serve(created("EXISTING")).await;
    let output = cli(
        &origin,
        &["--commit", sha, "--budget", "5", "--request-id", REQUEST],
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    let bodies = fake.bodies.lock().unwrap();
    assert_eq!(
        *bodies,
        [json!({
            "request_id": REQUEST,
            "budget_credits": 5,
            "commit_sha": sha.to_ascii_lowercase(),
        })]
    );
    assert!(stderr(&output).contains("Found the existing scan"));
}

#[tokio::test]
async fn a_server_failure_exits_4_and_names_the_fresh_request_id_that_retries_safely() {
    let (origin, fake) = serve(refused(StatusCode::INTERNAL_SERVER_ERROR, "boom")).await;
    let output = cli(&origin, &["--ref", "main", "--budget", "5"]).await;
    // Unknown outcome: exit 4, as `ci review` does when Proofline gives no answer.
    assert_eq!(output.status.code(), Some(4));
    let bodies = fake.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "a failed POST must not be repeated");
    let id = bodies[0]["request_id"].as_str().unwrap();
    id.parse::<Uuid>().unwrap();
    let message = stderr(&output);
    assert!(message.contains(&format!("--request-id {id}")), "{message}");
}

#[tokio::test]
async fn a_repository_github_cannot_resolve_starts_nothing_and_says_how_to_ask_again() {
    let reply: Arc<dyn Fn() -> Response + Send + Sync> = Arc::new(|| {
        Json(json!({"resolution_id": RESOLUTION, "outcome": "REPOSITORY_UNAVAILABLE"}))
            .into_response()
    });
    let (origin, fake) = serve(reply).await;
    let output = cli(
        &origin,
        &[
            "--ref",
            "main",
            "--budget",
            "5",
            "--request-id",
            REQUEST,
            "--json",
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    // Scripts still read the resolution from stdout.
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed["outcome"], "REPOSITORY_UNAVAILABLE");
    assert_eq!(printed["resolution_id"], RESOLUTION);
    let message = stderr(&output);
    assert!(message.contains("nothing was spent"), "{message}");
    assert!(message.contains("omit --request-id"), "{message}");
    assert_eq!(fake.bodies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_disabled_scan_limit_shows_the_servers_reason() {
    let (origin, _) = serve(refused(
        StatusCode::BAD_REQUEST,
        "On-demand scans are off; raise the limit in repository settings.",
    ))
    .await;
    let output = cli(&origin, &["--ref", "main", "--budget", "5"]).await;
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("On-demand scans are off"), "{message}");
    // A definite refusal created nothing, so no retry is suggested.
    assert!(!message.contains("--request-id"), "{message}");
}

#[tokio::test]
async fn an_unreadable_answer_leaves_the_outcome_unknown() {
    let reply: Arc<dyn Fn() -> Response + Send + Sync> =
        Arc::new(|| (StatusCode::OK, "<html>gateway</html>").into_response());
    let (origin, fake) = serve(reply).await;
    let output = cli(
        &origin,
        &["--ref", "main", "--budget", "5", "--request-id", REQUEST],
    )
    .await;
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(stderr(&output).contains(&format!("--request-id {REQUEST}")));
    assert_eq!(fake.bodies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_unknown_outcome_is_not_followed_and_cannot_drive_the_terminal() {
    let reply: Arc<dyn Fn() -> Response + Send + Sync> = Arc::new(|| {
        Json(
            json!({"resolution_id": RESOLUTION, "outcome": "QUEUED\u{1b}[2J", "review_id": REVIEW}),
        )
        .into_response()
    });
    let (origin, _) = serve(reply).await;
    let output = cli(&origin, &["--ref", "main", "--budget", "5"]).await;
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("unknown scan outcome"), "{message}");
    assert!(!message.contains('\u{1b}'), "{message:?}");
}

#[tokio::test]
async fn a_token_without_the_scan_scope_is_told_which_login_to_run() {
    let (origin, _) = serve(refused(StatusCode::FORBIDDEN, "missing scope")).await;
    let output = cli(&origin, &["--ref", "main", "--budget", "5"]).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("--scope scans:request"));
}

#[tokio::test]
async fn a_malformed_request_is_refused_before_any_http() {
    for args in [
        &["--budget", "5"][..],
        &["--ref", "main"][..],
        &["--ref", "main", "--budget", "0"][..],
        &["--ref", "main", "--budget", "-3"][..],
        &[
            "--ref",
            "main",
            "--commit",
            &"a".repeat(40),
            "--budget",
            "5",
        ][..],
        &["--commit", "main", "--budget", "5"][..],
        &["--commit", &"a".repeat(39), "--budget", "5"][..],
        &["--ref", "  ", "--budget", "5"][..],
        &[
            "--ref",
            "main",
            "--budget",
            "5",
            "--request-id",
            "not-a-uuid",
        ][..],
    ] {
        let output = cli("http://127.0.0.1:1", args).await;
        assert!(!output.status.success(), "{args:?} should be refused");
        assert!(
            !stderr(&output).contains("could not reach"),
            "{args:?} reached the network: {}",
            stderr(&output)
        );
    }
}
