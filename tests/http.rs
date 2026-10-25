//! The CLI against a loopback stand-in for the console: device sign-in, the
//! refusals that keep a token on its origin, and reading a review.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use proofline_cli::api::{Api, ApiError, Http};
use proofline_cli::device::{self, DeviceError};
use proofline_cli::origin::Origin;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use uuid::Uuid;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const TOKEN: &str = "pld_secretsecretsecret";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-000000000022";
const SELECTED_REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";

#[tokio::test]
async fn coverage_upload_preserves_the_tested_commit_and_reports_refusals() {
    let directory = tempfile::tempdir().unwrap();
    let report = directory.path().join("packages/a/coverage/lcov.info");
    let content = "TN:\nSF:src/lib.rs\nDA:1,1\nDA:2,0\nend_of_record\n";
    for path in [
        "packages/a/coverage/lcov.info",
        "packages/b/coverage/lcov.info",
    ] {
        let path = directory.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    let sha = "a".repeat(40);
    let expected_sha = sha.clone();
    let app = Router::new().route(
        &format!("/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/coverage-reports"),
        post(move |headers: HeaderMap, Json(body): Json<Value>| {
            let observed = Arc::clone(&observed);
            let expected_sha = expected_sha.clone();
            async move {
                assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                assert_eq!(
                    body,
                    json!({
                        "tested_sha": expected_sha,
                        "reports": [
                            { "name": "packages/a/coverage/lcov.info", "content": content },
                            { "name": "packages/b/coverage/lcov.info", "content": content },
                        ],
                    })
                );
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                if attempt >= 2 {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(
                            json!({"title": "unprocessable coverage upload", "status": 422,
                            "detail": "GitHub has no commit at the tested SHA"}),
                        ),
                    );
                }
                (
                    if attempt == 0 {
                        StatusCode::CREATED
                    } else {
                        StatusCode::OK
                    },
                    Json(
                        json!({ "report_id": SELECTED_REVIEW, "tested_sha": expected_sha,
                        "created": attempt == 0, "formats": ["LCOV"],
                        "instrumented_lines": 2, "covered_lines": 1 }),
                    ),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let args = [
        "coverage",
        "upload",
        "--repository-id",
        REPOSITORY,
        "--commit",
        &sha,
        "--report",
        "./packages/a/coverage/lcov.info",
        "--report",
        "packages/b/coverage/lcov.info",
        "--json",
    ];
    for created in [true, false] {
        let output = cli_in(&origin, &args, directory.path()).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["created"], created);
        assert_eq!(result["tested_sha"], sha);
        assert_eq!(result["covered_lines"], 1);
        assert_eq!(result["instrumented_lines"], 2);
    }
    let output = cli_in(&origin, &args, directory.path()).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HTTP 422"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let output = cli(
        &origin,
        &[
            "coverage",
            "upload",
            "--repository-id",
            REPOSITORY,
            "--commit",
            "main",
            "--report",
            report.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("full lowercase 40-character SHA"));
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    server.abort();
}

#[tokio::test]
async fn coverage_upload_rejects_ambiguous_and_oversized_files_before_http() {
    let directory = tempfile::tempdir().unwrap();
    let report = directory.path().join("lcov.info");
    std::fs::write(&report, "SF:lib.rs\nDA:1,1\nend_of_record\n").unwrap();
    let path = report.to_str().unwrap();
    let sha = "a".repeat(40);
    // This origin has no server: validation must fail before HTTP or credentials.
    let args = [
        "coverage",
        "upload",
        "--repository-id",
        REPOSITORY,
        "--commit",
        &sha,
        "--report",
        path,
        "--report",
        path,
    ];
    let output = cli("http://127.0.0.1:1", &args).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("report names must be distinct"));
    std::fs::File::create(&report)
        .unwrap()
        .set_len((64 << 20) + 1)
        .unwrap();
    let output = cli("http://127.0.0.1:1", &args[..8]).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("larger than 64 MiB"));
}

async fn cli(origin: &str, args: &[&str]) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    cli_in(origin, args, directory.path()).await
}

async fn cli_in(origin: &str, args: &[&str], directory: &std::path::Path) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"))
            .args(["--base-url", origin, "--org", ORG])
            .args(args)
            .env("PROOFLINE_TOKEN", TOKEN)
            .env("PATH", "")
            .current_dir(directory)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn status_preserves_metadata_and_reports_failed_checks_with_exit_one() {
    for status in [
        Some(StatusCode::OK),
        Some(StatusCode::UNAUTHORIZED),
        Some(StatusCode::FORBIDDEN),
        None,
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = if let Some(status) = status {
            let app = Router::new().route(
                &format!("/api/v1/organizations/{ORG}/reviews"),
                get(move |headers: HeaderMap| {
                    let observed = Arc::clone(&observed);
                    async move {
                        assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                        observed.fetch_add(1, Ordering::SeqCst);
                        let body = if status.is_success() {
                            json!({
                                "items": [], "next_cursor": null, "truncated": false,
                                "filters": { "repositories": [] },
                            })
                        } else {
                            json!({ "title": "Access refused", "status": status.as_u16() })
                        };
                        (status, Json(body))
                    }
                }),
            );
            Some(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }))
        } else {
            drop(listener);
            None
        };
        let output = cli(&origin, &["status"]).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.contains(&format!("console: {origin}")), "{stdout}");
        assert!(stdout.contains(&format!("organization: {ORG}")), "{stdout}");
        assert!(stdout.contains("token: PROOFLINE_TOKEN"), "{stdout}");
        assert!(!stdout.contains(TOKEN));
        assert!(!stderr.contains(TOKEN));
        if status == Some(StatusCode::OK) {
            assert_eq!(output.status.code(), Some(0), "{stderr}");
            assert!(stdout.contains("server: accepted the token"), "{stdout}");
            assert!(stderr.is_empty(), "{stderr}");
        } else {
            assert_eq!(output.status.code(), Some(1), "{stderr}");
            assert!(stdout.contains("server:"), "{stdout}");
            assert!(!stdout.contains("accepted the token"), "{stdout}");
            assert!(stderr.contains("proofline:"), "{stderr}");
            if let Some(status) = status {
                assert!(
                    stderr.contains(&format!("HTTP {}", status.as_u16())),
                    "{stderr}"
                );
            }
            if status == Some(StatusCode::UNAUTHORIZED) {
                assert!(stdout.contains("run `proofline login`"), "{stdout}");
            }
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            usize::from(status.is_some())
        );
        if let Some(server) = server {
            server.abort();
        }
    }
}

#[tokio::test]
async fn findings_timeout_applies_only_to_waiting_and_never_panics() {
    for (timeout, wait, code, reads) in [
        ("18446744073709551615", false, 2, 1),
        ("18446744073709551615", true, 1, 0),
        ("307445734561825860", true, 1, 0),
        ("0", true, 2, 1),
        ("1", true, 0, 2),
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let app = Router::new().route(
            &format!("/api/v1/organizations/{ORG}/reviews/{SELECTED_REVIEW}"),
            get(move |headers: HeaderMap| {
                let observed = Arc::clone(&observed);
                async move {
                    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                    let running = observed.fetch_add(1, Ordering::SeqCst) == 0;
                    Json(json!({
                        "id": SELECTED_REVIEW,
                        "kind": "PULL_REQUEST",
                        "status": if running { "RUNNING" } else { "COMPLETED" },
                        "assessment_count": 1,
                        "assessments": [{
                            "id": "0190f3a0-0000-7000-8000-000000000044",
                            "environment_display_name": "production",
                            "status": if running { "RUNNING" } else { "COMPLETED" },
                            "findings": [],
                            "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
                        }],
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut args = vec![
            "findings",
            "--review",
            SELECTED_REVIEW,
            "--json",
            "--timeout",
            timeout,
        ];
        if wait {
            args.push("--wait");
        }
        let output = cli(&origin, &args).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(code),
            "timeout={timeout}, wait={wait}: {stderr}"
        );
        assert_eq!(requests.load(Ordering::SeqCst), reads);
        assert!(!stderr.contains("panicked"), "{stderr}");
        if code == 1 {
            assert!(output.stdout.is_empty());
            assert!(stderr.contains("too large to wait"), "{stderr}");
        } else {
            let document: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(document["review"]["id"], SELECTED_REVIEW);
            assert_eq!(
                document["outcome"],
                if code == 0 {
                    json!("COMPLETED")
                } else {
                    Value::Null
                }
            );
        }
        server.abort();
    }
}

#[tokio::test]
async fn asynchronous_pull_request_acknowledgment_respects_json_without_polling() {
    for existing in [false, true] {
        let fixture = ReviewRequestFixture::new(StatusCode::OK, existing, false);
        let origin = serve_review_request(fixture.clone()).await.to_string();
        let output = cli(
            &origin,
            &[
                "review",
                "--repo",
                "acme/web",
                "--pr",
                "42",
                "--no-wait",
                "--json",
                "--timeout",
                "18446744073709551615",
            ],
        )
        .await;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let acknowledgment: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            acknowledgment,
            json!({
                "review_id": SELECTED_REVIEW,
                "review_url": format!("{}/orgs/by-id/{ORG}/reviews/{SELECTED_REVIEW}", origin.trim_end_matches('/')),
            })
        );
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        assert!(fixture.detail_reads.lock().unwrap().is_empty());
    }
}

#[derive(Clone, Default)]
struct Fake {
    polls: Arc<AtomicUsize>,
    report_organization: bool,
    summary: Option<Value>,
}

async fn code() -> Json<Value> {
    Json(json!({
        "device_code": "d".repeat(52),
        "user_code": "WDJB-MJHT",
        "verification_uri": "http://127.0.0.1/auth/device",
        "verification_uri_complete": "http://127.0.0.1/auth/device?user_code=WDJB-MJHT",
        "expires_in": 600,
        "interval": 1,
    }))
}

async fn token(State(fake): State<Fake>, Json(body): Json<Value>) -> Response {
    assert_eq!(
        body["grant_type"],
        "urn:ietf:params:oauth:grant-type:device_code"
    );
    assert_eq!(body["device_code"], "d".repeat(52));
    if fake.polls.fetch_add(1, Ordering::SeqCst) == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "authorization_pending" })),
        )
            .into_response();
    }
    let mut issued = json!({
        "access_token": TOKEN,
        "token_type": "Bearer",
        "expires_in": 1_209_600,
        "scope": "reviews:read findings:read",
    });
    if fake.report_organization {
        issued["organization_id"] = json!(ORG);
    }
    Json(issued).into_response()
}

async fn review(State(fake): State<Fake>, headers: HeaderMap) -> Response {
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {TOKEN}"))
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "title": "Unauthorized", "status": 401 })),
        )
            .into_response();
    }
    let mut body = json!({
        "id": "0190f3a0-0000-7000-8000-0000000000aa",
        "public_key": "rev_0190f3a00000700080000000000000aa",
        "kind": "PULL_REQUEST",
        "status": "COMPLETED",
        "assessment_count": 1,
        "environment_display_names": ["production"],
        "finding_count": 0,
        "trigger_origin": "MANUAL",
        "publication": "WITHHELD",
        "created_at": "2026-01-01T00:00:00Z",
        "stoppable": false,
        "related_reviews": [],
        "base_commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "head_commit_sha": "89abcdef0123456789abcdef0123456789abcdef",
        "subjects": [{
            "id": "0190f3a0-0000-7000-8000-0000000000cc",
            "kind": "GIT_REVISION",
            "role": "PRIMARY",
            "commit_sha": "89abcdef0123456789abcdef0123456789abcdef",
            "release_authorizations": [],
        }],
        "assessments": [{
            "id": "0190f3a0-0000-7000-8000-0000000000bb",
            "environment_display_name": "production",
            "status": "INCOMPLETE",
            "incompleteness_kind": "WORLD_UNAVAILABLE",
            "reason_codes": ["WORLD_UNAVAILABLE"],
            "findings": [],
            "domains": [],
            "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
        }],
        "code_assessment": {
            "id": "0190f3a0-0000-7000-8000-0000000000dd",
            "head_commit_sha": "89abcdef0123456789abcdef0123456789abcdef",
            "base_commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "status": "COMPLETED",
            "findings": [],
            "an_added_code_field": {"retained": true},
        },
        "actions": {
            "rerun": false, "publish": false, "stop": false, "validate_findings": false, "promote_findings": false,
        },
        "pull_request_number": 42,
        "repository_full_name": "acme/web",
        "an_added_field": true,
    });
    if let Some(summary) = fake.summary {
        body["change_summary"] = summary;
    }
    Json(body).into_response()
}

async fn serve(fake: Fake) -> Origin {
    let app = Router::new()
        .route("/auth/device/code", post(code))
        .route("/auth/device/token", post(token))
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{{id}}"),
            get(review),
        )
        .route(
            "/api/v1/organizations/{org}/reviews",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "https://elsewhere.example/")],
                )
            }),
        )
        .route(
            "/api/v1/organizations/{org}/repositories/{repo}/pull-requests/{n}/review",
            post(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "title": "Review not started",
                        "status": 400,
                        "detail": "No environment links acme/web.\u{1b}[2J",
                        "repository_name": "web",
                        "refusal": { "reason": "NO_LINKED_ENVIRONMENT" },
                    })),
                )
            }),
        )
        .with_state(fake);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Origin::parse(&format!("http://{address}")).unwrap()
}

fn org() -> Uuid {
    ORG.parse().unwrap()
}

#[tokio::test]
async fn device_sign_in_waits_for_approval_and_keeps_the_organization() {
    let fake = Fake {
        report_organization: true,
        ..Fake::default()
    };
    let http = Http::new(serve(fake.clone()).await).unwrap();
    let challenge = device::start(&http, &[]).await.unwrap();
    assert_eq!(challenge.user_code.expose_secret(), "WDJB-MJHT");
    assert!(format!("{challenge:?}").contains("REDACTED"));
    assert!(!format!("{challenge:?}").contains("WDJB"));
    let credential = device::finish(&http, &challenge, None).await.unwrap();
    assert_eq!(fake.polls.load(Ordering::SeqCst), 2);
    assert_eq!(credential.organization_id, org());
    assert_eq!(credential.token.expose_secret(), TOKEN);
    assert_eq!(
        credential.scope.as_deref(),
        Some("reviews:read findings:read")
    );
    assert!(!format!("{credential:?}").contains(TOKEN));
}

#[tokio::test]
async fn a_server_that_omits_the_organization_needs_one_named() {
    let http = Http::new(serve(Fake::default()).await).unwrap();
    let challenge = device::start(&http, &["reviews:read".to_owned()])
        .await
        .unwrap();
    assert!(matches!(
        device::finish(&http, &challenge, None).await,
        Err(DeviceError::OrganizationUnknown(_))
    ));
    let challenge = device::start(&http, &[]).await.unwrap();
    let named = device::finish(&http, &challenge, Some(org()))
        .await
        .unwrap();
    assert_eq!(named.organization_id, org());
}

#[tokio::test]
async fn a_review_reads_with_unknown_fields_and_keeps_its_gap() {
    let published = json!({
        "head_sha": "89abcdef0123456789abcdef0123456789abcdef",
        "base_sha": "0123456789abcdef0123456789abcdef01234567",
        "files": [{
            "path": "src/new.rs", "previous_path": "src/old.rs", "status": "renamed",
            "additions": 3, "deletions": 1, "depth": "STANDARD",
        }],
        "route": "SHORT",
        "prose_outcome": "PUBLISHED",
        "prose": {
            "headline": "[withheld] <script>literal text</script>",
            "paragraphs": ["Moves the request handler."],
            "notable_paths": ["src/new.rs"],
        },
    });
    let mut withheld = published.clone();
    withheld["prose"] = Value::Null;
    for summary in [None, Some(Value::Null), Some(published), Some(withheld)] {
        let origin = serve(Fake {
            summary: summary.clone(),
            ..Fake::default()
        })
        .await;
        let console = origin.to_string();
        let api = Api::new(Http::new(origin).unwrap(), SecretString::from(TOKEN), org());
        let id = "0190f3a0-0000-7000-8000-0000000000aa".parse().unwrap();
        let (raw, detail) = api.review(id).await.unwrap();
        assert_eq!(raw["an_added_field"], true);
        assert_eq!(raw.get("change_summary"), summary.as_ref());
        assert_eq!(
            raw["head_commit_sha"],
            "89abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            raw["base_commit_sha"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        let state = proofline_cli::outcome::terminal(&detail);
        assert_eq!(state, Some(proofline_cli::outcome::Outcome::Incomplete));

        let output = cli(
            &console,
            &[
                "findings",
                "--review",
                "0190f3a0-0000-7000-8000-0000000000aa",
                "--json",
            ],
        )
        .await;
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schema"], "proofline.review-result.v1");
        assert_eq!(result["outcome"], "INCOMPLETE");
        assert_eq!(result["review"], raw);
        let schema_output = cli(&console, &["review", "--schema"]).await;
        assert!(schema_output.status.success(), "{schema_output:?}");
        let result_schema: Value = serde_json::from_slice(&schema_output.stdout).unwrap();
        jsonschema::validator_for(&result_schema)
            .unwrap()
            .validate(&result)
            .unwrap();

        let wrong = Api::new(
            Http::new(serve(Fake::default()).await).unwrap(),
            SecretString::from("pld_other"),
            org(),
        );
        assert_eq!(wrong.review(id).await.unwrap_err().status(), Some(401));
    }
}

#[tokio::test]
async fn redirects_are_refused_so_the_token_stays_on_its_origin() {
    let api = Api::new(
        Http::new(serve(Fake::default()).await).unwrap(),
        SecretString::from(TOKEN),
        org(),
    );
    let error = api.reviews(None, None, None).await.unwrap_err();
    assert_eq!(error.status(), Some(302));
}

#[tokio::test]
async fn a_refused_review_request_names_the_reason_without_terminal_control() {
    let api = Api::new(
        Http::new(serve(Fake::default()).await).unwrap(),
        SecretString::from(TOKEN),
        org(),
    );
    let error = api.request_review(Uuid::nil(), 7).await.unwrap_err();
    let ApiError::Problem { status, detail, .. } = &error else {
        panic!("expected a problem, got {error:?}");
    };
    assert_eq!(*status, 400);
    assert_eq!(detail, "No environment links acme/web.\u{FFFD}[2J");
}

#[tokio::test]
async fn stopping_uses_one_post_and_confirms_the_selected_stopped_review() {
    let review_id = Uuid::parse_str(SELECTED_REVIEW).unwrap();
    let acknowledgment = json!({
        "review_id": SELECTED_REVIEW,
        "status": "STOPPED",
        "stopped_by": {"github_user_id": 123, "login": "reviewer"},
        "stopped_at": "2026-01-01T00:00:00Z",
        "a_compatible_addition": true,
    });
    let mut wrong_review = acknowledgment.clone();
    wrong_review["review_id"] = json!(Uuid::nil());
    let mut running = acknowledgment.clone();
    running["status"] = json!("RUNNING");
    for (status, body, json_output, success) in [
        (StatusCode::OK, acknowledgment.clone(), false, true),
        (StatusCode::OK, acknowledgment.clone(), true, true),
        (StatusCode::OK, wrong_review, true, false),
        (StatusCode::OK, running, true, false),
        (
            StatusCode::FORBIDDEN,
            json!({"detail": "live read access is required\u{1b}[2J"}),
            true,
            false,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"detail": "GitHub could not confirm read access"}),
            false,
            false,
        ),
        (StatusCode::FOUND, json!({}), false, false),
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let response_body = body;
        let app = Router::new().route(
            &format!("/api/v1/organizations/{ORG}/reviews/{{id}}/stop"),
            post(
                move |Path(id): Path<Uuid>, headers: HeaderMap, body: Bytes| {
                    let observed = Arc::clone(&observed);
                    let response_body = response_body.clone();
                    async move {
                        assert_eq!(id, review_id);
                        assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                        assert!(body.is_empty());
                        observed.fetch_add(1, Ordering::SeqCst);
                        (status, Json(response_body))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut args = vec!["stop", SELECTED_REVIEW];
        if json_output {
            args.push("--json");
        }
        let output = cli(&origin, &args).await;
        assert_eq!(output.status.success(), success, "{status}: {output:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{status}: {output:?}");
        assert!(
            !output
                .stdout
                .windows(TOKEN.len())
                .any(|bytes| bytes == TOKEN.as_bytes())
        );
        assert!(
            !output
                .stderr
                .windows(TOKEN.len())
                .any(|bytes| bytes == TOKEN.as_bytes())
        );
        assert!(!output.stderr.contains(&0x1b));
        if success && json_output {
            let returned: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(returned, acknowledgment);
        } else if success {
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(SELECTED_REVIEW));
        } else {
            assert!(
                output.stdout.is_empty(),
                "a refused stop cannot acknowledge success"
            );
        }
        server.abort();
    }
}

#[tokio::test]
async fn an_incomplete_review_is_not_success_in_either_output() {
    let origin = serve(Fake::default()).await.to_string();
    for json in [false, true] {
        let mut args = vec![
            "proofline",
            "--base-url",
            &origin,
            "--org",
            ORG,
            "findings",
            "--review",
            "0190f3a0-0000-7000-8000-0000000000aa",
        ];
        if json {
            args.push("--json");
        }
        let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from(args).unwrap();
        let verdict = proofline_cli::run(cli, Some(SecretString::from(TOKEN)))
            .await
            .unwrap();
        assert_eq!(verdict, proofline_cli::Verdict::NotComplete, "json: {json}");
    }
}

type ReviewRequests = Vec<(HeaderMap, Vec<u8>)>;

#[derive(Clone)]
struct ReviewRequestFixture {
    requests: Arc<Mutex<ReviewRequests>>,
    detail_reads: Arc<Mutex<Vec<Uuid>>>,
    status: StatusCode,
    existing: bool,
    incomplete: bool,
}

impl ReviewRequestFixture {
    fn new(status: StatusCode, existing: bool, incomplete: bool) -> Self {
        Self {
            requests: Arc::default(),
            detail_reads: Arc::default(),
            status,
            existing,
            incomplete,
        }
    }
}

async fn request_repository(headers: HeaderMap) -> Json<Value> {
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    Json(json!({
        "items": [],
        "next_cursor": null,
        "truncated": false,
        "filters": {"repositories": [{"id": REPOSITORY, "name": "acme/web"}]},
    }))
}

async fn requested_review(
    State(fixture): State<ReviewRequestFixture>,
    Path((repository, number)): Path<(Uuid, u64)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    assert_eq!(repository, REPOSITORY.parse::<Uuid>().unwrap());
    assert_eq!(number, 42);
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    fixture
        .requests
        .lock()
        .unwrap()
        .push((headers, body.to_vec()));
    if !fixture.status.is_success() {
        let detail = if fixture.status == StatusCode::BAD_REQUEST {
            "This requester has no assigned seat."
        } else {
            "Current write authority is unavailable.\u{1b}[2J"
        };
        return (
            fixture.status,
            [(header::RETRY_AFTER, "0")],
            Json(json!({
                "title": "Review not started",
                "status": fixture.status.as_u16(),
                "detail": detail,
            })),
        )
            .into_response();
    }
    Json(json!({
        "review_id": SELECTED_REVIEW,
        "run_number": 7,
        "existing": fixture.existing,
        "automatic_reviews_paused": false,
    }))
    .into_response()
}

async fn selected_review(
    State(fixture): State<ReviewRequestFixture>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Json<Value> {
    assert_eq!(id, SELECTED_REVIEW.parse::<Uuid>().unwrap());
    assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.detail_reads.lock().unwrap().push(id);
    Json(json!({
        "id": id,
        "kind": "PULL_REQUEST",
        "status": "COMPLETED",
        "publication": if fixture.existing {"PUBLISHED"} else {"WITHHELD"},
        "assessment_count": 1,
        "assessments": [{
            "id": "0190f3a0-0000-7000-8000-000000000044",
            "environment_display_name": "production",
            "status": if fixture.incomplete {"INCOMPLETE"} else {"COMPLETED"},
            "incompleteness_kind": fixture.incomplete.then_some("WORLD_UNAVAILABLE"),
            "findings": [],
            "checks": {"receipt_recorded": true, "status": "READY", "families": []},
        }],
        "head_commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "pull_request_number": 42,
        "repository_full_name": "acme/web",
        "run_number": 7,
    }))
}

async fn serve_review_request(fixture: ReviewRequestFixture) -> Origin {
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(request_repository),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/web" }] }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{{id}}"),
            get(selected_review),
        )
        .route(
            &format!(
                "/api/v1/organizations/{ORG}/repositories/{{repository}}/pull-requests/{{number}}/review"
            ),
            post(requested_review),
        )
        .with_state(fixture);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Origin::parse(&format!("http://{address}")).unwrap()
}

#[tokio::test]
async fn full_review_preserves_default_wire_and_follows_the_server_selected_run() {
    for (full, existing, incomplete, no_wait) in [
        (false, true, false, false),
        (true, false, false, false),
        (true, true, false, false),
        (true, true, true, false),
        (true, true, true, true),
    ] {
        for json in [false, true] {
            let fixture = ReviewRequestFixture::new(StatusCode::OK, existing, incomplete);
            let origin = serve_review_request(fixture.clone()).await.to_string();
            let mut args = vec![
                "proofline",
                "--base-url",
                &origin,
                "--org",
                ORG,
                "review",
                "--repo",
                "acme/web",
                "--pr",
                "42",
            ];
            if full {
                args.push("--full");
            }
            if json {
                args.push("--json");
            }
            if no_wait {
                args.push("--no-wait");
            }
            let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from(args).unwrap();
            let verdict = proofline_cli::run(cli, Some(SecretString::from(TOKEN)))
                .await
                .unwrap();
            assert_eq!(
                verdict,
                if incomplete && !no_wait {
                    proofline_cli::Verdict::NotComplete
                } else {
                    proofline_cli::Verdict::Done
                },
                "full={full}, existing={existing}, incomplete={incomplete}, json={json}, no_wait={no_wait}"
            );
            let requests = fixture.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            let (headers, body) = &requests[0];
            if full {
                assert_eq!(headers[header::CONTENT_TYPE], "application/json");
                assert_eq!(
                    serde_json::from_slice::<Value>(body).unwrap(),
                    json!({"mode": "FULL"})
                );
            } else {
                assert!(body.is_empty());
                assert!(!headers.contains_key(header::CONTENT_TYPE));
            }
            assert_eq!(
                *fixture.detail_reads.lock().unwrap(),
                if no_wait {
                    Vec::new()
                } else {
                    vec![SELECTED_REVIEW.parse::<Uuid>().unwrap()]
                }
            );
        }
    }
}

#[tokio::test]
async fn full_review_refusals_do_not_retry_or_fall_back_to_default() {
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let fixture = ReviewRequestFixture::new(status, false, false);
        let origin = serve_review_request(fixture.clone()).await.to_string();
        let args = [
            "proofline",
            "--base-url",
            &origin,
            "--org",
            ORG,
            "review",
            "--repo",
            "acme/web",
            "--pr",
            "42",
            "--full",
        ];
        let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from(args).unwrap();
        let error = proofline_cli::run(cli, Some(SecretString::from(TOKEN)))
            .await
            .unwrap_err();
        let display = format!("{error:#}");
        assert!(display.contains(&format!("HTTP {}", status.as_u16())));
        if status == StatusCode::BAD_REQUEST {
            assert!(display.contains("This requester has no assigned seat."));
        } else {
            assert!(display.contains("Current write authority is unavailable.\u{FFFD}[2J"));
        }
        assert!(!display.contains('\u{1b}'));
        assert!(!display.contains(TOKEN));
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "status={status}");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].1).unwrap(),
            json!({"mode": "FULL"})
        );
        assert!(fixture.detail_reads.lock().unwrap().is_empty());
    }

    let fixture = ReviewRequestFixture::new(StatusCode::OK, false, false);
    let origin = serve_review_request(fixture.clone()).await.to_string();
    let args = [
        "proofline",
        "--base-url",
        &origin,
        "--org",
        "0190f3a0-0000-7000-8000-000000000099",
        "review",
        "--repo",
        "acme/web",
        "--pr",
        "42",
        "--full",
    ];
    let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from(args).unwrap();
    let error = proofline_cli::run(cli, Some(SecretString::from(TOKEN)))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("HTTP 404"));
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(fixture.detail_reads.lock().unwrap().is_empty());
}

const FIRST_REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000cc";

/// A console where `acme/new` is connected but has never been reviewed: the
/// review collection names no repository, and only `/repository-names` does.
async fn unreviewed(requested: Arc<AtomicUsize>) -> Origin {
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(|| async {
                Json(json!({
                    "items": [],
                    "next_cursor": null,
                    "truncated": false,
                    "filters": { "repositories": [], "environments": [], "authors": [] },
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [
                    { "id": "0190f3a0-0000-7000-8000-0000000000ce", "full_name": "acme/legacy" },
                    { "id": FIRST_REPOSITORY, "full_name": "acme/new" },
                    { "id": "0190f3a0-0000-7000-8000-0000000000cf", "full_name": "acme/twin" },
                    { "id": "0190f3a0-0000-7000-8000-0000000000d0", "full_name": "Acme/Twin" },
                ] }))
            }),
        )
        .route(
            &format!(
                "/api/v1/organizations/{ORG}/repositories/{FIRST_REPOSITORY}/pull-requests/7/review"
            ),
            post(move || async move {
                requested.fetch_add(1, Ordering::SeqCst);
                Json(json!({
                    "review_id": "0190f3a0-0000-7000-8000-0000000000dd",
                    "run_number": 1,
                    "existing": false,
                    "automatic_reviews_paused": false,
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Origin::parse(&format!("http://{address}")).unwrap()
}

#[tokio::test]
async fn the_first_review_of_an_unreviewed_repository_is_requested_by_name() {
    let requested = Arc::new(AtomicUsize::new(0));
    let origin = unreviewed(Arc::clone(&requested)).await.to_string();
    let review = |repository: &'static str| {
        let origin = origin.clone();
        async move {
            let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from([
                "proofline",
                "--base-url",
                &origin,
                "--org",
                ORG,
                "review",
                "--pr",
                "7",
                "--no-wait",
                "--repo",
                repository,
            ])
            .unwrap();
            proofline_cli::run(cli, Some(SecretString::from(TOKEN))).await
        }
    };
    assert_eq!(
        review("Acme/New").await.unwrap(),
        proofline_cli::Verdict::Done
    );
    assert_eq!(requested.load(Ordering::SeqCst), 1);

    let refused = review("acme/other").await.unwrap_err().to_string();
    assert!(
        refused.starts_with("acme/other is not a repository in organization"),
        "{refused}"
    );
    assert_eq!(requested.load(Ordering::SeqCst), 1);

    let ambiguous = review("acme/twin").await.unwrap_err().to_string();
    assert!(
        ambiguous.ends_with("lists more than one repository named acme/twin, so the CLI cannot tell which one to use"),
        "{ambiguous}"
    );
    assert_eq!(requested.load(Ordering::SeqCst), 1);
}

const DEPARTED_REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000ee";
const DEPARTED_HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

/// A console where `acme/old` has left the installation but keeps an
/// authorized review: `/repository-names` omits it, the review collection
/// still names it.
async fn departed() -> Origin {
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(|| async {
                Json(json!({
                    "items": [{
                        "id": "0190f3a0-0000-7000-8000-0000000000aa",
                        "kind": "PULL_REQUEST",
                        "status": "COMPLETED",
                        "created_at": "2026-10-01T00:00:00Z",
                        "head_commit_sha": DEPARTED_HEAD,
                        "pull_request_number": 9,
                        "repository_id": DEPARTED_REPOSITORY,
                        "run_number": 1,
                    }],
                    "next_cursor": null,
                    "truncated": false,
                    "filters": {
                        "repositories": [{ "id": DEPARTED_REPOSITORY, "name": "acme/old" }],
                        "environments": [],
                        "authors": [],
                    },
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async { Json(json!({ "repositories": [] })) }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{{id}}"),
            get(review),
        )
        .with_state(Fake::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Origin::parse(&format!("http://{address}")).unwrap()
}

#[tokio::test]
async fn findings_of_a_departed_repository_still_resolve_through_its_reviews() {
    let origin = departed().await.to_string();
    let run = |selector: [&'static str; 2], command: &'static str| {
        let origin = origin.clone();
        async move {
            let mut args = vec!["proofline", "--base-url", &origin, "--org", ORG, command];
            args.extend(selector);
            if command == "review" {
                args.push("--no-wait");
            }
            args.extend(["--repo", "Acme/Old"]);
            let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from(args).unwrap();
            proofline_cli::run(cli, Some(SecretString::from(TOKEN))).await
        }
    };
    // The fixture review is complete with an incomplete assessment, so a
    // command that found it reads NotComplete rather than failing.
    for selector in [["--pr", "9"], ["--head", DEPARTED_HEAD]] {
        assert_eq!(
            run(selector, "findings").await.unwrap(),
            proofline_cli::Verdict::NotComplete,
            "{selector:?}"
        );
    }
    let cli = <proofline_cli::Cli as clap::Parser>::try_parse_from([
        "proofline",
        "--base-url",
        &origin,
        "--org",
        ORG,
        "findings",
        "--review",
        "0190f3a0-0000-7000-8000-0000000000aa",
    ])
    .unwrap();
    assert_eq!(
        proofline_cli::run(cli, Some(SecretString::from(TOKEN)))
            .await
            .unwrap(),
        proofline_cli::Verdict::NotComplete
    );
    // A new review needs a connected repository, which acme/old no longer is.
    let refused = run(["--pr", "9"], "review").await.unwrap_err().to_string();
    assert!(
        refused.starts_with("Acme/Old is not a repository in organization"),
        "{refused}"
    );
}

const CI_REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000f0";
const CI_REVIEW: &str = "0190f3a0-0000-7000-8000-0000000000f1";
const CI_HEAD: &str = "89abcdef0123456789abcdef0123456789abcdef";

#[derive(Debug, Clone, Copy)]
struct CiCodeFinding {
    only: bool,
    severity: Option<&'static str>,
    lifecycle_state: &'static str,
    risk_domain: &'static str,
    /// The head the CODE record names, `CI_HEAD` unless it is of another subject.
    head: &'static str,
    /// The CODE record's status, the assessment's unless set.
    status: Option<&'static str>,
}

/// A console that lists `kind` at `CI_HEAD` in `acme/app` and serves its detail
/// with `status` and an assessment in `assessment`. With `open`, the
/// ENV assessment lists one SERIOUS finding and the review counts `open` as
/// its open and serious ENV findings. CODE findings are separate from those
/// counts. Every request path is recorded, so a test can tell that nothing
/// was requested.
async fn ci_console(
    kind: &'static str,
    status: StatusCode,
    assessment: &'static str,
    open: Option<[u64; 2]>,
    code: Option<CiCodeFinding>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let findings = match open {
        None => json!([]),
        Some(_) => json!([{
            "id": "0190f3a0-0000-7000-8000-0000000000f3",
            "severity": "SERIOUS",
            "risk_domain": "data_integrity",
            "claim": "Orders are dropped on retry.",
            "impact": "orders are lost",
            "lifecycle_state": "NEW",
            "evidence_refs": [],
        }]),
    };
    let open_items = open.map(|[open_findings, serious_findings]| {
        json!({
            "open_findings": open_findings,
            "serious_findings": serious_findings,
            "accepted_risks": 0,
            "not_assessed": [],
        })
    });
    let app = Router::new()
        // The GitHub Actions runner's OIDC token endpoint and the exchange.
        .route(
            "/github/token",
            get(
                |headers: HeaderMap,
                 axum::extract::RawQuery(query): axum::extract::RawQuery| async move {
                    assert_eq!(headers[header::AUTHORIZATION], "Bearer runner-secret");
                    let host = headers[header::HOST].to_str().unwrap();
                    let audience = format!("http://{host}/ci");
                    assert!(
                        url::form_urlencoded::parse(query.unwrap().as_bytes())
                            .any(|(name, value)| name == "audience" && value == audience)
                    );
                    Json(json!({ "value": "signed-job-identity" }))
                },
            ),
        )
        .route(
            "/api/v1/ci/github-actions/credentials",
            post(
                |headers: HeaderMap, axum::extract::RawQuery(query): axum::extract::RawQuery| async move {
                assert_eq!(headers[header::AUTHORIZATION], "Bearer signed-job-identity");
                // A pull-request job names the head for the exchange to verify.
                assert_eq!(query, Some(format!("pull_request_head={CI_HEAD}")));
                Json(json!({
                    "organization_id": ORG,
                    "repository_id": CI_REPOSITORY,
                    "token": TOKEN,
                    "expires_at": "2026-10-01T01:00:00Z",
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [{ "id": CI_REPOSITORY, "full_name": "acme/app" }] }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(move || async move {
                Json(json!({
                    "items": [{
                        "id": CI_REVIEW,
                        "kind": kind,
                        "status": "COMPLETED",
                        "created_at": "2026-10-01T00:00:00Z",
                        "head_commit_sha": CI_HEAD,
                        "pull_request_number": 12,
                        "repository_id": CI_REPOSITORY,
                        "run_number": 1,
                    }],
                    "next_cursor": null,
                    "truncated": false,
                    "filters": { "repositories": [], "environments": [], "authors": [] },
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{CI_REVIEW}"),
            get(move || {
                let (findings, open_items) = (findings.clone(), open_items.clone());
                async move {
                    if !status.is_success() {
                        return (
                            status,
                            Json(json!({ "title": "Unavailable", "status": status.as_u16() })),
                        )
                            .into_response();
                    }
                    let mut document = json!({
                        "id": CI_REVIEW,
                        "kind": "PULL_REQUEST",
                        "status": "COMPLETED",
                        "head_commit_sha": CI_HEAD,
                        "pull_request_number": 12,
                        "run_number": 1,
                        "assessment_count": 1,
                        "open_items": open_items,
                        "assessments": [{
                            "id": "0190f3a0-0000-7000-8000-0000000000f2",
                            "environment_display_name": "production",
                            "status": assessment,
                            "findings": findings,
                            "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
                        }],
                    });
                    if let Some(code) = code {
                        let findings = code.severity.map_or_else(
                            || json!([]),
                            |severity| json!([{
                                "id": "0190f3a0-0000-7000-8000-0000000000f5",
                                "severity": severity,
                                "risk_domain": code.risk_domain,
                                "claim": "Orders are dropped on retry.",
                                "impact": "orders are lost",
                                "lifecycle_state": code.lifecycle_state,
                                "evidence_refs": [],
                            }]),
                        );
                        document["code_assessment"] = json!({
                            "id": "0190f3a0-0000-7000-8000-0000000000f4",
                            "status": code.status.unwrap_or(assessment),
                            "base_commit_sha": "0123456789abcdef0123456789abcdef01234567",
                            "head_commit_sha": code.head,
                            "findings": findings,
                        });
                        if code.only {
                            document["assessment_count"] = json!(0);
                            document["assessments"] = json!([]);
                        }
                    }
                    Json(document).into_response()
                }
            }),
        );
    let observed = Arc::clone(&requests);
    let app = app.layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let observed = Arc::clone(&observed);
            async move {
                observed.lock().unwrap().push(format!(
                    "{} {}",
                    request.method(),
                    request.uri().path()
                ));
                next.run(request).await
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (origin, requests)
}

struct CiCase {
    listed: &'static str,
    status: StatusCode,
    assessment: &'static str,
    commit: Option<&'static str>,
    code: i32,
    /// `executionSuccessful` of the written SARIF, or `None` when none is written.
    sarif: Option<bool>,
    open: Option<[u64; 2]>,
    code_finding: Option<CiCodeFinding>,
}

#[tokio::test]
async fn ci_review_attaches_to_the_head_review_and_keeps_unknown_apart_in_its_exit_code() {
    let case = |listed, status, assessment, commit, code, sarif| CiCase {
        listed,
        status,
        assessment,
        commit,
        code,
        sarif,
        open: None,
        code_finding: None,
    };
    let mut cases = vec![
        case(
            "PULL_REQUEST",
            StatusCode::OK,
            "COMPLETED",
            None,
            0,
            Some(true),
        ),
        case(
            "PULL_REQUEST",
            StatusCode::OK,
            "INCOMPLETE",
            Some(CI_HEAD),
            2,
            Some(false),
        ),
        // A deployment review of the same commit is not the pull request's.
        case(
            "DEPLOYMENT",
            StatusCode::OK,
            "COMPLETED",
            Some(CI_HEAD),
            4,
            None,
        ),
        case(
            "PULL_REQUEST",
            StatusCode::INTERNAL_SERVER_ERROR,
            "COMPLETED",
            Some(CI_HEAD),
            4,
            None,
        ),
        case(
            "PULL_REQUEST",
            StatusCode::OK,
            "COMPLETED",
            Some("main"),
            1,
            None,
        ),
    ];
    let mut withheld = case(
        "PULL_REQUEST",
        StatusCode::OK,
        "COMPLETED",
        None,
        0,
        Some(false),
    );
    withheld.open = Some([1, 1]);
    withheld.code_finding = Some(CiCodeFinding {
        only: false,
        severity: Some("SERIOUS"),
        lifecycle_state: "NEW",
        risk_domain: "[withheld: environment value]",
        head: CI_HEAD,
        status: None,
    });
    cases.push(withheld);
    for CiCase {
        listed: kind,
        status,
        assessment,
        commit,
        code,
        sarif,
        open,
        code_finding,
    } in cases
    {
        let (origin, requests) = ci_console(kind, status, assessment, open, code_finding).await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("proofline.sarif");
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"));
        command
            .args(["--base-url", &origin, "--org", ORG, "ci", "review"])
            .args(["--repo", "acme/app", "--timeout", "0", "--json", "--sarif"])
            .arg(&path)
            .env("PROOFLINE_TOKEN", TOKEN)
            .env("COMMIT_SHA", CI_HEAD)
            .env_remove("GITHUB_SHA")
            .env("PATH", "")
            .current_dir(directory.path())
            .kill_on_drop(true);
        if let Some(commit) = commit {
            command.args(["--commit", commit]);
        }
        let output = tokio::time::timeout(std::time::Duration::from_secs(15), command.output())
            .await
            .unwrap()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{kind} {status} {assessment}: {stderr}"
        );
        assert!(!stderr.contains(TOKEN));
        let requests = requests.lock().unwrap();
        assert!(
            requests.iter().all(|request| request.starts_with("GET ")),
            "{requests:?}"
        );
        if code == 1 {
            assert!(requests.is_empty(), "{requests:?}");
        }
        match sarif {
            Some(success) => {
                let document: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                assert_eq!(
                    document["runs"][0]["invocations"][0]["executionSuccessful"],
                    success
                );
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["review"]["id"], CI_REVIEW);
                if code_finding.is_some() {
                    let run = &document["runs"][0];
                    let findings = run["results"].as_array().unwrap();
                    assert_eq!(findings.len(), 1);
                    assert_eq!(
                        findings[0]["properties"]["findingId"],
                        "0190f3a0-0000-7000-8000-0000000000f3"
                    );
                    assert!(
                        run["invocations"][0]["toolExecutionNotifications"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|notification| notification["properties"]["reasonCode"]
                                == "CODE_ASSESSMENT_UNAVAILABLE")
                    );
                    assert_eq!(
                        result["review"]["code_assessment"]["findings"][0]["risk_domain"],
                        "[withheld: environment value]"
                    );
                }
            }
            None => assert!(!path.exists()),
        }
    }
}

#[tokio::test]
async fn ci_review_on_a_pull_request_event_reviews_the_head_not_the_merge_commit() {
    let (origin, _) = ci_console("PULL_REQUEST", StatusCode::OK, "COMPLETED", None, None).await;
    // GitHub's merge commit, which no review has as its head.
    let merge = "0123456789abcdef0123456789abcdef01234567";
    let cases = [
        (json!({ "pull_request": { "head": { "sha": CI_HEAD } } }), 0),
        // Without the head the job names it; the merge commit is never used.
        (json!({ "pull_request": { "number": 7 } }), 1),
    ];
    for (payload, code) in cases {
        let directory = tempfile::tempdir().unwrap();
        let event = directory.path().join("event.json");
        std::fs::write(&event, payload.to_string()).unwrap();
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"))
                .args(["--base-url", &origin, "--org", ORG, "ci", "review"])
                .args(["--repo", "acme/app", "--timeout", "0"])
                .env("PROOFLINE_TOKEN", TOKEN)
                .env_remove("COMMIT_SHA")
                .env("GITHUB_SHA", merge)
                .env("GITHUB_EVENT_NAME", "pull_request")
                .env("GITHUB_EVENT_PATH", &event)
                .env("PATH", "")
                .current_dir(directory.path())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(code), "{payload}: {stderr}");
    }
}

/// A runner that issues the job's token, and a console whose credential
/// exchange answers `status`.
async fn failing_exchange(status: StatusCode) -> String {
    let app = Router::new()
        .route(
            "/github/token",
            get(|| async { Json(json!({ "value": "signed-job-identity" })) }),
        )
        .route(
            "/api/v1/ci/github-actions/credentials",
            post(move || async move {
                (
                    status,
                    Json(json!({ "title": "Exchange", "status": status.as_u16() })),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    origin
}

#[tokio::test]
async fn ci_review_in_github_actions_exchanges_the_jobs_oidc_token_for_its_credential() {
    let (console, requests) =
        ci_console("PULL_REQUEST", StatusCode::OK, "COMPLETED", None, None).await;
    // A refused exchange is the caller's error. One Proofline could not serve
    // is an outage, like any other request it fails.
    let cases = [
        (console, 0),
        (failing_exchange(StatusCode::NOT_FOUND).await, 1),
        (failing_exchange(StatusCode::SERVICE_UNAVAILABLE).await, 4),
    ];
    for (origin, code) in cases {
        let directory = tempfile::tempdir().unwrap();
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"))
                .args(["--base-url", &origin, "ci", "review", "--repo", "acme/app"])
                .args(["--timeout", "0", "--commit", CI_HEAD])
                .env_remove("PROOFLINE_TOKEN")
                .env_remove("PROOFLINE_ORGANIZATION_ID")
                .env(
                    "ACTIONS_ID_TOKEN_REQUEST_URL",
                    format!("{origin}/github/token?api-version=2.0"),
                )
                .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-secret")
                .env("GITHUB_EVENT_NAME", "pull_request")
                .env("PATH", "")
                .current_dir(directory.path())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(code), "{stderr}");
        for secret in ["runner-secret", "signed-job-identity", TOKEN] {
            assert!(!stderr.contains(secret));
            assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        }
    }
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.get(..2).unwrap(),
        [
            "GET /github/token",
            "POST /api/v1/ci/github-actions/credentials"
        ],
        "{requests:?}"
    );
}

#[tokio::test]
async fn ci_review_fail_on_exits_three_for_an_open_finding_of_a_complete_review() {
    let code = |only, severity, lifecycle_state| {
        Some(CiCodeFinding {
            only,
            severity,
            lifecycle_state,
            risk_domain: "logic",
            head: CI_HEAD,
            status: None,
        })
    };
    // An open SERIOUS CODE finding recorded for another head.
    let other_subject = |only| {
        Some(CiCodeFinding {
            only,
            severity: Some("SERIOUS"),
            lifecycle_state: "NEW",
            risk_domain: "logic",
            head: "fedcba9876543210fedcba9876543210fedcba98",
            status: None,
        })
    };
    // An open SERIOUS finding of a partial CODE assessment beside the
    // environment.
    let partial = Some(CiCodeFinding {
        only: false,
        severity: Some("SERIOUS"),
        lifecycle_state: "NEW",
        risk_domain: "logic",
        head: CI_HEAD,
        status: Some("INCOMPLETE"),
    });
    // Server counts cover ENV only. CODE-only reviews report [0, 0] even
    // when they contain a serious finding. The exit codes are without the
    // flag, under `warning` and under `serious`.
    let cases = [
        // A person dismissed the finding, so nothing is open.
        (Some([0, 0]), "COMPLETED", None, [0, 0, 0]),
        (Some([1, 1]), "COMPLETED", None, [0, 3, 3]),
        (Some([1, 0]), "COMPLETED", None, [0, 3, 0]),
        // A threshold that cannot be measured is never a pass.
        (None, "COMPLETED", None, [0, 4, 4]),
        // A review that did not finish exits 2 whatever it found.
        (Some([1, 1]), "INCOMPLETE", None, [2, 2, 2]),
        (
            Some([0, 0]),
            "COMPLETED",
            code(true, Some("SERIOUS"), "NEW"),
            [0, 3, 3],
        ),
        (
            Some([0, 0]),
            "COMPLETED",
            code(true, Some("WARNING"), "NEW"),
            [0, 3, 0],
        ),
        (
            Some([0, 0]),
            "COMPLETED",
            code(true, None, "NEW"),
            [0, 0, 0],
        ),
        (
            Some([0, 0]),
            "COMPLETED",
            code(true, Some("SERIOUS"), "RESOLVED"),
            [0, 0, 0],
        ),
        (
            None,
            "COMPLETED",
            code(true, Some("SERIOUS"), "NEW"),
            [0, 4, 4],
        ),
        (
            Some([0, 0]),
            "INCOMPLETE",
            code(true, Some("SERIOUS"), "NEW"),
            [2, 2, 2],
        ),
        // A CODE finding can reach a threshold the ENV counts do not.
        (
            Some([1, 0]),
            "COMPLETED",
            code(false, Some("SERIOUS"), "NEW"),
            [0, 3, 3],
        ),
        // The complete environment completes the review, but a partial CODE
        // assessment's findings are not its whole result.
        (Some([0, 0]), "COMPLETED", partial, [0, 0, 0]),
        // A CODE record of another head neither completes the review nor
        // reaches a threshold, and the environment still decides.
        (Some([0, 0]), "COMPLETED", other_subject(true), [2, 2, 2]),
        (Some([0, 0]), "COMPLETED", other_subject(false), [0, 0, 0]),
    ];
    for (open, assessment, code_finding, codes) in cases {
        // Exit 2 is the CLI's reading of an incomplete review.
        let outcome = if codes[0] == 2 {
            "INCOMPLETE"
        } else {
            "COMPLETED"
        };
        let (origin, _) = ci_console(
            "PULL_REQUEST",
            StatusCode::OK,
            assessment,
            open,
            code_finding,
        )
        .await;
        for (fail_on, code) in [None, Some("warning"), Some("serious")]
            .into_iter()
            .zip(codes)
        {
            let mut args = vec!["ci", "review", "--repo", "acme/app", "--commit", CI_HEAD];
            args.extend(["--timeout", "0", "--json"]);
            if let Some(threshold) = fail_on {
                args.extend(["--fail-on", threshold]);
            }
            let output = cli(&origin, &args).await;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let case = format!("{open:?} {assessment} {fail_on:?} {code_finding:?}: {stderr}");
            assert_eq!(output.status.code(), Some(code), "{case}");
            assert_eq!(
                stderr.contains("at or above the --fail-on severity"),
                code == 3,
                "{case}"
            );
            assert_eq!(stderr.contains("without `open_items`"), code == 4, "{case}");
            // The flag changes the exit code only: the result keeps its shape,
            // and `outcome` still reads completeness.
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            let keys: BTreeSet<&str> = result
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                BTreeSet::from(["schema", "outcome", "review_url", "review"]),
                "{case}"
            );
            assert_eq!(result["schema"], "proofline.review-result.v1", "{case}");
            assert_eq!(result["outcome"], outcome, "{case}");
        }
    }
    // A threshold the CLI does not offer is a usage error, not an incomplete
    // review, and nothing is read.
    let (origin, requests) =
        ci_console("PULL_REQUEST", StatusCode::OK, "COMPLETED", None, None).await;
    let mut args = vec!["ci", "review", "--repo", "acme/app", "--commit", CI_HEAD];
    args.extend(["--fail-on", "critical"]);
    let output = cli(&origin, &args).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("warning, serious"));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_tools_keep_tenant_paths_and_reruns_make_one_attempt() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let app = Router::new().fallback(move |request: axum::extract::Request| {
        let seen = Arc::clone(&seen);
        async move {
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                format!("Bearer {TOKEN}")
            );
            let path = request.uri().path().to_owned();
            assert!(path.starts_with(&format!("/api/v1/organizations/{ORG}/")));
            seen.lock()
                .unwrap()
                .push((request.method().clone(), path.clone()));
            if path.ends_with("/rerun") {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "0")],
                    Json(json!({"detail":"unavailable"})),
                )
                    .into_response();
            }
            if path.ends_with("/exports/reviews") {
                return (
                    [
                        ("content-type", "text/csv"),
                        ("x-proofline-export-version", "1"),
                        ("x-proofline-export-settled-until", "2026-10-25T00:00:00Z"),
                        ("x-proofline-export-next-cursor", "opaque-next"),
                    ],
                    "dataset_version,claim\r\n1,\"a,b\"\r\n",
                )
                    .into_response();
            }
            if path.ends_with("repository-names") {
                return Json(
                    json!({"repositories": [{"id": REPOSITORY, "full_name":"owner/repo"}]}),
                )
                .into_response();
            }
            Json(json!({"untrusted_text":"literal\u{001b}[2J", "items":[]})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for args in [
        vec!["history", "--pr", "7", "--repo", "owner/repo"],
        vec!["fix-prompt", SELECTED_REVIEW],
    ] {
        let output = cli(&origin, &args).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.contains(&27));
    }
    let output = cli(&origin, &["rerun", SELECTED_REVIEW, "--no-wait"]).await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path.ends_with("/rerun"))
            .count(),
        1
    );
    let output = cli(
        &origin,
        &[
            "export",
            "reviews",
            "--from",
            "2026-10-01T00:00:00Z",
            "--to",
            "2026-10-25T00:00:00Z",
            "--format",
            "csv",
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"dataset_version,claim\r\n1,\"a,b\"\r\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("next-cursor: opaque-next"));
    server.abort();
}
