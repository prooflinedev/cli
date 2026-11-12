//! Deployment reviews against a loopback stand-in for the console: reading
//! one by its public key with `findings --deployment`, and holding a deploy
//! job to the review of its commit with `ci deployment`.

use std::sync::{Arc, Mutex};

use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const TOKEN: &str = "pld_secretsecretsecret";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000f0";
const HEAD: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// A complete deployment review, and its public key.
const COMPLETE: &str = "0190f3a0-0000-7000-8000-0000000000d1";
const COMPLETE_KEY: &str = "rev_0190f3a00000700080000000000000d1";
/// A deployment review whose environment assessment did not finish.
const INCOMPLETE: &str = "0190f3a0-0000-7000-8000-0000000000d2";
const INCOMPLETE_KEY: &str = "rev_0190f3a00000700080000000000000d2";
/// A key the console answers with another review.
const SUBSTITUTED_KEY: &str = "rev_0190f3a00000700080000000000000d3";
/// A key that addresses a pull-request review.
const PULL_REQUEST: &str = "0190f3a0-0000-7000-8000-0000000000d4";
const PULL_REQUEST_KEY: &str = "rev_0190f3a00000700080000000000000d4";
/// A key the console does not know.
const UNKNOWN_KEY: &str = "rev_0190f3a00000700080000000000000d5";

/// Every request the console received, as `METHOD path`.
type Requests = Arc<Mutex<Vec<String>>>;

fn review(id: &str, kind: &str, assessment: &str, open: Option<[u64; 2]>) -> Value {
    let findings = match open {
        Some([count, _]) if count > 0 => json!([{
            "id": "0190f3a0-0000-7000-8000-0000000000e1",
            "severity": "SERIOUS",
            "risk_domain": "iam_permissions",
            "claim": "The task role cannot read the new queue.",
            "impact": "workers fail at start",
            "lifecycle_state": "NEW",
            "evidence_refs": [],
        }]),
        _ => json!([]),
    };
    json!({
        "id": id,
        "kind": kind,
        "status": "COMPLETED",
        "head_commit_sha": HEAD,
        "repository_full_name": "acme/app",
        "assessment_count": 1,
        "open_items": open.map(|[open_findings, serious_findings]| json!({
            "open_findings": open_findings,
            "serious_findings": serious_findings,
            "accepted_risks": 0,
            "not_assessed": [],
        })),
        "assessments": [{
            "id": "0190f3a0-0000-7000-8000-0000000000e2",
            "environment_display_name": "production",
            "status": assessment,
            "findings": findings,
            "checks": { "receipt_recorded": true, "status": "READY", "families": [] },
        }],
    })
}

/// A console that serves deployment reviews by public key, and lists one
/// review of `HEAD` in `acme/app` as `listed` whose detail counts `open` as
/// its open and serious findings.
async fn console(listed: &'static str, open: Option<[u64; 2]>) -> (String, Requests) {
    let requests = Requests::default();
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/deployments/{{key}}"),
            get(|Path(key): Path<String>, headers: HeaderMap| async move {
                assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                let document = match key.as_str() {
                    COMPLETE_KEY => review(COMPLETE, "DEPLOYMENT", "COMPLETED", Some([0, 0])),
                    INCOMPLETE_KEY => review(INCOMPLETE, "DEPLOYMENT", "INCOMPLETE", None),
                    SUBSTITUTED_KEY => review(COMPLETE, "DEPLOYMENT", "COMPLETED", None),
                    PULL_REQUEST_KEY => review(PULL_REQUEST, "PULL_REQUEST", "COMPLETED", None),
                    _ => return problem(StatusCode::NOT_FOUND, "No such deployment review."),
                };
                Json(document).into_response()
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/app" }] }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(move || async move {
                Json(json!({
                    "items": [{
                        "id": COMPLETE,
                        "kind": listed,
                        "status": "COMPLETED",
                        "created_at": "2026-10-01T00:00:00Z",
                        "head_commit_sha": HEAD,
                        "pull_request_number": null,
                        "repository_id": REPOSITORY,
                        "run_number": null,
                    }],
                    "next_cursor": null,
                    "truncated": false,
                    "filters": { "repositories": [], "environments": [], "authors": [] },
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{COMPLETE}"),
            get(move || async move { Json(review(COMPLETE, "DEPLOYMENT", "COMPLETED", open)) }),
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

fn problem(status: StatusCode, detail: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        Json(json!({ "title": "Not found", "status": status.as_u16(), "detail": detail })),
    )
        .into_response()
}

async fn cli(origin: &str, args: &[&str]) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"))
            .args(["--base-url", origin, "--org", ORG])
            .args(args)
            .env("PROOFLINE_TOKEN", TOKEN)
            .env("COMMIT_SHA", HEAD)
            .env_remove("GITHUB_SHA")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
            .env("PATH", "")
            .current_dir(directory.path())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

fn deployment_path(key: &str) -> String {
    format!("GET /api/v1/organizations/{ORG}/reviews/deployments/{key}")
}

#[tokio::test]
async fn findings_reads_a_deployment_review_by_its_public_key() {
    let (origin, requests) = console("DEPLOYMENT", None).await;

    let output = cli(&origin, &["findings", "--deployment", COMPLETE_KEY]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.starts_with("acme/app at 89abcdef0123: COMPLETED\n"),
        "{text}"
    );
    assert!(
        text.contains("production: COMPLETED, no findings"),
        "{text}"
    );
    // The link is the review's console page, addressed by its identifier.
    assert!(
        text.contains(&format!("/orgs/by-id/{ORG}/reviews/{COMPLETE}")),
        "{text}"
    );

    let output = cli(
        &origin,
        &["findings", "--deployment", COMPLETE_KEY, "--json"],
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "COMPLETED");
    assert_eq!(document["review"]["id"], COMPLETE);
    assert_eq!(document["review"]["kind"], "DEPLOYMENT");

    // One read each, through the deployment operation and no other.
    assert_eq!(
        *requests.lock().unwrap(),
        [deployment_path(COMPLETE_KEY), deployment_path(COMPLETE_KEY)]
    );
    assert!(!stderr.contains(TOKEN));
}

#[tokio::test]
async fn an_incomplete_deployment_review_is_not_success() {
    let (origin, _) = console("DEPLOYMENT", None).await;
    for wait in [false, true] {
        let mut args = vec!["findings", "--deployment", INCOMPLETE_KEY];
        if wait {
            args.extend(["--wait", "--timeout", "0"]);
        }
        let output = cli(&origin, &args).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "wait={wait}: {stderr}");
        assert!(stderr.contains("incomplete"), "{stderr}");
    }
}

#[tokio::test]
async fn a_key_is_held_to_the_deployment_review_it_names() {
    let (origin, requests) = console("DEPLOYMENT", None).await;
    for (key, expected) in [
        (SUBSTITUTED_KEY, "but the server returned review"),
        (PULL_REQUEST_KEY, "has kind PULL_REQUEST, not DEPLOYMENT"),
        (UNKNOWN_KEY, "HTTP 404: No such deployment review."),
    ] {
        let output = cli(&origin, &["findings", "--deployment", key, "--json"]).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{key}: {stderr}");
        assert!(stderr.contains(expected), "{key}: {stderr}");
        // Nothing is printed as the named deployment's result.
        assert!(output.stdout.is_empty(), "{key}");
    }
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn a_malformed_key_or_a_second_selector_is_refused_before_any_request() {
    let (origin, requests) = console("DEPLOYMENT", None).await;
    let digits = COMPLETE_KEY.strip_prefix("rev_").unwrap();
    let uppercase = format!("rev_{}", digits.to_ascii_uppercase());
    for args in [
        vec!["findings", "--deployment", COMPLETE],
        vec!["findings", "--deployment", digits],
        vec!["findings", "--deployment", uppercase.as_str()],
        vec!["findings", "--deployment", "rev_../../reviews"],
        vec![
            "findings",
            "--deployment",
            COMPLETE_KEY,
            "--review",
            COMPLETE,
        ],
        vec!["findings", "--deployment", COMPLETE_KEY, "--pr", "7"],
        vec!["findings", "--deployment", COMPLETE_KEY, "--head", HEAD],
        // SARIF is a projection of a retained pull-request review.
        vec!["findings", "--deployment", COMPLETE_KEY, "--sarif"],
    ] {
        let output = cli(&origin, &args).await;
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ci_deployment_waits_for_the_deployment_review_of_the_commit() {
    // What the console lists at the commit, its open and serious counts, the
    // `--fail-on` threshold, and the exit code.
    for (listed, open, fail_on, code) in [
        ("DEPLOYMENT", Some([0, 0]), None, 0),
        ("DEPLOYMENT", Some([1, 1]), None, 0),
        ("DEPLOYMENT", Some([1, 1]), Some("serious"), 3),
        ("DEPLOYMENT", Some([1, 0]), Some("serious"), 0),
        ("DEPLOYMENT", Some([1, 0]), Some("warning"), 3),
        // A threshold that cannot be measured is never a pass.
        ("DEPLOYMENT", None, Some("warning"), 4),
        // A pull-request review of the same commit is not the deployment's.
        ("PULL_REQUEST", Some([0, 0]), None, 4),
    ] {
        let (origin, requests) = console(listed, open).await;
        let mut args = vec![
            "ci",
            "deployment",
            "--repo",
            "acme/app",
            "--timeout",
            "0",
            "--json",
        ];
        if let Some(threshold) = fail_on {
            args.extend(["--fail-on", threshold]);
        }
        let output = cli(&origin, &args).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let case = format!("{listed} {open:?} {fail_on:?}");
        assert_eq!(output.status.code(), Some(code), "{case}: {stderr}");
        assert!(!stderr.contains(TOKEN));
        let requests = requests.lock().unwrap();
        // A deployment job reads; it never requests or stops a review.
        assert!(
            requests.iter().all(|request| request.starts_with("GET ")),
            "{requests:?}"
        );
        if listed == "DEPLOYMENT" {
            let document: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(document["review"]["id"], COMPLETE, "{case}");
            assert_eq!(document["review"]["kind"], "DEPLOYMENT", "{case}");
        } else {
            assert!(output.stdout.is_empty(), "{case}");
            assert!(
                stderr.contains("No deployment review of acme/app"),
                "{case}: {stderr}"
            );
        }
    }
}

#[tokio::test]
async fn ci_deployment_takes_a_full_commit_and_writes_no_sarif() {
    let (origin, requests) = console("DEPLOYMENT", Some([0, 0])).await;
    for args in [
        // Only a full SHA names the deployed commit, never a ref.
        vec!["ci", "deployment", "--repo", "acme/app", "--commit", "main"],
        vec![
            "ci",
            "deployment",
            "--repo",
            "acme/app",
            "--sarif",
            "out.sarif",
        ],
    ] {
        let output = cli(&origin, &args).await;
        assert_eq!(output.status.code(), Some(1), "{args:?}");
    }
    assert!(requests.lock().unwrap().is_empty());

    let other = "0123456789abcdef0123456789abcdef01234567";
    let args = [
        "ci",
        "deployment",
        "--repo",
        "acme/app",
        "--timeout",
        "0",
        "--commit",
        other,
    ];
    let output = cli(&origin, &args).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The listed review is of another commit, so there is no answer yet.
    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains(other), "{stderr}");
}
