//! `proofline status --json` against a loopback stand-in for the console.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const TOKEN: &str = "pld_secretsecretsecret";
const WEB: &str = "0190f3a0-0000-7000-8000-000000000022";
const API: &str = "0190f3a0-0000-7000-8000-000000000023";

/// A console with acme/web connected that answers the token check with
/// `reviews`, the repository list with `names` and the setup tool with `setup`.
async fn console(reviews: StatusCode, names: (StatusCode, Value), setup: Value) -> String {
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(move || async move {
                let body = json!({
                    "items": [], "next_cursor": null, "truncated": false,
                    "filters": { "repositories": [] },
                });
                (reviews, Json(body))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(move || async move { (names.0, Json(names.1)) }),
        )
        .route(
            "/mcp",
            post(move |Json(body): Json<Value>| {
                let setup = setup.clone();
                async move {
                    match body["method"].as_str() {
                        Some("initialize") => Json(json!({
                            "jsonrpc": "2.0", "id": 1,
                            "result": { "protocolVersion": "2025-11-25" },
                        }))
                        .into_response(),
                        Some("notifications/initialized") => StatusCode::ACCEPTED.into_response(),
                        _ => {
                            assert_eq!(body["params"]["name"], "get_setup_status");
                            assert_eq!(body["params"]["arguments"]["organization_id"], ORG);
                            Json(json!({ "jsonrpc": "2.0", "id": 2, "result": setup }))
                                .into_response()
                        }
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    origin
}

/// A `get_setup_status` result carrying `data`, shaped as the live tool's.
fn setup(data: Value) -> Value {
    json!({
        "isError": false,
        "content": [{ "type": "text", "text": data.to_string() }],
        "structuredContent": { "ok": true, "data": data },
    })
}

fn environment(repository: &str, ready: bool) -> Value {
    json!({ "display_name": "production", "repository_ids": [repository], "ready": ready })
}

async fn status(origin: &str, args: &[&str]) -> (Option<i32>, Value) {
    let directory = tempfile::tempdir().unwrap();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_proofline"))
            .args(["--base-url", origin, "status", "--json"])
            .args(args)
            .env("PROOFLINE_TOKEN", TOKEN)
            .env("PATH", "")
            .current_dir(directory.path())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap();
    (output.status.code(), report)
}

/// A review runs only after setup is finished, through a ready environment
/// that links this repository. Open blockers alone never decide it.
#[tokio::test]
async fn reviewable_needs_finished_setup_and_a_ready_linked_environment() {
    let blocker =
        json!({ "code": "DRAFT_UNCONFIRMED", "detail": "Confirm the production environment." });
    let server = "https://console.example/orgs/github/acme";
    for (finished, environment, blockers, console, reviewable) in [
        // Unfinished setup with nothing open is still not reviewable.
        (
            false,
            environment(WEB, true),
            json!([]),
            Some(server),
            false,
        ),
        (false, environment(WEB, true), json!([blocker]), None, false),
        (true, environment(API, true), json!([]), None, false),
        (true, environment(WEB, false), json!([]), None, false),
        (true, environment(WEB, true), json!([]), None, true),
    ] {
        let mut data = json!({
            "configuration_complete": finished,
            "configured_environment_states": [environment],
            "blockers": blockers,
        });
        if let Some(console) = console {
            data["console_url"] = json!(console);
        }
        let origin = console_for(setup(data)).await;
        let (code, report) = status(&origin, &["--org", ORG, "--repo", "Acme/Web"]).await;
        assert_eq!(code, Some(0), "{report}");
        assert_eq!(report["reviewable"], reviewable, "{report}");
        assert_eq!(report["blockers"], blockers, "{report}");
        let next = console.map_or_else(|| format!("{origin}/orgs/github/acme"), str::to_owned);
        let next = (!reviewable).then(|| format!("finish setup at {next}"));
        assert_eq!(report["next"], json!(next), "{report}");
    }
}

/// A setup status the CLI cannot read never becomes a verdict either way.
#[tokio::test]
async fn an_unreadable_setup_cannot_tell() {
    let refused = json!({
        "isError": true,
        "content": [{ "type": "text", "text": "setup:write is required" }],
    });
    let incomplete = setup(json!({ "blockers": [] }));
    // The environment fields come from the console's own reads, not a contract.
    let renamed = setup(json!({
        "configuration_complete": true,
        "configured_environment_states": [{ "repositories": [WEB], "is_ready": true }],
    }));
    for result in [refused, incomplete, renamed] {
        let origin = console_for(result).await;
        let (code, report) = status(&origin, &["--org", ORG, "--repo", "acme/web"]).await;
        assert_eq!(code, Some(0), "{report}");
        assert_eq!(report["reviewable"], Value::Null, "{report}");
        assert_eq!(
            report["next"],
            format!("check setup at {origin}/orgs/github/acme")
        );
    }
}

/// `false` is kept for a confirmed answer; a server that did not answer says
/// nothing about the repository.
#[tokio::test]
async fn only_a_confirmed_answer_is_unreviewable() {
    let (ok, forbidden, unavailable) = (
        StatusCode::OK,
        StatusCode::FORBIDDEN,
        StatusCode::SERVICE_UNAVAILABLE,
    );
    for (reviews, names, repository, reviewable) in [
        (unavailable, (ok, connected()), "acme/web", Value::Null),
        (
            StatusCode::REQUEST_TIMEOUT,
            (ok, connected()),
            "acme/web",
            Value::Null,
        ),
        (forbidden, (ok, connected()), "acme/web", json!(false)),
        (ok, (unavailable, connected()), "acme/web", Value::Null),
        (ok, (forbidden, connected()), "acme/web", json!(false)),
        // A list that is not the contract's: no answer was read.
        (
            ok,
            (ok, json!({ "repositories": 5 })),
            "acme/web",
            Value::Null,
        ),
        (ok, (ok, connected()), "acme/other", json!(false)),
    ] {
        let origin = console(reviews, names, setup(json!({}))).await;
        let (_, report) = status(&origin, &["--org", ORG, "--repo", repository]).await;
        assert_eq!(report["reviewable"], reviewable, "{report}");
        assert!(report["next"].is_string(), "{report}");
    }
}

/// An agent reads the same fields when the CLI is not signed in.
#[tokio::test]
async fn without_a_sign_in_the_report_keeps_its_fields() {
    let origin = console_for(setup(json!({}))).await;
    let (code, report) = status(&origin, &["--repo", "acme/web"]).await;
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["console"], origin);
    assert_eq!(report["organization_id"], Value::Null);
    assert_eq!(report["reviewable"], false);
    assert!(
        report["next"].as_str().unwrap().contains("--org"),
        "{report}"
    );
}

async fn console_for(setup: Value) -> String {
    console(StatusCode::OK, (StatusCode::OK, connected()), setup).await
}

fn connected() -> Value {
    json!({ "repositories": [{ "id": WEB, "full_name": "acme/web" }] })
}
