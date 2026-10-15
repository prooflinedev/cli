//! Actual CLI processes read a retained review over HTTP and validate their
//! output against the unmodified OASIS SARIF 2.1.0 Plus Errata 01 schema.

use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::process::Command;
use uuid::Uuid;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const OTHER_ORG: &str = "0190f3a0-0000-7000-8000-000000000002";
const REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";
const ASSESSMENT: &str = "0190f3a0-0000-7000-8000-000000000044";
const CODE_ASSESSMENT: &str = "0190f3a0-0000-7000-8000-000000000055";
const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
const BASE: &str = "89abcdef0123456789abcdef0123456789abcdef";
const OTHER_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const TOKEN: &str = "pld_sarifsynthetictoken";
const PRIVATE_VALUE: &str = "raw-world-evidence-and-operator-diagnostics";
const CLAIM: &str = r"A retry can replay {0} with {{receipt}} from [label](0), array[nested[0]] and C:\orders\receipt.";
const ESCAPED_CLAIM: &str = r"A retry can replay {{0}} with {{{{receipt}}}} from \[label\](0), array\[nested\[0\]\] and C:\\orders\\receipt.";
const ENVIRONMENT: &str = r"production {0} [overview](0)\primary";
const ESCAPED_ENVIRONMENT: &str = r"production {{0}} \[overview\](0)\\primary";
const LITERAL_REASON: &str = r"CHECK_{0}_[link](0)\broker";
const ESCAPED_REASON: &str = r"CHECK_{{0}}_\[link\](0)\\broker";
const FINGERPRINT: &str = "5f3c9a7e1b2d4c6a8e0f9b1d3a5c7e9f2b4d6a8c0e1f3a5b7d9c2e4f6a8b0c1d";
const SCHEMA_SOURCE: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

#[derive(Clone)]
struct Console {
    status: StatusCode,
    document: Value,
    requests: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Console {
    fn new(document: Value) -> Self {
        Self {
            status: StatusCode::OK,
            document,
            requests: Arc::default(),
        }
    }

    fn assert_reads(&self, count: usize, organization: &str) {
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), count);
        for (method, path) in &*requests {
            assert_eq!(method, Method::GET);
            assert_eq!(
                path,
                &format!("/api/v1/organizations/{organization}/reviews/{REVIEW}")
            );
        }
    }
}

async fn retained_review(
    State(console): State<Console>,
    Path((organization, review)): Path<(String, Uuid)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    console
        .requests
        .lock()
        .unwrap()
        .push((method.clone(), uri.path().to_owned()));
    let authorization = format!("Bearer {TOKEN}");
    let status = if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(authorization.as_str())
    {
        StatusCode::UNAUTHORIZED
    } else if method != Method::GET {
        StatusCode::METHOD_NOT_ALLOWED
    } else if organization != ORG || review != REVIEW.parse::<Uuid>().unwrap() {
        StatusCode::NOT_FOUND
    } else {
        console.status
    };
    if !status.is_success() {
        return (
            status,
            Json(json!({
                "status": status.as_u16(),
                "title": "Review unavailable",
                "detail": "This token cannot read the requested review.",
            })),
        )
            .into_response();
    }
    Json(console.document).into_response()
}

async fn unexpected_request(
    State(console): State<Console>,
    method: Method,
    uri: Uri,
) -> StatusCode {
    console
        .requests
        .lock()
        .unwrap()
        .push((method, uri.path().to_owned()));
    StatusCode::NOT_FOUND
}

async fn serve(console: Console) -> String {
    let app = Router::new()
        .route(
            "/api/v1/organizations/{organization}/reviews/{review}",
            any(retained_review),
        )
        .fallback(unexpected_request)
        .with_state(console);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

async fn cli(origin: &str, organization: &str, token: &str, args: &[&str]) -> Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        Command::new(env!("CARGO_BIN_EXE_proofline"))
            .args(["--base-url", origin, "--org", organization])
            .args(args)
            .env("PROOFLINE_TOKEN", token)
            // Explicit retained-review selection needs neither Git nor a
            // checkout. A regression into repository resolution fails here.
            .env("PATH", "")
            .current_dir(std::env::temp_dir())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn export(origin: &str) -> Output {
    cli(
        origin,
        ORG,
        TOKEN,
        &["findings", "--review", REVIEW, "--sarif"],
    )
    .await
}

fn schema() -> jsonschema::Validator {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sarif-schema-2.1.0.json");
    let raw = std::fs::read_to_string(path).unwrap();
    let document: Value = serde_json::from_str(&raw).unwrap();
    jsonschema::options()
        .offline()
        .should_validate_formats(true)
        .build(&document)
        .unwrap()
}

fn report(output: &Output, schema: &jsonschema::Validator) -> Value {
    let document: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid SARIF JSON: {error}; stderr: {:?}", output.stderr));
    let errors: Vec<String> = schema
        .iter_errors(&document)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "SARIF schema errors: {errors:?}");
    assert_eq!(document["$schema"], SCHEMA_SOURCE);
    let text = std::str::from_utf8(&output.stdout).unwrap();
    assert!(!text.contains(TOKEN));
    assert!(!text.contains(PRIVATE_VALUE));
    document
}

fn code(path: &str, start: u32, end: Option<u32>) -> Value {
    json!({
        "kind": "repository_file",
        "label": "verified file read",
        "provenance_status": "VERIFIED_REPOSITORY_READ",
        "commit_sha": HEAD,
        "repository_path": path,
        "start_line": start,
        "end_line": end,
    })
}

fn finding(number: u128, severity: &str, refs: Vec<Value>) -> Value {
    json!({
        "id": Uuid::from_u128(0x0190_f3a0_0000_7000_8000_0000_0000_0100 + number),
        "severity": severity,
        "risk_domain": "data_integrity",
        "claim": CLAIM,
        "impact": "The customer can be charged twice.",
        "lifecycle_state": "ACTIVE",
        "remediation": "Make the order receipt idempotent.",
        "evidence_refs": refs,
        "evidence_values": PRIVATE_VALUE,
        "operator_diagnostics": PRIVATE_VALUE,
    })
}

fn review(findings: Vec<Value>) -> Value {
    json!({
        "id": REVIEW,
        "kind": "PULL_REQUEST",
        "status": "COMPLETED",
        "head_commit_sha": HEAD,
        "repository_full_name": "acme/web",
        "pull_request_number": 42,
        "run_number": 7,
        "assessment_count": 1,
        "assessments": [{
            "id": ASSESSMENT,
            "environment_display_name": ENVIRONMENT,
            "status": "COMPLETED",
            "findings": findings,
            "checks": {"receipt_recorded": true, "status": "READY", "families": []},
            "reviewer_version": PRIVATE_VALUE,
            "world_evidence_values": PRIVATE_VALUE,
        }],
        "operator_diagnostics": PRIVATE_VALUE,
    })
}

fn code_review() -> Value {
    let mut document = review(Vec::new());
    let mut recorded = finding(1, "SERIOUS", vec![code("src/orders.rs", 10, Some(14))]);
    recorded["risk_domain"] = json!("logic");
    document["base_commit_sha"] = json!(BASE);
    document["assessment_count"] = json!(0);
    document["assessments"] = json!([]);
    document["code_assessment"] = json!({
        "id": CODE_ASSESSMENT,
        "status": "COMPLETED",
        "base_commit_sha": BASE,
        "head_commit_sha": HEAD,
        "incompleteness_kind": null,
        "findings": [recorded],
        "compatible_addition": PRIVATE_VALUE,
    });
    document
}

#[tokio::test]
async fn code_results_keep_their_identity_and_cannot_complete_environment_assessments() {
    let schema = schema();
    let complete = code_review();
    let mut cases = vec![("completed", complete.clone(), Some("COMPLETED"), 0, 1, true)];
    let mut deterministic = complete.clone();
    deterministic["code_assessment"]["findings"][0]["risk_domain"] = json!("committed_secret");
    cases.push((
        "deterministic CODE finding",
        deterministic,
        Some("COMPLETED"),
        0,
        1,
        true,
    ));
    // Different occurrences keep their own IDs and share the retained
    // fingerprint. Every other row is an older response without one.
    let mut retained = complete.clone();
    retained["code_assessment"]["findings"][0]["finding_fingerprint"] = json!(FINGERPRINT);
    let mut later_occurrence = retained.clone();
    later_occurrence["code_assessment"]["findings"][0]["id"] =
        finding(3, "SERIOUS", Vec::new())["id"].clone();
    cases.push((
        "retained fingerprint",
        retained,
        Some("COMPLETED"),
        0,
        1,
        true,
    ));
    cases.push((
        "same fingerprint, later occurrence",
        later_occurrence,
        Some("COMPLETED"),
        0,
        1,
        true,
    ));
    for status in ["PENDING", "RUNNING", "INCOMPLETE", "EXCLUDED"] {
        let mut document = complete.clone();
        document["code_assessment"]["status"] = json!(status);
        cases.push((status, document, Some("INCOMPLETE"), 2, 1, false));
    }
    let mut gap = complete.clone();
    gap["code_assessment"]["incompleteness_kind"] = json!("EVIDENCE_UNAVAILABLE");
    cases.push(("recorded gap", gap, Some("INCOMPLETE"), 2, 1, false));
    for (label, field, value) in [
        ("unknown state", "status", json!("FUTURE_STATE")),
        ("malformed findings", "findings", json!({})),
        ("malformed gap", "incompleteness_kind", json!(42)),
        ("malformed identity", "id", json!("unknown")),
        ("missing subject", "head_commit_sha", json!("")),
        ("other head", "head_commit_sha", json!(OTHER_COMMIT)),
        ("other base", "base_commit_sha", json!(OTHER_COMMIT)),
    ] {
        let mut document = complete.clone();
        document["code_assessment"][field] = value;
        cases.push((label, document, Some("INCOMPLETE"), 2, 0, false));
    }
    for (label, value) in [("null code", Value::Null), ("malformed code", json!([]))] {
        let mut document = complete.clone();
        document["code_assessment"] = value;
        cases.push((label, document, Some("INCOMPLETE"), 2, 0, false));
    }
    let mut missing = complete.clone();
    missing.as_object_mut().unwrap().remove("code_assessment");
    cases.push(("missing code", missing, Some("INCOMPLETE"), 2, 0, false));
    let mut pending = complete.clone();
    pending["status"] = json!("PENDING");
    cases.push(("review pending", pending, None, 2, 1, false));
    let mut missing_environment = complete.clone();
    missing_environment["assessment_count"] = json!(1);
    cases.push((
        "missing environment",
        missing_environment,
        Some("INCOMPLETE"),
        2,
        1,
        false,
    ));
    let mut environment_gap = review(vec![finding(2, "WARNING", Vec::new())]);
    environment_gap["code_assessment"] = complete["code_assessment"].clone();
    environment_gap["assessments"][0]["checks"]["receipt_recorded"] = json!(false);
    cases.push((
        "environment gap",
        environment_gap,
        Some("INCOMPLETE"),
        2,
        1,
        false,
    ));
    let mut complete_environment = review(Vec::new());
    complete_environment["code_assessment"] = complete["code_assessment"].clone();
    complete_environment["code_assessment"]["status"] = json!("INCOMPLETE");
    cases.push((
        "environment precedence",
        complete_environment,
        Some("COMPLETED"),
        0,
        1,
        false,
    ));
    // A review's base is null until pinned, and its CODE record still counts.
    let mut unpinned = complete.clone();
    unpinned["base_commit_sha"] = Value::Null;
    cases.push((
        "unpinned review base",
        unpinned,
        Some("COMPLETED"),
        0,
        1,
        true,
    ));
    let mut other_subject = review(Vec::new());
    other_subject["code_assessment"] = complete["code_assessment"].clone();
    other_subject["code_assessment"]["head_commit_sha"] = json!(OTHER_COMMIT);
    cases.push((
        "other subject beside an environment",
        other_subject,
        Some("COMPLETED"),
        0,
        0,
        false,
    ));
    // Once the review's protected evidence is missing or has expired, the API
    // publishes the server's marker in place of every CODE finding's text and
    // drops its file citations. The record keeps its identity and status.
    let marker = "[withheld: environment value]";
    let mut withheld = complete.clone();
    for field in ["risk_domain", "claim", "impact", "remediation"] {
        withheld["code_assessment"]["findings"][0][field] = json!(marker);
    }
    withheld["code_assessment"]["findings"][0]["evidence_refs"] = json!([]);
    let mut withheld_beside_environment = review(vec![finding(
        2,
        "WARNING",
        vec![code("src/orders.rs", 10, Some(14))],
    )]);
    withheld_beside_environment["assessments"][0]["findings"][0]["claim"] =
        json!("The environment drops the order.");
    withheld_beside_environment["code_assessment"] = withheld["code_assessment"].clone();
    cases.push(("withheld code", withheld, Some("INCOMPLETE"), 2, 0, false));
    cases.push((
        "withheld code beside an environment",
        withheld_beside_environment,
        Some("COMPLETED"),
        0,
        0,
        false,
    ));

    for (label, raw, outcome, exit, finding_count, execution_successful) in cases {
        let console = Console::new(raw.clone());
        let origin = serve(console.clone()).await;
        let text = cli(&origin, ORG, TOKEN, &["findings", "--review", REVIEW]).await;
        assert_eq!(text.status.code(), Some(exit), "{label}: {text:?}");
        let text = std::str::from_utf8(&text.stdout).unwrap();
        assert!(text.contains("Code-only:"), "{label}: {text}");
        assert_eq!(text.contains(CLAIM), finding_count > 0, "{label}: {text}");
        // Every row without a usable CODE record says so.
        assert_eq!(
            text.contains("(CODE_ASSESSMENT_UNAVAILABLE)"),
            finding_count == 0,
            "{label}: {text}"
        );
        assert!(
            !text.contains("Code-only: COMPLETED, no findings"),
            "{label}: {text}"
        );

        let output = cli(
            &origin,
            ORG,
            TOKEN,
            &["findings", "--review", REVIEW, "--json"],
        )
        .await;
        assert_eq!(output.status.code(), Some(exit), "{label}: {output:?}");
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["outcome"], json!(outcome), "{label}");
        assert_eq!(json["review"], raw, "{label}");

        let output = export(&origin).await;
        assert_eq!(output.status.code(), Some(exit), "{label}: {output:?}");
        let document = report(&output, &schema);
        let run = &document["runs"][0];
        assert_eq!(run["properties"]["outcome"], json!(outcome), "{label}");
        assert_eq!(
            run["invocations"][0]["executionSuccessful"], execution_successful,
            "{label}"
        );
        let code_findings: Vec<&Value> = run["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["properties"]["lane"] == "CODE")
            .collect();
        assert_eq!(code_findings.len(), finding_count, "{label}");
        assert_eq!(
            run["invocations"][0]["toolExecutionNotifications"]
                .as_array()
                .unwrap()
                .iter()
                .any(|notice| notice["properties"]["reasonCode"] == "CODE_ASSESSMENT_UNAVAILABLE"),
            finding_count == 0,
            "{label}"
        );
        // An unusable CODE record supplies no metadata, rule or domain.
        assert_eq!(
            run["properties"].get("codeAssessment").is_some(),
            finding_count > 0,
            "{label}"
        );
        if label == "withheld code beside an environment" {
            let results = run["results"].as_array().unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0]["properties"]["lane"], "ENV");
            assert_eq!(
                results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "src/orders.rs"
            );
        }
        if let Some(finding) = code_findings.first() {
            assert_eq!(
                finding["properties"]["assessmentId"], CODE_ASSESSMENT,
                "{label}"
            );
            assert!(
                finding["properties"].get("environment").is_none(),
                "{label}"
            );
            let domain = if label == "deterministic CODE finding" {
                "committed_secret"
            } else {
                "logic"
            };
            assert_eq!(finding["ruleId"], domain, "{label}");
            let index = usize::try_from(finding["ruleIndex"].as_u64().unwrap()).unwrap();
            assert_eq!(
                run["tool"]["driver"]["rules"][index]["id"], domain,
                "{label}"
            );
            assert_eq!(
                finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "src/orders.rs",
                "{label}"
            );
            assert_eq!(
                finding["locations"][0]["physicalLocation"]["region"]["startLine"], 10,
                "{label}"
            );
            assert!(
                finding["message"]["text"]
                    .as_str()
                    .unwrap()
                    .contains("Code-only finding"),
                "{label}"
            );
            assert_eq!(
                run["properties"]["codeAssessment"]["headCommitSha"], HEAD,
                "{label}"
            );
            let recorded = &raw["code_assessment"]["findings"][0];
            assert_eq!(
                finding["properties"]["findingId"], recorded["id"],
                "{label}"
            );
            assert_eq!(
                finding.get("partialFingerprints").cloned(),
                recorded
                    .get("finding_fingerprint")
                    .map(|fingerprint| json!({"prooflineFinding/v1": fingerprint})),
                "{label}"
            );
            assert!(finding.get("fingerprints").is_none(), "{label}");
        }
        if outcome == Some("INCOMPLETE") {
            assert!(
                !run["invocations"][0]["toolExecutionNotifications"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "{label}"
            );
        }
        if label == "recorded gap" {
            assert_eq!(
                run["properties"]["codeAssessment"]["gapReasons"],
                json!(["EVIDENCE_UNAVAILABLE"])
            );
            assert!(
                run["invocations"][0]["toolExecutionNotifications"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(
                        |notice| notice["properties"]["assessmentId"] == CODE_ASSESSMENT
                            && notice["properties"]["reasonCode"] == "EVIDENCE_UNAVAILABLE"
                    )
            );
        }
        if label == "completed" {
            let catalog: Value =
                serde_json::from_str(include_str!("fixtures/risk-domains.json")).unwrap();
            let categories: Vec<&str> = catalog["code"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            let rules: Vec<&str> = run["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .map(|rule| rule["id"].as_str().unwrap())
                .collect();
            assert_eq!(
                rules[rules.len() - categories.len()..],
                categories,
                "the exporting CODE rules must match the recorded code catalog"
            );
        }
        console.assert_reads(3, ORG);
    }
}

#[tokio::test]
async fn sarif_retains_identity_and_filters_locations_at_the_recorded_head() {
    let mut references = vec![
        code("src/orders #100%.rs", 10, Some(14)),
        code("src/orders #100%.rs", 10, Some(14)),
        code("src/\u{00e9}.rs", 20, None),
    ];
    let mut wrong_commit = code("src/orders.rs", 1, Some(2));
    wrong_commit["commit_sha"] = json!("9876543210abcdef0123456789abcdef01234567");
    references.push(wrong_commit);
    let mut invalid_commit = code("src/orders.rs", 1, Some(2));
    invalid_commit["commit_sha"] = json!("main");
    references.push(invalid_commit);
    let mut no_commit = code("src/orders.rs", 1, Some(2));
    no_commit.as_object_mut().unwrap().remove("commit_sha");
    references.push(no_commit);
    let mut unverified = code("src/orders.rs", 1, Some(2));
    unverified["provenance_status"] = json!("UNVERIFIED");
    references.push(unverified);
    let mut legacy = code("src/orders.rs", 1, Some(2));
    legacy.as_object_mut().unwrap().remove("provenance_status");
    references.push(legacy);
    let mut companion = code("src/orders.rs", 1, Some(2));
    companion["kind"] = json!("companion_repository_file");
    companion["companion_repository"] = json!("acme/contracts");
    references.push(companion);
    let mut disguised_companion = code("src/orders.rs", 1, Some(2));
    disguised_companion["companion_repository"] = json!("acme/contracts");
    references.push(disguised_companion);
    for path in [
        "",
        "/etc/passwd",
        "../src/orders.rs",
        "src/../orders.rs",
        "src/./orders.rs",
        "src//orders.rs",
        "src\\orders.rs",
        "C:/orders.rs",
        "https://elsewhere.example/orders.rs",
        "src/\u{1b}[2J.rs",
        "src/\u{202e}orders.rs",
    ] {
        references.push(code(path, 1, Some(2)));
    }
    references.push(code("src/orders.rs", 0, Some(2)));
    references.push(code("src/orders.rs", 2, Some(1)));
    let mut missing_line = code("src/orders.rs", 1, Some(2));
    missing_line.as_object_mut().unwrap().remove("start_line");
    references.push(missing_line);
    references.push(json!({
        "kind": "world_entity",
        "label": PRIVATE_VALUE,
        "provenance_status": "PINNED_WORLD_ENTITY",
        "world_entity_id": PRIVATE_VALUE,
        "values": PRIVATE_VALUE,
        "url": "https://elsewhere.example/private",
    }));
    let mut retained = finding(1, "SERIOUS", references);
    retained["finding_fingerprint"] = json!(FINGERPRINT);
    let console = Console::new(review(vec![retained, finding(2, "WARNING", Vec::new())]));
    let origin = serve(console.clone()).await;
    let schema = schema();
    let first = export(&origin).await;
    assert_eq!(first.status.code(), Some(0));
    let document = report(&first, &schema);
    let run = &document["runs"][0];
    assert_eq!(run["properties"]["reviewId"], REVIEW);
    assert_eq!(run["properties"]["organizationId"], ORG);
    assert_eq!(run["properties"]["headCommitSha"], HEAD);
    assert_eq!(run["properties"]["runNumber"], 7);
    assert_eq!(run["properties"]["outcome"], "COMPLETED");
    let catalog: Value = serde_json::from_str(include_str!("fixtures/risk-domains.json")).unwrap();
    let domains: Vec<&str> = catalog["environment"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    let rules: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        rules, domains,
        "the exporting rules must match the domain catalog"
    );
    assert_eq!(run["invocations"][0]["executionSuccessful"], true);
    assert_eq!(run["results"].as_array().unwrap().len(), 2);
    let serious = &run["results"][0];
    assert_eq!(
        serious["message"]["text"],
        format!("{ESCAPED_CLAIM}\n\nThe customer can be charged twice.")
    );
    assert!(serious["message"].get("arguments").is_none());
    assert!(serious["message"].get("markdown").is_none());
    assert_eq!(serious["properties"]["environment"], ENVIRONMENT);
    assert_eq!(
        serious["properties"]["findingId"],
        finding(1, "SERIOUS", Vec::new())["id"]
    );
    assert_eq!(serious["level"], "error");
    assert_eq!(serious["ruleId"], "data_integrity");
    let rule_index = serious["ruleIndex"].as_u64().unwrap();
    let rule_index = usize::try_from(rule_index).unwrap();
    assert_eq!(
        run["tool"]["driver"]["rules"][rule_index]["id"],
        "data_integrity"
    );
    let locations = serious["locations"].as_array().unwrap();
    assert_eq!(locations.len(), 1);
    assert_eq!(
        locations[0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/orders%20%23100%25.rs"
    );
    assert_eq!(
        locations[0]["physicalLocation"]["region"],
        json!({"startLine": 10, "endLine": 14})
    );
    let supporting = serious["relatedLocations"].as_array().unwrap();
    assert_eq!(supporting.len(), 1);
    assert_eq!(
        supporting[0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/%C3%A9.rs"
    );
    assert_eq!(
        supporting[0]["physicalLocation"]["region"],
        json!({"startLine": 20, "endLine": 20})
    );
    let refs = serious["properties"]["evidenceReferences"]
        .as_array()
        .unwrap();
    assert_eq!(refs[3]["locationStatus"], "DIFFERENT_COMMIT");
    assert_eq!(refs[4]["locationStatus"], "INVALID_COMMIT");
    assert_eq!(refs[5]["locationStatus"], "COMMIT_UNAVAILABLE");
    assert_eq!(refs[6]["locationStatus"], "UNVERIFIED_PROVENANCE");
    assert_eq!(refs[7]["locationStatus"], "UNVERIFIED_PROVENANCE");
    assert_eq!(refs[8]["locationStatus"], "COMPANION_REPOSITORY");
    assert_eq!(refs[8]["companionRepository"], "acme/contracts");
    assert_eq!(refs[8]["commitSha"], HEAD);
    assert_eq!(refs[9]["locationStatus"], "COMPANION_REPOSITORY");
    for reference in &refs[10..21] {
        assert_eq!(reference["locationStatus"], "INVALID_PATH");
    }
    for reference in &refs[21..24] {
        assert_eq!(reference["locationStatus"], "INVALID_REGION");
    }
    assert_eq!(refs[24]["locationStatus"], "NON_CODE_REFERENCE");
    assert_eq!(run["results"][1]["level"], "warning");
    assert_eq!(run["results"][1]["locations"], json!([]));
    assert!(run["results"][1].get("relatedLocations").is_none());
    assert_eq!(
        run["results"][1]["properties"]["locationStatus"],
        "NO_VERIFIED_REVIEWED_LOCATION"
    );
    // The retained fingerprint passes through beside the occurrence ID, and
    // the older finding without one gets none.
    assert_eq!(
        serious["partialFingerprints"],
        json!({"prooflineFinding/v1": FINGERPRINT})
    );
    assert!(run["results"][1].get("partialFingerprints").is_none());
    for result in run["results"].as_array().unwrap() {
        assert!(result.get("guid").is_none());
        assert!(result.get("fingerprints").is_none());
        assert!(result.get("correlationGuid").is_none());
    }
    // Re-exporting this immutable occurrence keeps its ID and bytes. Only the
    // retained fingerprint, never the occurrence ID, links it to a later run.
    let second = export(&origin).await;
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    console.assert_reads(2, ORG);
}

#[tokio::test]
async fn sarif_keeps_partial_findings_and_names_every_gap_with_exit_two() {
    let schema = schema();
    for status in [
        "COMPLETED",
        "PENDING",
        "RUNNING",
        "FAILED",
        "STOPPED",
        "UNRECOGNIZED",
    ] {
        let mut document = review(vec![finding(
            1,
            "WARNING",
            vec![code("src/orders.rs", 5, None)],
        )]);
        document["status"] = json!(status);
        document["assessments"][0]["status"] = json!("INCOMPLETE");
        document["assessments"][0]["incompleteness_kind"] = json!("WORLD_UNAVAILABLE");
        document["assessments"][0]["reason_codes"] =
            json!(["WORLD_UNAVAILABLE", "WORLD_UNAVAILABLE", LITERAL_REASON]);
        document["assessments"][0]["release_evidence_gap"] = json!("RELEASE_EVIDENCE_ABSENT");
        document["assessments"][0]["checks"]["receipt_recorded"] = json!(false);
        let console = Console::new(document);
        let origin = serve(console.clone()).await;
        let output = if status == "RUNNING" {
            cli(
                &origin,
                ORG,
                TOKEN,
                &[
                    "findings",
                    "--review",
                    REVIEW,
                    "--sarif",
                    "--wait",
                    "--timeout",
                    "0",
                ],
            )
            .await
        } else {
            export(&origin).await
        };
        assert_eq!(output.status.code(), Some(2), "status: {status}");
        let document = report(&output, &schema);
        let run = &document["runs"][0];
        assert_eq!(run["properties"]["reviewStatus"], status);
        assert_eq!(run["properties"]["reviewId"], REVIEW);
        assert_eq!(run["invocations"][0]["executionSuccessful"], false);
        assert_eq!(run["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            run["results"][0]["properties"]["findingId"],
            finding(1, "WARNING", Vec::new())["id"]
        );
        let notifications = run["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert_eq!(notifications.len(), 5);
        for reason in [
            "WORLD_UNAVAILABLE",
            "CHECK_RECEIPT_ABSENT",
            "RELEASE_EVIDENCE_ABSENT",
            LITERAL_REASON,
        ] {
            assert_eq!(
                notifications
                    .iter()
                    .filter(|notice| notice["properties"]["reasonCode"] == reason)
                    .count(),
                1
            );
        }
        let literal_notice = notifications
            .iter()
            .find(|notice| notice["properties"]["reasonCode"] == LITERAL_REASON)
            .unwrap();
        assert_eq!(
            literal_notice["message"]["text"],
            format!("{ESCAPED_ENVIRONMENT}: {ESCAPED_REASON}")
        );
        for notice in notifications {
            assert!(notice["message"].get("arguments").is_none());
            assert!(notice["message"].get("markdown").is_none());
        }
        assert_eq!(
            run["properties"]["assessments"][0]["environment"],
            ENVIRONMENT
        );
        console.assert_reads(1, ORG);
    }
    let mut missing_assessment = review(Vec::new());
    missing_assessment["assessment_count"] = json!(2);
    let mut no_assessments = review(Vec::new());
    no_assessments["assessment_count"] = json!(0);
    no_assessments["assessments"] = json!([]);
    for document in [missing_assessment, no_assessments] {
        let console = Console::new(document);
        let output = export(&serve(console.clone()).await).await;
        assert_eq!(output.status.code(), Some(2));
        let document = report(&output, &schema);
        assert_eq!(
            document["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(
            document["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["properties"]["reasonCode"],
            "REVIEW_RESULT_INCOMPLETE"
        );
        console.assert_reads(1, ORG);
    }
}

#[tokio::test]
async fn sarif_authentication_and_scope_refusals_emit_no_result_or_fallback() {
    for (status, organization, token) in [
        (StatusCode::UNAUTHORIZED, ORG, TOKEN),
        (StatusCode::FORBIDDEN, ORG, TOKEN),
        (StatusCode::NOT_FOUND, ORG, TOKEN),
        (StatusCode::OK, OTHER_ORG, TOKEN),
        (StatusCode::OK, ORG, "pld_wrongtoken"),
    ] {
        let mut console = Console::new(review(Vec::new()));
        console.status = status;
        let origin = serve(console.clone()).await;
        let output = cli(
            &origin,
            organization,
            token,
            &["findings", "--review", REVIEW, "--sarif"],
        )
        .await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("This token cannot read the requested review."));
        assert!(!stderr.contains(token));
        console.assert_reads(1, organization);
    }
}

#[tokio::test]
async fn sarif_refuses_unpinned_or_unrecognized_records_before_writing_output() {
    let mut records = Vec::new();
    let mut wrong_review = review(Vec::new());
    wrong_review["id"] = json!(ASSESSMENT);
    records.push((wrong_review, "server returned review"));
    for head in [Value::Null, json!("main"), json!(format!(" {HEAD}"))] {
        let mut document = review(Vec::new());
        document["head_commit_sha"] = head;
        records.push((document, "does not record a full commit SHA"));
    }
    let mut deployment = review(Vec::new());
    deployment["kind"] = json!("DEPLOYMENT_GATE");
    records.push((deployment, "requires a retained pull-request review"));
    for (field, value, expected) in [
        ("severity", "CRITICAL", "unsupported severity"),
        (
            "risk_domain",
            "unrecognized_domain",
            "unsupported risk domain",
        ),
    ] {
        let mut document = review(vec![
            finding(1, "WARNING", Vec::new()),
            finding(2, "WARNING", Vec::new()),
        ]);
        document["assessments"][0]["findings"][1][field] = json!(value);
        records.push((document, expected));
    }
    // Only the exact withheld marker makes a CODE record unavailable.
    let mut code_domain = code_review();
    code_domain["code_assessment"]["findings"][0]["risk_domain"] = json!("unrecognized_domain");
    records.push((code_domain, "unsupported risk domain"));
    for (document, expected) in records {
        let console = Console::new(document);
        let output = export(&serve(console.clone()).await).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(expected), "stderr: {stderr}");
        assert!(!stderr.contains(PRIVATE_VALUE));
        console.assert_reads(1, ORG);
    }
    let mut wrong_running_review = review(Vec::new());
    wrong_running_review["id"] = json!(ASSESSMENT);
    wrong_running_review["status"] = json!("RUNNING");
    let console = Console::new(wrong_running_review);
    let origin = serve(console.clone()).await;
    let output = cli(
        &origin,
        ORG,
        TOKEN,
        &["findings", "--review", REVIEW, "--sarif", "--wait"],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    console.assert_reads(1, ORG);
}

#[tokio::test]
async fn sarif_usage_errors_are_rejected_before_reading_a_review() {
    let console = Console::new(review(Vec::new()));
    let origin = serve(console.clone()).await;
    for args in [
        vec!["findings", "--sarif"],
        vec!["findings", "--pr", "42", "--sarif"],
        vec!["findings", "--head", HEAD, "--sarif"],
        vec!["findings", "--review", REVIEW, "--json", "--sarif"],
        vec!["review", "--pr", "42", "--sarif"],
    ] {
        let output = cli(&origin, ORG, TOKEN, &args).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    assert!(console.requests.lock().unwrap().is_empty());
}
