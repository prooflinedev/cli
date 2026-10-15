//! Holds the CLI's API types to the bundled public contract.

use std::path::PathBuf;
use std::process::Command;

use proofline_cli::model::{
    Assessment, Check, Checks, CodeAssessment, CommitReviewRequest, CommitReviewResponse,
    EvidenceRef, FileReviewRequest, FileReviewResponse, FileScope, FilterChoice, Finding,
    OpenItems, PatchReviewRequest, PatchReviewResponse, RepositoryName, RepositoryNames,
    ReviewDetail, ReviewFilters, ReviewPage, ReviewSubject, ReviewSummary, RunNowMode,
    RunNowRequest, RunNowResponse, StopResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

fn saas() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(saas().join("openapi.public.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn schema<'a>(document: &'a Value, name: &str) -> &'a Value {
    document["components"]["schemas"]
        .get(name)
        .unwrap_or_else(|| panic!("the public contract has no schema {name}"))
}

fn resolve<'a>(document: &'a Value, node: &'a Value) -> &'a Value {
    // A described property wraps its reference in a one-item `allOf`.
    let node = match node
        .get("allOf")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([only]) => only,
        _ => node,
    };
    node.get("$ref")
        .and_then(Value::as_str)
        .map_or(node, |reference| {
            schema(
                document,
                reference.trim_start_matches("#/components/schemas/"),
            )
        })
}

/// An instance of `node`: only required properties when `full` is false,
/// with nullable values null, or every property with a non-null value.
fn instance(document: &Value, node: &Value, full: bool, depth: usize) -> Value {
    assert!(depth < 24, "the contract nests deeper than expected");
    // Recursive schemas, such as a causal graph, stop at their required fields.
    let full = full && depth < 6;
    let node = resolve(document, node);
    if let Some(constant) = node.get("const") {
        return constant.clone();
    }
    if let Some(values) = node.get("enum").and_then(Value::as_array) {
        return values[0].clone();
    }
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(options) = node.get(key).and_then(Value::as_array) {
            let pick = options
                .iter()
                .find(|option| resolve(document, option).get("type") != Some(&json!("null")))
                .unwrap_or(&options[0]);
            if !full
                && options
                    .iter()
                    .any(|option| option.get("type") == Some(&json!("null")))
            {
                return Value::Null;
            }
            return instance(document, pick, full, depth + 1);
        }
    }
    let kind = match node.get("type") {
        Some(Value::Array(kinds)) => {
            if !full && kinds.contains(&json!("null")) {
                return Value::Null;
            }
            kinds
                .iter()
                .find(|kind| *kind != "null")
                .cloned()
                .unwrap_or(Value::Null)
        }
        Some(kind) => kind.clone(),
        None if node.get("properties").is_some() => json!("object"),
        None => return json!({}),
    };
    match kind.as_str() {
        Some("object") => {
            let required: Vec<&str> = node
                .get("required")
                .and_then(Value::as_array)
                .map(|names| names.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut object = Map::new();
            if let Some(properties) = node.get("properties").and_then(Value::as_object) {
                for (name, property) in properties {
                    if full || required.contains(&name.as_str()) {
                        object.insert(name.clone(), instance(document, property, full, depth + 1));
                    }
                }
            }
            Value::Object(object)
        }
        Some("array") => json!([instance(document, &node["items"], full, depth + 1)]),
        Some("string") => match node.get("format").and_then(Value::as_str) {
            Some("uuid") => json!("00000000-0000-0000-0000-000000000001"),
            Some("date-time") => json!("2026-01-01T00:00:00Z"),
            _ => json!("text"),
        },
        Some("integer") => json!(1),
        Some("number") => json!(1.5),
        Some("boolean") => json!(true),
        _ => Value::Null,
    }
}

/// The CLI type reads both the smallest and the fullest document the
/// contract allows, and names no field the contract lacks.
fn holds<T: DeserializeOwned + Serialize>(name: &str) {
    let document = contract();
    let node = schema(&document, name);
    let properties = node["properties"].as_object().unwrap();
    for full in [false, true] {
        let value = instance(&document, node, full, 0);
        let typed: T = serde_json::from_value(value.clone()).unwrap_or_else(|error| {
            panic!("{name} (full: {full}) does not decode: {error}\n{value:#}")
        });
        let back = serde_json::to_value(&typed).unwrap();
        for field in back.as_object().unwrap().keys() {
            assert!(
                properties.contains_key(field),
                "{name} has no field {field}"
            );
        }
    }
}

#[test]
fn types_match_the_public_contract() {
    holds::<ReviewPage>("ReviewPage");
    holds::<ReviewFilters>("ReviewFilters");
    holds::<FilterChoice>("FilterChoice");
    holds::<RepositoryNames>("RepositoryNames");
    holds::<RepositoryName>("RepositoryName");
    holds::<ReviewSummary>("ReviewSummary");
    holds::<ReviewDetail>("CustomerReviewDetail");
    holds::<OpenItems>("OpenItemsView");
    holds::<Assessment>("CustomerAssessment");
    holds::<CodeAssessment>("CustomerCodeAssessment");
    holds::<Checks>("CustomerChecks");
    holds::<Check>("CustomerCheck");
    holds::<Finding>("CustomerFinding");
    holds::<EvidenceRef>("CustomerEvidenceRef");
    holds::<RunNowRequest>("RunNowRequest");
    holds::<RunNowResponse>("RunNowResponse");
    holds::<PatchReviewRequest>("PatchReviewRequest");
    holds::<PatchReviewResponse>("PatchReviewResponse");
    holds::<CommitReviewRequest>("CommitReviewRequest");
    holds::<CommitReviewResponse>("CommitReviewResponse");
    holds::<StopResponse>("StopResponse");
    holds::<FileReviewRequest>("FileReviewRequest");
    holds::<FileReviewResponse>("FileReviewResponse");
    holds::<FileScope>("FileScope");
    holds::<ReviewSubject>("SubjectView");

    // Schema display has no console, credentials or checkout to read. It uses
    // the bundled public contract, even when the configured origin is invalid.
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_proofline"))
        .args(["--base-url", "not-a-console", "review", "--schema"])
        .env_remove("PROOFLINE_TOKEN")
        .env_remove("PROOFLINE_ORGANIZATION_ID")
        .env("PATH", "")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result_schema: Value = serde_json::from_slice(&output.stdout).unwrap();
    let validator = jsonschema::validator_for(&result_schema).unwrap();
    let public = contract();
    for (name, definition) in result_schema["$defs"].as_object().unwrap() {
        let original = serde_json::to_string(definition)
            .unwrap()
            .replace("#/$defs/", "#/components/schemas/");
        assert_eq!(
            serde_json::from_str::<Value>(&original).unwrap(),
            *schema(&public, name),
            "the CLI changes the public definition {name}"
        );
    }
    for full in [false, true] {
        let review = instance(&public, schema(&public, "CustomerReviewDetail"), full, 0);
        let mut result = json!({
            "schema": "proofline.review-result.v1",
            "outcome": null,
            "review_url": "https://console.proofline.example/reviews/retained",
            "review": review,
        });
        // Compatible API additions remain part of the raw result.
        result["review"]["a_compatible_addition"] = json!({"retained": true});
        validator.validate(&result).unwrap();
        for (field, value) in [
            ("schema", json!("proofline.review-result.v2")),
            ("outcome", json!("SAFE")),
            ("review", json!([])),
        ] {
            let mut invalid = result.clone();
            invalid[field] = value;
            assert!(!validator.is_valid(&invalid), "{invalid:#}");
        }
        result.as_object_mut().unwrap().remove("schema");
        assert!(!validator.is_valid(&result), "{result:#}");
    }
}

#[test]
fn operations_the_cli_calls_exist() {
    let document = contract();
    for (method, path) in [
        ("get", "/api/v1/organizations/{org_id}/reviews"),
        ("get", "/api/v1/organizations/{org_id}/reviews/{review_id}"),
        ("get", "/api/v1/organizations/{org_id}/repository-names"),
        (
            "post",
            "/api/v1/organizations/{org_id}/reviews/{review_id}/stop",
        ),
        (
            "post",
            "/api/v1/organizations/{org_id}/repositories/{repo_id}/pull-requests/{number}/review",
        ),
        (
            "post",
            "/api/v1/organizations/{org_id}/repositories/{repo_id}/patch-reviews",
        ),
        (
            "post",
            "/api/v1/organizations/{org_id}/repositories/{repo_id}/commit-reviews",
        ),
        (
            "post",
            "/api/v1/organizations/{org_id}/repositories/{repo_id}/file-reviews",
        ),
    ] {
        assert!(
            document["paths"][path][method].is_object(),
            "the public contract lacks {method} {path}"
        );
    }
    let detail = &document["paths"]["/api/v1/organizations/{org_id}/reviews/{review_id}"]["get"]["responses"]
        ["200"]["content"]["application/json"]["schema"];
    assert_eq!(
        resolve(&document, detail),
        schema(&document, "CustomerReviewDetail")
    );
    let list = &document["paths"]["/api/v1/organizations/{org_id}/reviews"]["get"]["parameters"];
    for name in ["repository", "search", "cursor", "limit"] {
        assert!(
            list.as_array()
                .unwrap()
                .iter()
                .any(|parameter| parameter["name"] == name),
            "the review list lacks the {name} parameter"
        );
    }
    let operation = &document["paths"]["/api/v1/organizations/{org_id}/repositories/{repo_id}/pull-requests/{number}/review"]
        ["post"];
    let body = &operation["requestBody"];
    assert_ne!(body["required"], true, "the default request has no body");
    let request = resolve(&document, &body["content"]["application/json"]["schema"]);
    assert_eq!(request, schema(&document, "RunNowRequest"));
    assert_eq!(request["additionalProperties"], false);
    assert!(
        request["required"].is_null()
            || !request["required"]
                .as_array()
                .unwrap()
                .contains(&json!("mode"))
    );
    let mode = resolve(&document, &request["properties"]["mode"]);
    assert_eq!(
        mode["enum"],
        json!([
            serde_json::to_value(RunNowMode::ExistingOrNew).unwrap(),
            serde_json::to_value(RunNowMode::Full).unwrap(),
            serde_json::to_value(RunNowMode::Extended).unwrap(),
        ])
    );
    assert_eq!(
        serde_json::from_value::<RunNowRequest>(json!({}))
            .unwrap()
            .mode,
        RunNowMode::ExistingOrNew
    );
    for invalid in [
        json!({"mode": null}),
        json!({"mode": "INCREMENTAL"}),
        json!({"mode": "FULL", "head_sha": "caller-chosen"}),
    ] {
        assert!(serde_json::from_value::<RunNowRequest>(invalid).is_err());
    }
}

#[test]
fn review_requests_preserve_deep_focus_and_omit_absent_focus() {
    for wire in [
        json!({}),
        json!({"mode":"FULL"}),
        json!({"mode":"FULL","focus_text":null}),
    ] {
        let request: RunNowRequest = serde_json::from_value(wire).unwrap();
        assert!(request.focus_text.is_none());
        assert!(
            serde_json::to_value(request)
                .unwrap()
                .get("focus_text")
                .is_none()
        );
    }
    let wire = json!({"mode":"EXTENDED","focus_text":"Verify tenant authorization"});
    let request: RunNowRequest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(request.mode, RunNowMode::Extended);
    assert_eq!(
        request.focus_text.as_deref(),
        Some("Verify tenant authorization")
    );
    assert_eq!(serde_json::to_value(request).unwrap(), wire);
    assert!(
        serde_json::from_value::<RunNowRequest>(json!({"mode":"EXTENDED","focus_text":42}))
            .is_err()
    );
}
