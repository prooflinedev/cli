//! Generate URL builders for the public operations used by declared CLI commands.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;
use std::{env, fs, path::Path, path::PathBuf};

use serde_json::Value;

// Argument order belongs to the caller. Segment order comes from OpenAPI.
const OPERATIONS: &[(&str, &str, &[&str])] = &[
    ("get", "export_reviews", &["dataset"]),
    ("get", "get_agent_session", &["session_id"]),
    ("get", "get_agent_session_prompt", &["finding_id"]),
    ("get", "get_finding_fix_prompt", &["finding_id"]),
    (
        "get",
        "get_pull_request_review",
        &["repository", "pull_request_number", "run_number"],
    ),
    ("get", "get_review", &["review_id"]),
    ("get", "get_review_guidance", &["repo_id"]),
    ("get", "get_review_routing", &["review_id"]),
    (
        "get",
        "list_pull_request_reviews",
        &["repository", "pull_request_number"],
    ),
    ("get", "list_repositories", &[]),
    ("get", "list_reviews", &[]),
    ("post", "request_commit_review", &["repo_id"]),
    ("post", "request_file_review", &["repo_id"]),
    ("post", "request_patch_review", &["repo_id"]),
    ("post", "request_review", &["repo_id", "number"]),
    ("post", "rerun_review", &["review_id"]),
    ("post", "start_agent_session", &["finding_id"]),
    ("post", "stop_review", &["review_id"]),
    ("post", "upload_coverage_reports", &["repo_id"]),
];

// A source checkout keeps the public contract beside the SDKs, and this
// crate's distribution carries it at the crate root. The checkout's comes
// first, so a stale copy at the crate root is never built there. Sources and
// tests read the copy written to OUT_DIR.
const CONTRACTS: [&str; 2] = ["../clients/sdk/openapi.public.json", "openapi.public.json"];

fn main() -> Result<(), Box<dyn Error>> {
    let contract = CONTRACTS
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .ok_or("missing the public API contract")?;
    println!("cargo::rerun-if-changed={}", contract.display());
    println!("cargo::rerun-if-changed=build.rs");
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing Cargo output directory")?);
    let raw = fs::read(contract)?;
    fs::write(output.join("openapi.public.json"), &raw)?;
    let document: Value = serde_json::from_slice(&raw)?;
    let mut routes = BTreeMap::new();
    for (path, item) in document["paths"]
        .as_object()
        .ok_or("missing public paths")?
    {
        for (method, operation) in item.as_object().ok_or("invalid public path")? {
            if let Some(id) = operation["operationId"].as_str()
                && routes
                    .insert(id, (method.as_str(), path.as_str()))
                    .is_some()
            {
                return Err(format!("duplicate public operation {id}").into());
            }
        }
    }
    let mut code = String::from("impl Api {\n");
    for &(verb, name, parameters) in OPERATIONS {
        let &(method, path) = routes
            .get(name)
            .ok_or_else(|| format!("missing public operation {name}"))?;
        if method != verb {
            return Err(format!("HTTP method changed for {name}").into());
        }
        let tail = path
            .strip_prefix("/api/v1/organizations/{org_id}/")
            .ok_or_else(|| format!("{name} must use an organization-scoped route"))?;
        let mut arguments = BTreeSet::new();
        let mut segments = Vec::new();
        for segment in tail.split('/') {
            if let Some(parameter) = segment
                .strip_prefix('{')
                .and_then(|part| part.strip_suffix('}'))
            {
                arguments.insert(parameter);
                segments.push(parameter.to_owned());
            } else if !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                segments.push(format!("{segment:?}"));
            } else {
                return Err(format!("unsupported path segment for {name}").into());
            }
        }
        if arguments != parameters.iter().copied().collect() {
            return Err(format!("path arguments changed for {name}").into());
        }
        let signature = parameters
            .iter()
            .map(|p| format!(", {p}: &str"))
            .collect::<String>();
        writeln!(
            code,
            "pub(crate) fn url_{name}(&self{signature}) -> Url {{ self.url(&[{}]) }}",
            segments.join(", ")
        )?;
    }
    code.push_str("}\n");
    fs::write(output.join("routes.rs"), code)?;
    Ok(())
}
