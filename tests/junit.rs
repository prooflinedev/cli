//! Actual CLI processes read a retained review over HTTP, write `--junit`, and
//! the file is parsed by a strict XML reader and held to the `JUnit` report
//! structure CI systems read: `testsuites`, `testsuite`, `testcase`, and a
//! `failure` or `error` per case at most. That reader is the sole check. It
//! mirrors the content model of the Jenkins `junit-10.xsd`: a `testcase` holds
//! only `skipped`, `error`, `failure` and `system-out`, never `properties`.

use std::path::Path;
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::process::Command;
use uuid::Uuid;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000f0";
const REVIEW: &str = "0190f3a0-0000-7000-8000-000000000033";
const OTHER_REVIEW: &str = "0190f3a0-0000-7000-8000-000000000034";
const ASSESSMENT: &str = "0190f3a0-0000-7000-8000-000000000044";
const CODE_ASSESSMENT: &str = "0190f3a0-0000-7000-8000-000000000055";
const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
const BASE: &str = "89abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "pld_junitsynthetictoken";
const PRIVATE_VALUE: &str = "raw-world-evidence-and-operator-diagnostics";
// The hostile text of tests/sarif.rs, plus what only XML cares about: markup,
// quotes, a CDATA terminator, a carriage return and characters XML forbids.
const CLAIM: &str = "A retry can replay {0} with {{receipt}} from [label](0), \
    array[nested[0]] and C:\\orders\\receipt. </failure><x a=\"1\"/> 'q' & ]]> \r\nsecond line \u{1}\u{b}\u{fffe}end";
const CLEAN_CLAIM: &str = "A retry can replay {0} with {{receipt}} from [label](0), \
    array[nested[0]] and C:\\orders\\receipt. </failure><x a=\"1\"/> 'q' & ]]> \r\nsecond line end";
const ENVIRONMENT: &str = "production {0} [overview](0)\\primary \"quoted\" <b>&amp;</b>\u{2}";
const CLEAN_ENVIRONMENT: &str =
    "environment: production {0} [overview](0)\\primary \"quoted\" <b>&amp;</b>";
const FINGERPRINT: &str = "5f3c9a7e1b2d4c6a8e0f9b1d3a5c7e9f2b4d6a8c0e1f3a5b7d9c2e4f6a8b0c1d";

#[derive(Clone)]
struct Console {
    document: Value,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn detail(State(console): State<Console>, headers: HeaderMap) -> Response {
    console.requests.lock().unwrap().push("detail".to_owned());
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(format!("Bearer {TOKEN}").as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(console.document).into_response()
}

async fn serve(document: Value) -> (String, Arc<Mutex<Vec<String>>>) {
    let console = Console {
        document,
        requests: Arc::default(),
    };
    let requests = console.requests.clone();
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{ORG}/repository-names"),
            get(|| async {
                Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/web" }] }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews"),
            get(|| async {
                Json(json!({
                    "items": [{
                        "id": REVIEW,
                        "kind": "PULL_REQUEST",
                        "status": "COMPLETED",
                        "created_at": "2026-10-01T00:00:00Z",
                        "head_commit_sha": HEAD,
                        "pull_request_number": 42,
                        "repository_id": REPOSITORY,
                        "run_number": 7,
                    }],
                    "next_cursor": null,
                    "truncated": false,
                    "filters": { "repositories": [] },
                }))
            }),
        )
        .route(
            &format!("/api/v1/organizations/{ORG}/reviews/{REVIEW}"),
            get(detail),
        )
        .with_state(console);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), requests)
}

/// `proofline ci review --junit FILE`, with any extra arguments.
async fn ci(origin: &str, report: &Path, extra: &[&str]) -> Output {
    ci_waiting(origin, report, "0", extra).await
}

/// Like `ci`, with a poll timeout in minutes.
async fn ci_waiting(origin: &str, report: &Path, minutes: &str, extra: &[&str]) -> Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        Command::new(env!("CARGO_BIN_EXE_proofline"))
            .args(["--base-url", origin, "--org", ORG, "ci", "review"])
            .args(["--repo", "acme/web", "--timeout", minutes, "--commit", HEAD])
            .arg("--junit")
            .arg(report)
            .args(extra)
            .env("PROOFLINE_TOKEN", TOKEN)
            .env_remove("GITHUB_SHA")
            .env("PATH", "")
            .current_dir(std::env::temp_dir())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

/// Runs the CLI against `document`, returning its output and the report.
async fn export(document: Value, extra: &[&str]) -> (Output, Option<String>) {
    let (origin, _) = serve(document).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.xml");
    let output = ci(&origin, &path, extra).await;
    let report = std::fs::read_to_string(&path).ok();
    if let Some(report) = &report {
        assert!(!report.contains(TOKEN));
        assert!(!report.contains(PRIVATE_VALUE), "{report}");
    }
    (output, report)
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
        "lifecycle_state": "NEW",
        "remediation": "Make the order receipt idempotent.",
        "evidence_refs": refs,
        "evidence_values": PRIVATE_VALUE,
        "operator_diagnostics": PRIVATE_VALUE,
    })
}

fn decided(number: u128, decision: &str) -> Value {
    let mut recorded = finding(number, "SERIOUS", Vec::new());
    recorded["validation"] = json!(decision);
    recorded
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
        "open_items": { "open_findings": 1, "serious_findings": 1 },
        "assessments": [{
            "id": ASSESSMENT,
            "environment_display_name": ENVIRONMENT,
            "status": "COMPLETED",
            "findings": findings,
            "checks": {
                "receipt_recorded": true,
                "status": "READY",
                "families": [
                    { "name": "deployment", "outcome": "READY", "lifecycle": "GATING" },
                    { "name": "capacity", "outcome": "NOT_APPLICABLE", "lifecycle": "GATING" },
                    {
                        "name": "iam",
                        "outcome": "BLOCKED",
                        "lifecycle": "GATING",
                        "detail": PRIVATE_VALUE,
                    },
                ],
            },
            "reviewer_version": PRIVATE_VALUE,
            "world_evidence_values": PRIVATE_VALUE,
        }],
        "operator_diagnostics": PRIVATE_VALUE,
    })
}

fn code_review(findings: Vec<Value>) -> Value {
    let mut document = review(Vec::new());
    document["base_commit_sha"] = json!(BASE);
    document["assessment_count"] = json!(0);
    document["assessments"] = json!([]);
    document["code_assessment"] = json!({
        "id": CODE_ASSESSMENT,
        "status": "COMPLETED",
        "base_commit_sha": BASE,
        "head_commit_sha": HEAD,
        "incompleteness_kind": null,
        "findings": findings,
    });
    document
}

// A strict XML 1.0 reader for the subset a report uses. It rejects what a
// real parser would normalize or refuse: raw control characters, a raw `<` or
// line break in an attribute, `]]>` in text, CDATA, comments, unknown
// entities and mismatched tags.

#[derive(Debug)]
struct Node {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Self>,
    text: String,
}

impl Node {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Self> {
        self.children.iter().filter(move |child| child.name == name)
    }

    fn one<'a>(&'a self, name: &'a str) -> &'a Self {
        let mut found = self.all(name);
        let node = found.next().unwrap_or_else(|| panic!("no <{name}>"));
        assert!(found.next().is_none(), "two <{name}>");
        node
    }
}

struct Reader {
    characters: Vec<char>,
    at: usize,
}

fn xml_char(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

impl Reader {
    fn peek(&self) -> Option<char> {
        self.characters.get(self.at).copied()
    }

    fn starts_with(&self, prefix: &str) -> bool {
        prefix
            .chars()
            .enumerate()
            .all(|(offset, ch)| self.characters.get(self.at + offset) == Some(&ch))
    }

    fn expect(&mut self, prefix: &str) {
        assert!(
            self.starts_with(prefix),
            "expected {prefix:?} at {}",
            self.at
        );
        self.at += prefix.chars().count();
    }

    fn name(&mut self) -> String {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
        {
            self.at += 1;
        }
        assert!(self.at > start, "expected a name at {start}");
        self.characters[start..self.at].iter().collect()
    }

    fn reference(&mut self) -> char {
        self.expect("&");
        let start = self.at;
        while self.peek().is_some_and(|ch| ch != ';') {
            self.at += 1;
        }
        let entity: String = self.characters[start..self.at].iter().collect();
        self.expect(";");
        let character = match entity.as_str() {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            other => {
                let code = other
                    .strip_prefix("#x")
                    .map(|hex| u32::from_str_radix(hex, 16).unwrap())
                    .or_else(|| {
                        other
                            .strip_prefix('#')
                            .map(|digits| digits.parse().unwrap())
                    })
                    .unwrap_or_else(|| panic!("unknown entity &{other};"));
                char::from_u32(code).unwrap()
            }
        };
        assert!(xml_char(character), "reference to a forbidden character");
        character
    }

    fn value(&mut self) -> String {
        self.expect("\"");
        let mut value = String::new();
        loop {
            let ch = self.peek().expect("unterminated attribute");
            assert!(xml_char(ch), "forbidden character {ch:?} in an attribute");
            match ch {
                '"' => break,
                '<' | '\t' | '\n' | '\r' => panic!("raw {ch:?} in an attribute"),
                '&' => value.push(self.reference()),
                _ => {
                    value.push(ch);
                    self.at += 1;
                }
            }
        }
        self.expect("\"");
        value
    }

    fn element(&mut self) -> Node {
        self.expect("<");
        let name = self.name();
        let mut attributes: Vec<(String, String)> = Vec::new();
        while self.peek() == Some(' ') {
            self.at += 1;
            let key = self.name();
            self.expect("=");
            assert!(
                attributes.iter().all(|(seen, _)| *seen != key),
                "duplicate attribute {key}"
            );
            attributes.push((key, self.value()));
        }
        let mut node = Node {
            name,
            attributes,
            children: Vec::new(),
            text: String::new(),
        };
        if self.starts_with("/>") {
            self.expect("/>");
            return node;
        }
        self.expect(">");
        loop {
            assert!(
                !self.starts_with("<!") && !self.starts_with("<?"),
                "markup declaration"
            );
            assert!(!self.starts_with("]]>"), "]]> in text");
            match self.peek().expect("unterminated element") {
                '<' if self.starts_with("</") => break,
                '<' => node.children.push(self.element()),
                '&' => node.text.push(self.reference()),
                ch => {
                    assert!(
                        xml_char(ch) && ch != '\r',
                        "forbidden character {ch:?} in text"
                    );
                    node.text.push(ch);
                    self.at += 1;
                }
            }
        }
        self.expect("</");
        assert_eq!(self.name(), node.name, "mismatched end tag");
        self.expect(">");
        node
    }
}

fn parse(xml: &str) -> Node {
    let mut reader = Reader {
        characters: xml.chars().collect(),
        at: 0,
    };
    reader.expect("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let root = reader.element();
    while reader.peek().is_some_and(char::is_whitespace) {
        reader.at += 1;
    }
    assert_eq!(reader.at, reader.characters.len(), "content after the root");
    root
}

fn only_attributes(node: &Node, allowed: &[&str], required: &[&str]) {
    for (key, _) in &node.attributes {
        assert!(allowed.contains(&key.as_str()), "<{}> has {key}", node.name);
    }
    for key in required {
        assert!(node.attribute(key).is_some(), "<{}> lacks {key}", node.name);
    }
}

fn count(node: &Node, key: &str) -> usize {
    node.attribute(key).unwrap().parse().unwrap()
}

/// The `JUnit` report structure: the elements and attributes the Jenkins `JUnit`
/// schema allows, and counts that match the cases beneath them.
fn validate(root: &Node) {
    assert_eq!(root.name, "testsuites");
    only_attributes(
        root,
        &["name", "time", "tests", "failures", "disabled", "errors"],
        &[],
    );
    assert_eq!(root.attribute("name"), Some("proofline"));
    assert!(root.text.trim().is_empty());
    let (mut tests, mut failures, mut errors) = (0, 0, 0);
    for suite in &root.children {
        assert_eq!(suite.name, "testsuite");
        only_attributes(
            suite,
            &[
                "name",
                "tests",
                "failures",
                "errors",
                "time",
                "disabled",
                "skipped",
                "timestamp",
                "hostname",
                "id",
                "package",
            ],
            &["name", "tests"],
        );
        let cases: Vec<&Node> = suite.all("testcase").collect();
        assert!(suite.text.trim().is_empty());
        for child in &suite.children {
            assert!(matches!(child.name.as_str(), "properties" | "testcase"));
        }
        assert_eq!(count(suite, "tests"), cases.len());
        let ended = |name: &str| {
            cases
                .iter()
                .filter(|case| case.all(name).count() == 1)
                .count()
        };
        assert_eq!(count(suite, "failures"), ended("failure"));
        assert_eq!(count(suite, "errors"), ended("error"));
        assert_eq!(count(suite, "skipped"), ended("skipped"));
        for properties in suite.all("properties") {
            for property in &properties.children {
                assert_eq!(property.name, "property");
                only_attributes(property, &["name", "value"], &["name", "value"]);
            }
        }
        for case in cases {
            only_attributes(case, &["name", "classname"], &["name"]);
            let outcomes = ["skipped", "error", "failure"]
                .iter()
                .map(|name| case.all(name).count())
                .sum::<usize>();
            assert!(outcomes <= 1, "{case:?}");
            for child in &case.children {
                match child.name.as_str() {
                    "failure" | "error" => only_attributes(child, &["message", "type"], &[]),
                    "skipped" => only_attributes(child, &["message"], &[]),
                    "system-out" => only_attributes(child, &[], &[]),
                    other => panic!("<testcase> has <{other}>"),
                }
            }
        }
        tests += count(suite, "tests");
        failures += count(suite, "failures");
        errors += count(suite, "errors");
    }
    assert_eq!(count(root, "tests"), tests);
    assert_eq!(count(root, "failures"), failures);
    assert_eq!(count(root, "errors"), errors);
}

fn report(xml: &str) -> Node {
    let root = parse(xml);
    validate(&root);
    root
}

fn suite<'a>(root: &'a Node, name: &str) -> &'a Node {
    root.children
        .iter()
        .find(|suite| suite.attribute("name") == Some(name))
        .unwrap_or_else(|| panic!("no suite {name}"))
}

fn case<'a>(suite: &'a Node, prefix: &str) -> &'a Node {
    let mut found = suite
        .all("testcase")
        .filter(|case| case.attribute("name").unwrap().starts_with(prefix));
    let case = found.next().unwrap_or_else(|| panic!("no case {prefix}"));
    assert!(found.next().is_none(), "two cases {prefix}");
    case
}

fn property<'a>(node: &'a Node, name: &str) -> Option<&'a str> {
    node.all("properties")
        .flat_map(|properties| properties.children.iter())
        .find(|property| property.attribute("name") == Some(name))
        .and_then(|property| property.attribute("value"))
}

#[tokio::test]
async fn an_open_finding_is_a_failure_with_its_location_and_claim() {
    let mut open = finding(
        1,
        "SERIOUS",
        vec![
            code("src/orders.rs", 10, Some(14)),
            code("src/receipt.rs", 3, None),
            // Not a verified read of this head: cited by no line.
            json!({ "kind": "companion_repository_file", "label": "other", "companion_repository": "acme/other" }),
        ],
    );
    open["finding_fingerprint"] = json!(FINGERPRINT);
    let (output, xml) = export(review(vec![open]), &[]).await;
    // The report does not change the exit code: no --fail-on, so findings pass.
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let xml = xml.unwrap();
    let root = report(&xml);
    let environment = suite(&root, CLEAN_ENVIRONMENT);
    assert_eq!(property(environment, "review_id"), Some(REVIEW));
    assert_eq!(property(environment, "head_commit_sha"), Some(HEAD));
    assert_eq!(property(environment, "lane"), Some("ENV"));
    assert_eq!(property(environment, "assessment_id"), Some(ASSESSMENT));
    let failing = case(environment, &format!("data_integrity {FINGERPRINT}"));
    let failure = failing.one("failure");
    assert_eq!(failure.attribute("type"), Some("SERIOUS"));
    // The title is the claim's first line, cut at the first line break.
    let title = CLEAN_CLAIM.lines().next().unwrap().trim();
    assert_eq!(failure.attribute("message"), Some(title));
    let id = Uuid::from_u128(0x0190_f3a0_0000_7000_8000_0000_0000_0101);
    let body = &failure.text;
    for expected in [
        format!("finding: {id}"),
        "domain: data_integrity".to_owned(),
        "cited: src/orders.rs:10-14".to_owned(),
        "cited: src/receipt.rs:3".to_owned(),
        format!("claim: {CLEAN_CLAIM}"),
    ] {
        assert!(body.contains(&expected), "{expected:?} not in {body:?}");
    }
    assert!(!body.contains("acme/other"));
    // Checks: ready passes, not applicable is skipped, blocked fails.
    assert!(case(environment, "check deployment").children.is_empty());
    assert_eq!(
        case(environment, "check capacity")
            .one("skipped")
            .attribute("message"),
        Some("NOT_APPLICABLE")
    );
    assert_eq!(
        case(environment, "check iam")
            .one("failure")
            .attribute("type"),
        Some("BLOCKED")
    );
    assert!(case(environment, "completeness").children.is_empty());
    assert_eq!(count(&root, "failures"), 2);
    assert_eq!(count(&root, "errors"), 0);
    // Without a fingerprint the occurrence ID names the case.
    let (_, xml) = export(review(vec![finding(1, "WARNING", Vec::new())]), &[]).await;
    let root = report(&xml.unwrap());
    let warned = case(
        suite(&root, CLEAN_ENVIRONMENT),
        &format!("data_integrity {id}"),
    );
    assert_eq!(warned.one("failure").attribute("type"), Some("WARNING"));
}

#[tokio::test]
async fn hostile_text_is_escaped_in_every_attribute_and_text_node() {
    let (_, xml) = export(review(vec![finding(1, "SERIOUS", Vec::new())]), &[]).await;
    let xml = xml.unwrap();
    // The strict reader above already refuses raw markup, control characters
    // and a bare `]]>`; check the bytes too.
    assert!(!xml.contains("<![CDATA["));
    assert!(!xml.contains("]]>"));
    assert!(!xml.contains('\r'));
    assert!(xml.chars().all(|ch| ch == '\n' || ch >= ' '));
    assert!(xml.contains("&lt;/failure&gt;&lt;x a=\"1\"/&gt;"));
    assert!(xml.contains("&quot;quoted&quot; &lt;b&gt;&amp;amp;&lt;/b&gt;"));
    let root = report(&xml);
    let environment = suite(&root, CLEAN_ENVIRONMENT);
    // The reader decodes it back to the original text, minus forbidden characters.
    assert!(
        case(environment, "data_integrity")
            .one("failure")
            .text
            .ends_with(CLEAN_CLAIM)
    );
}

#[tokio::test]
async fn dismissed_accepted_and_resolved_findings_do_not_fail() {
    let mut resolved = finding(3, "SERIOUS", Vec::new());
    resolved["lifecycle_state"] = json!("RESOLVED");
    let mut document = review(vec![
        decided(1, "DISMISSED"),
        decided(2, "ACCEPTED_RISK"),
        resolved,
        decided(4, "CONFIRMED"),
    ]);
    document["open_items"] = json!({ "open_findings": 1, "serious_findings": 1 });
    let (output, xml) = export(document, &["--fail-on", "warning"]).await;
    // The server counts one open finding, so --fail-on still decides the exit.
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let root = report(&xml.unwrap());
    let environment = suite(&root, CLEAN_ENVIRONMENT);
    for (number, state) in [(1, "dismissed"), (2, "accepted-risk"), (3, "resolved")] {
        let id = Uuid::from_u128(0x0190_f3a0_0000_7000_8000_0000_0000_0100 + number);
        let settled = case(environment, &format!("data_integrity {id}"));
        assert_eq!(settled.all("properties").count(), 0);
        let output = &settled.one("system-out").text;
        assert!(output.contains(&format!("state: {state}\n")), "{output}");
        assert!(output.contains(&format!("finding: {id}\n")), "{output}");
        assert_eq!(settled.all("failure").count(), 0);
    }
    // A confirmed finding is still open.
    let id = Uuid::from_u128(0x0190_f3a0_0000_7000_8000_0000_0000_0104);
    assert_eq!(
        case(environment, &format!("data_integrity {id}"))
            .all("failure")
            .count(),
        1
    );
    // Three settled findings and the blocked check: two failures in all.
    assert_eq!(count(&root, "failures"), 2);
}

#[tokio::test]
async fn the_report_is_independent_of_fail_on_and_the_exit_code() {
    let (origin, _) = serve(review(vec![finding(1, "SERIOUS", Vec::new())])).await;
    let directory = tempfile::tempdir().unwrap();
    let mut reports = Vec::new();
    for (extra, exit) in [
        (vec![], 0),
        (vec!["--fail-on", "serious"], 3),
        (vec!["--fail-on", "warning", "--json"], 3),
    ] {
        let path = directory
            .path()
            .join(format!("report-{}.xml", reports.len()));
        let output = ci(&origin, &path, &extra).await;
        assert_eq!(output.status.code(), Some(exit), "{extra:?}: {output:?}");
        reports.push(std::fs::read_to_string(&path).unwrap());
    }
    // No clock and no ordering luck: every run writes the same bytes.
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
}

#[tokio::test]
async fn code_findings_are_a_lane_of_their_own() {
    let mut recorded = finding(1, "SERIOUS", vec![code("src/orders.rs", 10, Some(14))]);
    recorded["risk_domain"] = json!("logic");
    // CODE findings carry no projected decisions.
    let mut settled = finding(2, "WARNING", Vec::new());
    settled["risk_domain"] = json!("edge_case");
    settled["validation"] = json!("DISMISSED");
    let (output, xml) = export(code_review(vec![recorded, settled]), &[]).await;
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let root = report(&xml.unwrap());
    assert_eq!(root.children.len(), 1);
    let lane = suite(&root, "Code-only");
    assert_eq!(property(lane, "lane"), Some("CODE"));
    assert_eq!(property(lane, "assessment_id"), Some(CODE_ASSESSMENT));
    assert_eq!(
        case(lane, "logic").one("failure").attribute("type"),
        Some("SERIOUS")
    );
    assert!(
        case(lane, "logic")
            .one("failure")
            .text
            .contains("cited: src/orders.rs:10-14")
    );
    assert_eq!(
        case(lane, "edge_case").one("failure").attribute("type"),
        Some("WARNING")
    );
    assert!(case(lane, "completeness").children.is_empty());
}

#[tokio::test]
async fn an_incomplete_lane_is_an_error_and_exits_2() {
    let mut environment = review(vec![finding(1, "WARNING", Vec::new())]);
    environment["assessments"][0]["reason_codes"] =
        json!(["WORLD_UNAVAILABLE", "WORLD_UNAVAILABLE", "CHECK_{0}_<link>"]);
    environment["assessments"][0]["checks"]["receipt_recorded"] = json!(false);
    let mut incomplete_code = code_review(Vec::new());
    incomplete_code["code_assessment"]["status"] = json!("INCOMPLETE");
    let mut gap = code_review(Vec::new());
    gap["code_assessment"]["incompleteness_kind"] = json!("EVIDENCE_UNAVAILABLE");
    let mut unavailable = code_review(Vec::new());
    unavailable["code_assessment"]["head_commit_sha"] = json!(BASE);
    let mut stopped = review(Vec::new());
    stopped["status"] = json!("STOPPED");
    let mut running = review(Vec::new());
    running["status"] = json!("RUNNING");
    for (label, document, lane, message) in [
        (
            "environment",
            environment,
            CLEAN_ENVIRONMENT,
            "CHECK_RECEIPT_ABSENT, CHECK_{0}_<link>, WORLD_UNAVAILABLE",
        ),
        (
            "code status",
            incomplete_code,
            "Code-only",
            "CODE_ASSESSMENT_STATE_UNAVAILABLE",
        ),
        ("code gap", gap, "Code-only", "EVIDENCE_UNAVAILABLE"),
        (
            "code unavailable",
            unavailable,
            "Code-only",
            "CODE_ASSESSMENT_UNAVAILABLE",
        ),
        ("stopped", stopped, "review", "REVIEW_STOPPED"),
        ("running", running, "review", "REVIEW_IN_PROGRESS"),
    ] {
        let (output, xml) = export(document, &[]).await;
        assert_ne!(output.status.code(), Some(0), "{label}: {output:?}");
        let root = report(&xml.unwrap_or_else(|| panic!("{label}: no report")));
        let lane = suite(&root, lane);
        let ended: Vec<&Node> = lane
            .all("testcase")
            .filter(|case| case.all("error").count() == 1)
            .collect();
        assert!(
            ended.iter().any(|case| {
                let error = case.one("error");
                error.attribute("type") == Some("INCOMPLETE")
                    && error.attribute("message") == Some(message)
            }),
            "{label}: {ended:?}"
        );
        assert!(count(&root, "errors") >= 1, "{label}");
    }
    // An incomplete environment still reports its findings and exits 2.
    let mut environment = review(vec![finding(1, "WARNING", Vec::new())]);
    environment["assessments"][0]["checks"]["receipt_recorded"] = json!(false);
    let (output, xml) = export(environment, &[]).await;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let root = report(&xml.unwrap());
    assert_eq!(count(&root, "failures"), 2);
}

#[tokio::test]
async fn a_review_that_is_not_the_requested_pull_request_head_is_refused() {
    let mut wrong_review = review(Vec::new());
    wrong_review["id"] = json!(OTHER_REVIEW);
    let mut deployment = review(Vec::new());
    deployment["kind"] = json!("DEPLOYMENT_GATE");
    let mut records = vec![
        (wrong_review, "server returned review"),
        (deployment, "requires a retained pull-request review"),
    ];
    for head in [Value::Null, json!("main")] {
        let mut document = review(Vec::new());
        document["head_commit_sha"] = head;
        records.push((document, "does not record a full commit SHA"));
    }
    let severity = review(vec![finding(1, "CRITICAL", Vec::new())]);
    records.push((severity, "unsupported severity"));
    for (document, expected) in records {
        let (output, xml) = export(document, &[]).await;
        assert_eq!(output.status.code(), Some(1), "{expected}: {output:?}");
        assert!(xml.is_none(), "{expected}: a refused review wrote a report");
        assert!(output.stdout.is_empty(), "{expected}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(expected), "{expected}: {stderr}");
        assert!(stderr.contains("JUnit export"), "{stderr}");
        assert!(!stderr.contains("SARIF"), "{stderr}");
        assert!(!stderr.contains(PRIVATE_VALUE));
    }
}

#[tokio::test]
async fn a_wrong_review_is_refused_while_polling_without_waiting_for_the_deadline() {
    let mut running = review(Vec::new());
    running["id"] = json!(OTHER_REVIEW);
    running["status"] = json!("RUNNING");
    let (origin, _) = serve(running).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.xml");
    let started = std::time::Instant::now();
    let output = ci_waiting(&origin, &path, "5", &[]).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!path.exists());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("server returned review"), "{stderr}");
}

#[tokio::test]
async fn an_unwritable_path_fails_without_hiding_the_review() {
    let (origin, requests) = serve(review(Vec::new())).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing").join("report.xml");
    let output = ci(&origin, &path, &[]).await;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("could not write JUnit XML to"), "{stderr}");
    assert!(!stderr.contains(TOKEN));
    assert_eq!(requests.lock().unwrap().as_slice(), ["detail"]);
}

#[tokio::test]
async fn an_environment_named_like_a_synthetic_suite_keeps_its_own_suite() {
    let mut document = review(Vec::new());
    document["status"] = json!("RUNNING");
    document["code_assessment"] = code_review(Vec::new())["code_assessment"].clone();
    document["assessments"][0]["environment_display_name"] = json!("review");
    let mut second = document["assessments"][0].clone();
    second["id"] = json!("0190f3a0-0000-7000-8000-000000000066");
    second["environment_display_name"] = json!("Code-only");
    document["assessments"].as_array_mut().unwrap().push(second);
    let (_, xml) = export(document, &[]).await;
    let root = report(&xml.unwrap());
    let mut names: Vec<&str> = root
        .all("testsuite")
        .map(|suite| suite.attribute("name").unwrap())
        .collect();
    names.sort_unstable();
    let total = names.len();
    names.dedup();
    assert_eq!(names.len(), total, "duplicate suite names: {names:?}");
    for expected in ["environment: review", "environment: Code-only", "review"] {
        assert!(names.contains(&expected), "{expected}: {names:?}");
    }
}
