//! The actual stdio binary against a channel-controlled loopback MCP origin.
//! Database authority remains covered by the server's real router fixtures.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
const OTHER_ORG: &str = "0190f3a0-0000-7000-8000-000000000002";
const TOKEN: &str = "pld_CLI_MCP_SYNTHETIC_TOKEN_CANARY";
const PROTOCOL: &str = "2025-11-25";
const FRAME_LIMIT: usize = 8192;
const BODY_LIMIT: usize = 8 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(10);
const REFUSAL_CANARY: &str = "RAW_REFUSAL_BODY_CANARY";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    responses_released_at_arrival: usize,
}

impl Seen {
    fn message(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

#[derive(Debug)]
struct Captured {
    seen: Seen,
    reply: oneshot::Sender<Reply>,
}

impl Captured {
    fn respond(self, reply: Reply) {
        self.reply.send(reply).unwrap();
    }
}

#[derive(Debug)]
struct BodyGate {
    headers_sent: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: BTreeMap<String, String>,
    chunks: Vec<Vec<u8>>,
    chunked: bool,
    gate: Option<BodyGate>,
    may_disconnect: bool,
}

impl Reply {
    fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
            chunks: vec![body],
            chunked: false,
            gate: None,
            may_disconnect: false,
        }
    }

    fn json(value: &Value) -> Self {
        Self::bytes(200, serde_json::to_vec(value).unwrap())
    }

    fn notification() -> Self {
        let mut reply = Self::bytes(202, Vec::new());
        reply.headers.remove("content-type");
        reply
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_owned(), value.to_owned());
        self
    }

    fn held(mut self) -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (headers_sent, headers) = oneshot::channel();
        let (release, released) = oneshot::channel();
        self.gate = Some(BodyGate {
            headers_sent,
            release: released,
        });
        self.may_disconnect = true;
        (self, headers, release)
    }
}

#[derive(Debug)]
struct Fixture {
    origin: String,
    requests: mpsc::UnboundedReceiver<Captured>,
    traffic: Arc<Mutex<Vec<Seen>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (sent, requests) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let traffic = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(serve(listener, sent, traffic.clone(), stopped));
        Self {
            origin,
            requests,
            traffic,
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn request(&mut self) -> Captured {
        timeout(WAIT, self.requests.recv()).await.unwrap().unwrap()
    }

    async fn finish(mut self) -> Vec<Seen> {
        self.stop.take().unwrap().send(()).unwrap();
        timeout(WAIT, self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        drop(self.task.take());
        self.traffic.lock().unwrap().clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            // An assertion failure still closes the listener and its JoinSet.
            task.abort();
        }
    }
}

async fn serve(
    listener: TcpListener,
    requests: mpsc::UnboundedSender<Captured>,
    traffic: Arc<Mutex<Vec<Seen>>>,
    mut stopped: oneshot::Receiver<()>,
) {
    let released = Arc::new(AtomicUsize::new(0));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.unwrap();
                connections.spawn(exchange(
                    stream,
                    requests.clone(),
                    traffic.clone(),
                    released.clone(),
                ));
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                result.unwrap();
            }
        }
    }
    while let Some(result) = connections.join_next().await {
        result.unwrap();
    }
}

async fn exchange(
    stream: TcpStream,
    requests: mpsc::UnboundedSender<Captured>,
    traffic: Arc<Mutex<Vec<Seen>>>,
    released: Arc<AtomicUsize>,
) {
    let mut stream = BufReader::new(stream);
    let mut first = String::new();
    stream.read_line(&mut first).await.unwrap();
    let words: Vec<_> = first.split_whitespace().collect();
    assert_eq!(words.len(), 3);
    let mut headers = BTreeMap::new();
    let mut header_bytes = first.len();
    loop {
        let mut line = String::new();
        let read = stream.read_line(&mut line).await.unwrap();
        assert_ne!(read, 0);
        header_bytes += read;
        assert!(header_bytes <= 16 * 1024);
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        assert!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_none()
        );
    }
    let length = headers
        .get("content-length")
        .map_or(0, |length| length.parse::<usize>().unwrap());
    assert!(length <= FRAME_LIMIT);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    let seen = Seen {
        method: words[0].to_owned(),
        path: words[1].to_owned(),
        headers,
        body,
        responses_released_at_arrival: released.load(Ordering::SeqCst),
    };
    traffic.lock().unwrap().push(seen.clone());
    let (reply, received) = oneshot::channel();
    requests.send(Captured { seen, reply }).unwrap();
    let reply = received.await.unwrap();
    let may_disconnect = reply.may_disconnect;
    if let Err(error) = write_reply(stream.into_inner(), reply, &released).await {
        assert!(
            may_disconnect
                && matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::NotConnected
                ),
            "unexpected fixture write failure: {error}"
        );
    }
}

async fn write_reply(
    mut stream: TcpStream,
    reply: Reply,
    released: &AtomicUsize,
) -> io::Result<()> {
    let mut headers = format!("HTTP/1.1 {} Fixture\r\nConnection: close\r\n", reply.status);
    for (name, value) in &reply.headers {
        write!(headers, "{name}: {value}\r\n").unwrap();
    }
    if reply.chunked {
        headers.push_str("Transfer-Encoding: chunked\r\n\r\n");
    } else {
        let length: usize = reply.chunks.iter().map(Vec::len).sum();
        write!(headers, "Content-Length: {length}\r\n\r\n").unwrap();
    }
    stream.write_all(headers.as_bytes()).await?;
    stream.flush().await?;
    if let Some(gate) = reply.gate {
        gate.headers_sent.send(()).unwrap();
        gate.release.await.unwrap();
    }
    // Record the release before the last body write can wake the client. A
    // socket-shutdown completion counter would race a lawful next POST.
    released.fetch_add(1, Ordering::SeqCst);
    for chunk in reply.chunks {
        if reply.chunked {
            stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await?;
        }
        stream.write_all(&chunk).await?;
        if reply.chunked {
            stream.write_all(b"\r\n").await?;
        }
    }
    if reply.chunked {
        stream.write_all(b"0\r\n\r\n").await?;
    }
    stream.shutdown().await
}

#[derive(Debug)]
struct Bridge {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<BufReader<ChildStdout>>,
    diagnostic: ChildStderr,
    frames: Vec<Value>,
}

#[derive(Debug)]
struct Finished {
    status: ExitStatus,
    frames: Vec<Value>,
    remaining_output: Vec<u8>,
    diagnostic: Vec<u8>,
}

impl Bridge {
    fn start(origin: &str, organization: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_proofline"))
            .env_clear()
            .env("PROOFLINE_TOKEN", TOKEN)
            .env("PROOFLINE_ORGANIZATION_ID", organization)
            .env("PATH", "")
            .current_dir(std::env::temp_dir())
            .args(["--base-url", origin, "mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take(),
            output: child.stdout.take().map(BufReader::new),
            diagnostic: child.stderr.take().unwrap(),
            child,
            frames: Vec::new(),
        }
    }

    async fn bytes(&mut self, bytes: &[u8]) {
        let input = self.input.as_mut().unwrap();
        timeout(WAIT, input.write_all(bytes))
            .await
            .unwrap()
            .unwrap();
        input.flush().await.unwrap();
    }

    async fn send(&mut self, message: &Value) {
        let mut frame = serde_json::to_vec(message).unwrap();
        frame.push(b'\n');
        self.bytes(&frame).await;
    }

    async fn response(&mut self) -> Value {
        let mut line = Vec::new();
        let read = timeout(
            WAIT,
            self.output.as_mut().unwrap().read_until(b'\n', &mut line),
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(read, 0, "the process produced no response frame");
        assert_eq!(line.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(&line).unwrap();
        let mut compact = serde_json::to_vec(&value).unwrap();
        compact.push(b'\n');
        assert_eq!(line, compact, "stdout must contain compact frames only");
        assert_private(&line);
        self.frames.push(value.clone());
        value
    }

    async fn finish(mut self, close_input: bool) -> Finished {
        if close_input {
            drop(self.input.take());
        }
        let status = timeout(WAIT, self.child.wait()).await.unwrap().unwrap();
        // With close_input=false, exit is observed while stdin is still held.
        drop(self.input.take());
        let mut remaining_output = Vec::new();
        if let Some(output) = &mut self.output {
            timeout(WAIT, output.read_to_end(&mut remaining_output))
                .await
                .unwrap()
                .unwrap();
        }
        let mut diagnostic = Vec::new();
        timeout(WAIT, self.diagnostic.read_to_end(&mut diagnostic))
            .await
            .unwrap()
            .unwrap();
        assert_private(&remaining_output);
        assert_private(&diagnostic);
        Finished {
            status,
            frames: self.frames,
            remaining_output,
            diagnostic,
        }
    }
}

fn assert_private(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for canary in [
        TOKEN,
        REFUSAL_CANARY,
        "SESSION_RESPONSE_CANARY",
        "MALFORMED_INPUT_CANARY",
    ] {
        assert!(
            !text.contains(canary),
            "diagnostic exposed fixture material"
        );
    }
}

fn assert_request(captured: &Captured, origin: &str, message: &Value, negotiated: bool) {
    let seen = &captured.seen;
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/mcp");
    assert_eq!(&seen.message(), message);
    assert_eq!(seen.headers["authorization"], format!("Bearer {TOKEN}"));
    assert_eq!(seen.headers["origin"], origin);
    assert_eq!(seen.headers["content-type"], "application/json");
    let accepts: Vec<_> = seen.headers["accept"].split(',').map(str::trim).collect();
    assert!(accepts.contains(&"application/json"));
    assert!(accepts.contains(&"text/event-stream"));
    assert_eq!(
        seen.headers.get("mcp-protocol-version").map(String::as_str),
        negotiated.then_some(PROTOCOL)
    );
    for absent in [
        "cookie",
        "mcp-session-id",
        "x-organization-id",
        "x-proofline-organization-id",
    ] {
        assert!(!seen.headers.contains_key(absent));
    }
}

fn request(id: Value, method: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method})
}

fn result(id: Value, body: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":body,"_meta":{"opaque":null}})
}

fn initialize(id: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{
        "protocolVersion":"2025-03-26",
        "capabilities":{"roots":{"listChanged":true}},
        "clientInfo":{"name":"CLI fixture\nsecond line","version":"1"}
    }})
}

fn initialized() -> Value {
    json!({"jsonrpc":"2.0","method":"notifications/initialized"})
}

fn init_result(id: Value) -> Value {
    result(
        id,
        json!({
            "protocolVersion":PROTOCOL,
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"proofline","version":"fixture"},
            "instructions":"fixture instruction\nkept exactly"
        }),
    )
}

async fn negotiate(bridge: &mut Bridge, fixture: &mut Fixture, early_ping: bool) {
    let message = initialize(json!("init\nquoted \" id"));
    bridge.send(&message).await;
    let captured = fixture.request().await;
    assert_request(&captured, &fixture.origin, &message, false);
    let response = init_result(message["id"].clone());
    captured.respond(Reply::json(&response));
    assert_eq!(bridge.response().await, response);
    if early_ping {
        exchange_value(
            bridge,
            fixture,
            request(json!(-8), "ping"),
            result(json!(-8), json!({"negotiated_ping":true})),
        )
        .await;
    }
    let notification = initialized();
    bridge.send(&notification).await;
    let captured = fixture.request().await;
    assert_request(&captured, &fixture.origin, &notification, true);
    captured.respond(Reply::notification());
}

fn status_call(id: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":"get_review_status",
        "arguments":{"review_id":"0199abcd-1000-7000-8000-000000000001"}
    }})
}

fn status_result(id: Value, status: &str) -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/mcp-review-status.json")).unwrap();
    let mut data = fixture["expected"].clone();
    data["status"] = json!(status);
    if status == "RUNNING" {
        data["completed_at"] = Value::Null;
    }
    let structured = json!({"ok":true,"data":data});
    result(
        id,
        json!({
            "structuredContent":structured,
            "content":[{"type":"text","text":serde_json::to_string(&structured).unwrap()}],
            "isError":false
        }),
    )
}

async fn exchange_value(
    bridge: &mut Bridge,
    fixture: &mut Fixture,
    message: Value,
    response: Value,
) {
    bridge.send(&message).await;
    let captured = fixture.request().await;
    assert_request(&captured, &fixture.origin, &message, true);
    captured.respond(Reply::json(&response));
    assert_eq!(bridge.response().await, response);
}

fn assert_failure(finished: &Finished) {
    assert_eq!(finished.status.code(), Some(1));
    assert!(finished.remaining_output.is_empty());
}

fn assert_error(response: &Value, id: &Value, code: i32, category: &str) {
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(&response["id"], id);
    assert_eq!(response["error"]["code"], code);
    assert_eq!(response["error"]["data"]["category"], category);
    assert!(response.get("result").is_none());
    assert_eq!(response.as_object().unwrap().len(), 3);
    assert_eq!(response["error"].as_object().unwrap().len(), 3);
    assert!(response["error"]["message"].is_string());
    let data = response["error"]["data"].as_object().unwrap();
    assert_eq!(data.len(), if category == "http" { 2 } else { 1 });
    assert_private(&serde_json::to_vec(response).unwrap());
}

#[tokio::test]
async fn empty_notification_acknowledgments_accept_response_media_types() {
    for media_type in [None, Some("application/json"), Some("text/html")] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        let init = initialize(json!(1));
        bridge.send(&init).await;
        fixture
            .request()
            .await
            .respond(Reply::json(&init_result(json!(1))));
        assert_eq!(bridge.response().await, init_result(json!(1)));
        bridge.send(&initialized()).await;
        let reply = media_type.map_or_else(Reply::notification, |media_type| {
            Reply::notification().header("content-type", media_type)
        });
        fixture.request().await.respond(reply);
        let catalog = result(json!(2), json!({"tools":[]}));
        exchange_value(
            &mut bridge,
            &mut fixture,
            request(json!(2), "tools/list"),
            catalog,
        )
        .await;
        let finished = bridge.finish(true).await;
        assert!(
            finished.status.success(),
            "{media_type:?}: {:?}",
            finished.diagnostic
        );
        assert!(finished.remaining_output.is_empty());
        assert_eq!(
            finished.frames.len(),
            2,
            "notification acknowledgment must be silent"
        );
        assert_eq!(fixture.finish().await.len(), 3);
    }
}

#[tokio::test]
async fn negotiated_stdio_forwards_exact_messages_headers_and_machine_status_without_notification_output()
 {
    let second = Fixture::start().await;
    for organization in [ORG, OTHER_ORG] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, organization);
        negotiate(&mut bridge, &mut fixture, true).await;
        let tools = request(json!(-7), "tools/list");
        let catalog = result(
            json!(-7),
            json!({"tools":[{
            "name":"get_review_status",
            "description":"Recorded machine status",
            "inputSchema":{"type":"object","properties":{"review_id":{"type":"string","format":"uuid"}},"required":["review_id"],"additionalProperties":false},
            "annotations":{"readOnlyHint":true,"untrustedContentHint":false}
        }],"nextCursor":null}),
        );
        exchange_value(&mut bridge, &mut fixture, tools, catalog).await;
        let mut call = status_call(json!("status\nstring id"));
        call["params"]["_meta"] = json!({
            "url":format!("{}/mcp", second.origin),
            "organization_id":OTHER_ORG,
            "headers":{"Authorization":"ignored data"}
        });
        let status = status_result(call["id"].clone(), "INCOMPLETE");
        assert_eq!(
            status["result"]["structuredContent"]["data"]["assessments"][0]["status"],
            "INCOMPLETE"
        );
        assert_eq!(
            status["result"]["structuredContent"]["data"]["exact_change"]["subjects"][0]["artifact_digest"],
            Value::Null
        );
        exchange_value(&mut bridge, &mut fixture, call, status).await;
        let tool_error = result(
            json!(3),
            json!({
                "structuredContent":{"ok":false,"error":{"code":"RESOURCE_NOT_FOUND","message":"Review not found"}},
                "content":[{"type":"text","text":"fixture machine error"}],
                "isError":true
            }),
        );
        exchange_value(&mut bridge, &mut fixture, status_call(json!(3)), tool_error).await;
        let rpc_error = json!({"jsonrpc":"2.0","id":4,"error":{
            "code":-32601,"message":"Method not found","data":{"server_owned":null}
        }});
        exchange_value(
            &mut bridge,
            &mut fixture,
            request(json!(4), "server/unknown"),
            rpc_error,
        )
        .await;
        exchange_value(
            &mut bridge,
            &mut fixture,
            request(json!(5), "ping"),
            result(json!(5), json!({})),
        )
        .await;
        let finished = bridge.finish(true).await;
        assert!(finished.status.success());
        assert!(finished.remaining_output.is_empty());
        assert!(finished.diagnostic.is_empty());
        assert_eq!(finished.frames.len(), 7, "initialized must be silent");
        let traffic = fixture.finish().await;
        assert_eq!(traffic.len(), 8);
        assert!(
            traffic
                .iter()
                .all(|seen| seen.path == "/mcp" && seen.method == "POST")
        );
        assert!(
            traffic
                .iter()
                .all(|seen| seen.headers["authorization"] == format!("Bearer {TOKEN}"))
        );
    }
    assert!(
        second.finish().await.is_empty(),
        "payload URLs cannot choose another origin"
    );

    let mut fixture = Fixture::start().await;
    let mut bridge = Bridge::start(&fixture.origin, ORG);
    bridge.send(&initialize(json!(1))).await;
    fixture
        .request()
        .await
        .respond(Reply::json(&init_result(json!(1))));
    assert_eq!(bridge.response().await, init_result(json!(1)));
    exchange_value(
        &mut bridge,
        &mut fixture,
        request(json!(2), "ping"),
        result(json!(2), json!({})),
    )
    .await;
    bridge.send(&request(json!(3), "tools/list")).await;
    assert_error(&bridge.response().await, &json!(3), -32000, "lifecycle");
    assert_failure(&bridge.finish(false).await);
    assert_eq!(
        fixture.finish().await.len(),
        2,
        "a negotiated ping does not unlock tools before initialized"
    );
}

#[tokio::test]
async fn evolving_status_never_survives_a_live_transport_refusal_or_leaks_to_another_origin() {
    let second = Fixture::start().await;
    for status in [401, 403, 404, 429, 503, 302] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        negotiate(&mut bridge, &mut fixture, false).await;
        for (id, state) in [(1, "RUNNING"), (2, "INCOMPLETE")] {
            exchange_value(
                &mut bridge,
                &mut fixture,
                status_call(json!(id)),
                status_result(json!(id), state),
            )
            .await;
        }
        let message = status_call(json!("retired\nrequest"));
        bridge.send(&message).await;
        let captured = fixture.request().await;
        assert_request(&captured, &fixture.origin, &message, true);
        let refusal = Reply::bytes(status, format!("{REFUSAL_CANARY} {TOKEN}").into_bytes())
            .header("content-type", "application/problem+json")
            .header("retry-after", "0")
            .header(
                "location",
                &format!("{}/capture?{REFUSAL_CANARY}", second.origin),
            );
        let (refusal, headers, release) = refusal.held();
        captured.respond(refusal);
        timeout(WAIT, headers).await.unwrap().unwrap();
        let response = bridge.response().await;
        assert_error(&response, &message["id"], -32000, "http");
        assert_eq!(response["error"]["data"]["http_status"], status);
        assert_eq!(
            response["error"]["message"],
            format!("the MCP server refused the request with HTTP {status}")
        );
        assert!(
            response["error"]
                .get("data")
                .unwrap()
                .get("review")
                .is_none()
        );
        let finished = bridge.finish(false).await;
        assert_failure(&finished);
        assert_eq!(finished.frames.len(), 4);
        release.send(()).unwrap();
        assert_eq!(
            fixture.finish().await.len(),
            5,
            "there is one POST per message and no retry or alternate read"
        );
    }
    assert!(
        second.finish().await.is_empty(),
        "a redirect must never contact the second origin"
    );

    for (header, value) in [
        ("content-type", "text/event-stream"),
        ("content-type", "text/plain"),
        ("mcp-session-id", "SESSION_RESPONSE_CANARY"),
    ] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        negotiate(&mut bridge, &mut fixture, false).await;
        let message = status_call(json!(8));
        bridge.send(&message).await;
        let captured = fixture.request().await;
        let (reply, headers, release) = Reply::bytes(200, REFUSAL_CANARY.as_bytes().to_vec())
            .header(header, value)
            .held();
        captured.respond(reply);
        timeout(WAIT, headers).await.unwrap().unwrap();
        assert_error(&bridge.response().await, &json!(8), -32000, "protocol");
        assert_failure(&bridge.finish(false).await);
        release.send(()).unwrap();
        assert_eq!(fixture.finish().await.len(), 3);
    }

    let malformed = [
        Vec::new(),
        format!("not JSON {REFUSAL_CANARY}").into_bytes(),
        serde_json::to_vec(&result(json!("wrong id"), json!({}))).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":9,"result":{},"error":{"code":-1,"message":"both"}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"1.0","id":9,"result":{}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":9,"error":{"code":"invalid","message":REFUSAL_CANARY}})).unwrap(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":\"other\",\"id\":9,\"result\":{{\"raw\":\"{REFUSAL_CANARY}\"}}}}").into_bytes(),
        format!("{{\"jsonrpc\":\"1.0\",\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{{\"raw\":\"{REFUSAL_CANARY}\"}}}}").into_bytes(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{{\"raw\":\"{REFUSAL_CANARY}\"}},\"result\":{{}}}}").into_bytes(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":9,\"error\":{{\"code\":-1,\"message\":\"{REFUSAL_CANARY}\"}},\"error\":{{\"code\":-2,\"message\":\"last\"}}}}").into_bytes(),
    ];
    for body in malformed {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        negotiate(&mut bridge, &mut fixture, false).await;
        bridge.send(&request(json!(9), "ping")).await;
        fixture.request().await.respond(Reply::bytes(200, body));
        assert_error(&bridge.response().await, &json!(9), -32000, "response");
        assert_failure(&bridge.finish(false).await);
        assert_eq!(fixture.finish().await.len(), 3);
    }

    for chunked in [false, true] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        negotiate(&mut bridge, &mut fixture, false).await;
        bridge.send(&request(json!(10), "ping")).await;
        let mut reply = Reply::bytes(200, vec![b'x'; BODY_LIMIT + 1]);
        reply.chunked = chunked;
        reply.may_disconnect = true;
        if chunked {
            reply.chunks = (0..64).map(|_| vec![b'x'; BODY_LIMIT / 64]).collect();
            reply.chunks.push(vec![b'x']);
        }
        fixture.request().await.respond(reply);
        assert_error(
            &bridge.response().await,
            &json!(10),
            -32000,
            "response_size",
        );
        assert_failure(&bridge.finish(false).await);
        assert_eq!(fixture.finish().await.len(), 3);
    }

    for reply in [
        Reply::bytes(202, Vec::new()),
        Reply::bytes(202, b"{}".to_vec()),
    ] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        negotiate(&mut bridge, &mut fixture, false).await;
        bridge.send(&request(json!(11), "ping")).await;
        fixture.request().await.respond(reply);
        assert_error(&bridge.response().await, &json!(11), -32000, "protocol");
        assert_failure(&bridge.finish(false).await);
        assert_eq!(fixture.finish().await.len(), 3);
    }

    for reply in [
        Reply::bytes(200, b"{}".to_vec()),
        Reply::bytes(202, b"{}".to_vec()).header("content-type", "text/html"),
        Reply::bytes(403, REFUSAL_CANARY.as_bytes().to_vec()),
        Reply::notification().header("mcp-session-id", "SESSION_RESPONSE_CANARY"),
    ] {
        let mut fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        let init = initialize(json!(1));
        bridge.send(&init).await;
        fixture
            .request()
            .await
            .respond(Reply::json(&init_result(json!(1))));
        assert_eq!(bridge.response().await, init_result(json!(1)));
        bridge.send(&initialized()).await;
        fixture.request().await.respond(reply);
        let finished = bridge.finish(false).await;
        assert_failure(&finished);
        assert_eq!(
            finished.frames.len(),
            1,
            "valid notification refusal emits no id:null response"
        );
        assert!(!finished.diagnostic.is_empty());
        assert_eq!(fixture.finish().await.len(), 2);
    }

    let mut fixture = Fixture::start().await;
    let mut bridge = Bridge::start(&fixture.origin, ORG);
    bridge.send(&initialize(json!(1))).await;
    let incompatible = result(
        json!(1),
        json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}),
    );
    fixture.request().await.respond(Reply::json(&incompatible));
    assert_error(&bridge.response().await, &json!(1), -32000, "lifecycle");
    assert_failure(&bridge.finish(false).await);
    assert_eq!(fixture.finish().await.len(), 1);

    let mut fixture = Fixture::start().await;
    let mut bridge = Bridge::start(&fixture.origin, ORG);
    bridge.send(&initialize(json!(1))).await;
    let refused_init = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unsupported initialization"}});
    fixture.request().await.respond(Reply::json(&refused_init));
    assert_eq!(bridge.response().await, refused_init);
    bridge.send(&request(json!(2), "tools/list")).await;
    assert_error(&bridge.response().await, &json!(2), -32000, "lifecycle");
    assert_failure(&bridge.finish(false).await);
    assert_eq!(
        fixture.finish().await.len(),
        1,
        "failed initialization cannot install a protocol header or start tools"
    );
}

#[tokio::test]
async fn bounded_frames_serial_backpressure_and_broken_stdout_release_the_actual_process() {
    for (bytes, close_input, code, category) in [
        (vec![b'x'; FRAME_LIMIT + 1], false, -32600, "input"),
        (vec![b'{', 0xff, b'}', b'\n'], false, -32700, "input"),
        (
            b"{MALFORMED_INPUT_CANARY}\n".to_vec(),
            false,
            -32700,
            "jsonrpc",
        ),
        (
            serde_json::to_vec(&initialize(json!(1))).unwrap(),
            true,
            -32600,
            "input",
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"initialize\"}\n".to_vec(),
            false,
            -32600,
            "jsonrpc",
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":999,\"id\":1,\"method\":\"initialize\"}\n".to_vec(),
            false,
            -32600,
            "jsonrpc",
        ),
    ] {
        let fixture = Fixture::start().await;
        let mut bridge = Bridge::start(&fixture.origin, ORG);
        bridge.bytes(&bytes).await;
        if close_input {
            drop(bridge.input.take());
        }
        assert_error(&bridge.response().await, &Value::Null, code, category);
        let finished = bridge.finish(false).await;
        assert_failure(&finished);
        assert_eq!(finished.frames.len(), 1);
        assert!(fixture.finish().await.is_empty());
    }

    let fixture = Fixture::start().await;
    let bridge = Bridge::start(&fixture.origin, ORG);
    let finished = bridge.finish(true).await;
    assert!(finished.status.success());
    assert!(finished.frames.is_empty());
    assert!(finished.remaining_output.is_empty());
    assert!(finished.diagnostic.is_empty());
    assert!(fixture.finish().await.is_empty());

    let mut fixture = Fixture::start().await;
    let mut bridge = Bridge::start(&fixture.origin, ORG);
    negotiate(&mut bridge, &mut fixture, false).await;
    let mut exact = request(json!(20), "ping");
    exact["params"] = json!({"_meta":{"padding":""}});
    let empty_length = serde_json::to_vec(&exact).unwrap().len();
    exact["params"]["_meta"]["padding"] = json!("x".repeat(FRAME_LIMIT - empty_length));
    assert_eq!(serde_json::to_vec(&exact).unwrap().len(), FRAME_LIMIT);
    exchange_value(
        &mut bridge,
        &mut fixture,
        exact,
        result(json!(20), json!({})),
    )
    .await;

    let first = request(json!(21), "ping");
    bridge.send(&first).await;
    let captured = fixture.request().await;
    assert_request(&captured, &fixture.origin, &first, true);
    let first_reply = result(json!(21), json!({"order":1}));
    let (reply, headers, release) = Reply::json(&first_reply).held();
    captured.respond(reply);
    timeout(WAIT, headers).await.unwrap().unwrap();
    let second = request(json!(22), "ping");
    let third = request(json!(23), "ping");
    let mut queued = serde_json::to_vec(&second).unwrap();
    queued.push(b'\n');
    queued.extend_from_slice(&serde_json::to_vec(&third).unwrap());
    queued.push(b'\n');
    bridge.bytes(&queued).await;
    drop(bridge.input.take());
    // The first request and its written headers establish the phase. Observe
    // the request channel while its body is still explicitly unavailable;
    // this deadline is an absence check, not an arrival sleep.
    assert!(
        timeout(Duration::from_millis(200), fixture.requests.recv())
            .await
            .is_err(),
        "queued input started a second POST while the first response was held"
    );
    release.send(()).unwrap();
    assert_eq!(bridge.response().await, first_reply);
    for (message, id, prior) in [(second, 22, 4), (third, 23, 5)] {
        let captured = fixture.request().await;
        assert_request(&captured, &fixture.origin, &message, true);
        assert_eq!(
            captured.seen.responses_released_at_arrival, prior,
            "queued POST arrived before its predecessor's response was released"
        );
        let response = result(json!(id), json!({"order":id}));
        let (reply, headers, release) = Reply::json(&response).held();
        captured.respond(reply);
        timeout(WAIT, headers).await.unwrap().unwrap();
        if id == 22 {
            assert!(
                timeout(Duration::from_millis(200), fixture.requests.recv())
                    .await
                    .is_err(),
                "the next queued POST bypassed its predecessor's held response"
            );
        }
        release.send(()).unwrap();
        assert_eq!(bridge.response().await, response);
    }
    let finished = bridge.finish(false).await;
    assert!(finished.status.success());
    assert!(finished.remaining_output.is_empty());
    assert!(finished.diagnostic.is_empty());
    assert_eq!(finished.frames.len(), 5);
    assert_eq!(fixture.finish().await.len(), 6);

    let mut fixture = Fixture::start().await;
    let mut bridge = Bridge::start(&fixture.origin, ORG);
    negotiate(&mut bridge, &mut fixture, false).await;
    bridge.send(&request(json!(30), "ping")).await;
    let captured = fixture.request().await;
    drop(bridge.output.take());
    captured.respond(Reply::json(&result(json!(30), json!({}))));
    let finished = bridge.finish(false).await;
    assert_failure(&finished);
    assert!(
        String::from_utf8_lossy(&finished.diagnostic).contains("MCP output could not be written")
    );
    assert_eq!(finished.frames.len(), 1);
    assert_eq!(
        fixture.finish().await.len(),
        3,
        "broken output terminates while stdin remains open"
    );
}
