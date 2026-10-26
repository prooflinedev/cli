//! A serial stdio adapter for this console's JSON-only, stateless MCP server.

use secrecy::SecretString;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Stdin, Stdout};

use crate::api::{Http, McpHttpError};

const FRAME_LIMIT: usize = 8192;
const PROTOCOL: &str = "2025-11-25";

#[derive(Debug, thiserror::Error)]
pub(crate) enum McpError {
    #[error(transparent)]
    Http(#[from] McpHttpError),
    #[error("MCP input exceeds 8192 bytes")]
    TooLarge,
    #[error("MCP input is not UTF-8")]
    Utf8,
    #[error("MCP input ended before its newline delimiter")]
    Incomplete,
    #[error("MCP input could not be read")]
    Input,
    #[error("MCP input is not valid JSON")]
    Parse,
    #[error("MCP input is not a JSON-RPC 2.0 request or notification")]
    Envelope,
    #[error("MCP requires initialize followed by notifications/initialized before other messages")]
    Lifecycle,
    #[error("the MCP server offered an unsupported protocol version")]
    Version,
    #[error("the MCP server sent an invalid or uncorrelated JSON-RPC response")]
    Response,
    #[error("MCP output could not be written")]
    Output,
}

impl McpError {
    fn code(&self) -> i32 {
        match self {
            Self::Utf8 | Self::Parse => -32700,
            Self::TooLarge | Self::Incomplete | Self::Envelope => -32600,
            Self::Http(_)
            | Self::Input
            | Self::Lifecycle
            | Self::Version
            | Self::Response
            | Self::Output => -32000,
        }
    }

    fn category(&self) -> &'static str {
        match self {
            Self::Http(error) => error.category(),
            Self::TooLarge | Self::Utf8 | Self::Incomplete | Self::Input => "input",
            Self::Parse | Self::Envelope => "jsonrpc",
            Self::Lifecycle | Self::Version => "lifecycle",
            Self::Response => "response",
            Self::Output => "output",
        }
    }

    fn response(&self, id: Option<&RequestId>) -> Value {
        let mut data = json!({"category": self.category()});
        if let Self::Http(McpHttpError::Http(status)) = self {
            data["http_status"] = json!(status);
        }
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": self.code(), "message": self.to_string(), "data": data}
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum RequestId {
    Number(i64),
    Text(String),
}

#[derive(Debug)]
struct Envelope(Value);

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor;

        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = Envelope;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one JSON-RPC object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if matches!(key.as_str(), "jsonrpc" | "id" | "result" | "error")
                        && object.contains_key(&key)
                    {
                        return Err(A::Error::custom("duplicate JSON-RPC envelope field"));
                    }
                    // Only reserved envelope fields need uniqueness here.
                    // Tool results remain opaque JSON, without a local schema.
                    object.insert(key, map.next_value::<Value>()?);
                }
                Ok(Envelope(Value::Object(object)))
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

impl RequestId {
    fn matches(&self, value: &Value) -> bool {
        match self {
            Self::Number(number) => value.as_i64() == Some(*number),
            Self::Text(text) => value.as_str() == Some(text.as_str()),
        }
    }
}

#[derive(Debug)]
struct Message {
    id: Option<RequestId>,
    method: String,
}

impl Message {
    fn parse(frame: &[u8]) -> Result<Self, McpError> {
        let text = std::str::from_utf8(frame).map_err(|_| McpError::Utf8)?;
        let value = serde_json::from_str::<Envelope>(text)
            .map_err(|error| {
                if error.is_data() {
                    McpError::Envelope
                } else {
                    McpError::Parse
                }
            })?
            .0;
        let object = value.as_object().ok_or(McpError::Envelope)?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
            || object
                .get("params")
                .is_some_and(|params| !params.is_object() && !params.is_array())
        {
            return Err(McpError::Envelope);
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(McpError::Envelope)?
            .to_owned();
        let id = match object.get("id") {
            None => None,
            Some(Value::String(text)) => Some(RequestId::Text(text.clone())),
            Some(Value::Number(number)) => Some(RequestId::Number(
                number.as_i64().ok_or(McpError::Envelope)?,
            )),
            Some(_) => return Err(McpError::Envelope),
        };
        Ok(Self { id, method })
    }
}

#[derive(Debug)]
enum Session {
    New,
    Negotiated(String),
    Ready(String),
}

impl Session {
    fn protocol(&self) -> Option<&str> {
        match self {
            Self::New => None,
            Self::Negotiated(version) | Self::Ready(version) => Some(version),
        }
    }

    fn admit(&self, message: &Message) -> Result<(), McpError> {
        let admitted = match self {
            Self::New => message.method == "initialize" && message.id.is_some(),
            Self::Negotiated(_) => {
                (message.method == "ping" && message.id.is_some())
                    || (message.method == "notifications/initialized" && message.id.is_none())
            }
            Self::Ready(_) => !matches!(
                message.method.as_str(),
                "initialize" | "notifications/initialized"
            ),
        };
        if admitted {
            Ok(())
        } else {
            Err(McpError::Lifecycle)
        }
    }

    fn complete(&mut self, message: &Message, response: Option<&Value>) -> Result<(), McpError> {
        match self {
            Self::New => {
                if let Some(result) = response.and_then(|response| response.get("result")) {
                    let version = result
                        .get("protocolVersion")
                        .and_then(Value::as_str)
                        .filter(|version| *version == PROTOCOL)
                        .ok_or(McpError::Version)?;
                    *self = Self::Negotiated(version.to_owned());
                }
                // A valid server initialize error passes through without
                // pretending that negotiation succeeded.
            }
            Self::Negotiated(version) => {
                if message.method == "notifications/initialized" {
                    *self = Self::Ready(std::mem::take(version));
                }
            }
            Self::Ready(_) => {}
        }
        Ok(())
    }
}

async fn read_frame(input: &mut BufReader<Stdin>) -> Result<Option<Vec<u8>>, McpError> {
    let mut frame = Vec::with_capacity(FRAME_LIMIT);
    loop {
        let available = input.fill_buf().await.map_err(|_| McpError::Input)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(McpError::Incomplete)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.unwrap_or(available.len());
        if length > FRAME_LIMIT - frame.len() {
            return Err(McpError::TooLarge);
        }
        frame.extend_from_slice(&available[..length]);
        input.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

fn decode_response(body: &[u8], id: &RequestId) -> Result<Value, McpError> {
    let value = serde_json::from_slice::<Envelope>(body)
        .map_err(|_| McpError::Response)?
        .0;
    let object = value.as_object().ok_or(McpError::Response)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !object.get("id").is_some_and(|value| id.matches(value))
        || object.contains_key("result") == object.contains_key("error")
    {
        return Err(McpError::Response);
    }
    if let Some(error) = object.get("error") {
        let error = error.as_object().ok_or(McpError::Response)?;
        if error.get("code").and_then(Value::as_i64).is_none()
            || error.get("message").and_then(Value::as_str).is_none()
        {
            return Err(McpError::Response);
        }
    }
    Ok(value)
}

async fn relay(
    http: &Http,
    token: &SecretString,
    session: &mut Session,
    message: &Message,
    frame: Vec<u8>,
) -> Result<Option<Value>, McpError> {
    session.admit(message)?;
    let body = http
        .mcp(token, frame, session.protocol(), message.id.is_none())
        .await?;
    let response = message
        .id
        .as_ref()
        .map(|id| decode_response(&body, id))
        .transpose()?;
    session.complete(message, response.as_ref())?;
    Ok(response)
}

async fn write(output: &mut Stdout, response: &Value) -> Result<(), McpError> {
    let mut encoded = serde_json::to_vec(response).map_err(|_| McpError::Output)?;
    encoded.push(b'\n');
    output
        .write_all(&encoded)
        .await
        .map_err(|_| McpError::Output)?;
    output.flush().await.map_err(|_| McpError::Output)
}

pub(crate) async fn run(http: &Http, token: &SecretString) -> Result<(), McpError> {
    let mut input = BufReader::with_capacity(FRAME_LIMIT, tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut session = Session::New;
    loop {
        // Do not leave an uncancellable stdin read alive while waiting for
        // HTTP or output. A failed transport can then terminate with stdin open.
        let frame = match read_frame(&mut input).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => {
                write(&mut output, &error.response(None)).await?;
                return Err(error);
            }
        };
        let message = match Message::parse(&frame) {
            Ok(message) => message,
            Err(error) => {
                write(&mut output, &error.response(None)).await?;
                return Err(error);
            }
        };
        match relay(http, token, &mut session, &message, frame).await {
            Ok(Some(response)) => write(&mut output, &response).await?,
            Ok(None) => {}
            Err(error) => {
                if let Some(id) = &message.id {
                    write(&mut output, &error.response(Some(id))).await?;
                }
                return Err(error);
            }
        }
    }
}

/// One native command uses the same negotiated, bounded transport as the bridge.
pub(crate) async fn call(
    http: &Http,
    token: &SecretString,
    name: &str,
    arguments: Value,
) -> Result<Value, McpError> {
    let mut session = Session::New;
    let frames = [
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":PROTOCOL, "capabilities":{},
            "clientInfo":{"name":"proofline-cli", "version":env!("CARGO_PKG_VERSION")}}}),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":name, "arguments":arguments}}),
    ];
    let mut result = None;
    for value in frames {
        let frame = serde_json::to_vec(&value).map_err(|_| McpError::Parse)?;
        if frame.len() > FRAME_LIMIT {
            return Err(McpError::TooLarge);
        }
        let message = Message::parse(&frame)?;
        result = relay(http, token, &mut session, &message, frame).await?;
        if result.as_ref().is_some_and(|r| r.get("error").is_some()) {
            return Err(McpError::Response);
        }
    }
    result
        .and_then(|mut r| r.get_mut("result").map(Value::take))
        .ok_or(McpError::Response)
}
