//! Add one server while retaining the user's other configuration.

use std::collections::HashSet;
use std::fmt;

use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap as _;
use serde::{Deserialize, Serialize};
use serde_json::value::{RawValue, to_raw_value};
use serde_json::{Map, Value};
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table};

use super::{Client, InstallError};
use crate::origin::Origin;

pub(super) enum Update {
    Existing,
    Change(Vec<u8>),
}

impl fmt::Debug for Update {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Existing => formatter.write_str("Existing"),
            Self::Change(bytes) => formatter
                .debug_struct("Change")
                .field("bytes", &bytes.len())
                .finish(),
        }
    }
}

pub(super) fn snippet(client: Client, origin: &Origin) -> Result<String, InstallError> {
    match prepare(client, None, origin)? {
        Update::Change(bytes) => {
            String::from_utf8(bytes).map_err(|_| InstallError::InvalidConfig(client))
        }
        Update::Existing => Err(InstallError::InvalidConfig(client)),
    }
}

pub(super) fn prepare(
    client: Client,
    original: Option<&[u8]>,
    origin: &Origin,
) -> Result<Update, InstallError> {
    match client {
        Client::Codex => codex(original, origin),
        Client::ClaudeCode | Client::Cursor | Client::Gemini | Client::Kiro => {
            json(client, original, origin)
        }
    }
}

pub(super) fn registration(client: Client, bytes: &[u8]) -> Result<Option<Value>, InstallError> {
    let document: Value = if client == Client::Codex {
        let raw = std::str::from_utf8(bytes).map_err(|_| InstallError::InvalidConfig(client))?;
        let document = bounded_toml(raw)?;
        Value::deserialize(toml_edit::de::Deserializer::from(document))
            .map_err(|_| InstallError::InvalidConfig(client))?
    } else {
        // Client JSON parsers use the last occurrence of a repeated member.
        serde_json::from_slice(bytes).map_err(|_| InstallError::InvalidConfig(client))?
    };
    let root = document.as_object().ok_or(InstallError::ConfigShape {
        client,
        member: "root",
    })?;
    let member = if client == Client::Codex {
        "mcp_servers"
    } else {
        "mcpServers"
    };
    let Some(servers) = root.get(member) else {
        return Ok(None);
    };
    let servers = servers
        .as_object()
        .ok_or(InstallError::ConfigShape { client, member })?;
    Ok(servers.get("proofline").cloned())
}

fn bounded_toml(raw: &str) -> Result<toml_edit::Document<&str>, InstallError> {
    use toml_parser::parser::{EventKind, RecursionGuard, parse_document};

    // Inspect flat events before tree construction, whose error cleanup can
    // itself recurse. Reuse the same lexer/parser as toml_edit, including quoted
    // keys, strings and comments. The guard bounds the event parser's recursion.
    let tokens = toml_parser::Source::new(raw).lex().into_vec();
    let mut events = Vec::new();
    let mut error = None;
    parse_document(
        &tokens,
        &mut RecursionGuard::new(&mut events, 64),
        &mut error,
    );
    if error.is_some() {
        return Err(InstallError::InvalidConfig(Client::Codex));
    }
    let mut containers = Vec::new();
    let mut table_depth = 0;
    let mut key_depth = 0;
    let mut value_depth = 0;
    for event in events {
        match event.kind() {
            EventKind::StdTableOpen | EventKind::ArrayTableOpen => key_depth = 0,
            EventKind::SimpleKey => key_depth += 1,
            EventKind::StdTableClose | EventKind::ArrayTableClose => {
                table_depth = key_depth + usize::from(event.kind() == EventKind::ArrayTableClose);
                key_depth = 0;
            }
            EventKind::KeyValSep => {
                value_depth = containers.last().copied().unwrap_or(table_depth) + key_depth;
                key_depth = 0;
            }
            EventKind::InlineTableOpen | EventKind::ArrayOpen => {
                if value_depth > 64 {
                    return Err(InstallError::InvalidConfig(Client::Codex));
                }
                containers.push(value_depth);
                value_depth += 1;
            }
            EventKind::InlineTableClose | EventKind::ArrayClose => {
                value_depth = containers.pop().unwrap_or(0);
            }
            EventKind::ValueSep => value_depth = containers.last().copied().unwrap_or(0) + 1,
            EventKind::Scalar if value_depth > 64 => {
                return Err(InstallError::InvalidConfig(Client::Codex));
            }
            _ => {}
        }
        if key_depth > 64 || table_depth > 64 {
            return Err(InstallError::InvalidConfig(Client::Codex));
        }
    }
    let document =
        toml_edit::Document::parse(raw).map_err(|_| InstallError::InvalidConfig(Client::Codex))?;
    // Array-of-table ancestors add implicit containers to header paths. The flat
    // guard bounds these to at most twice its limit, including error cleanup;
    // check the exact structural depth before recursive serde conversion.
    let mut pending = vec![(document.as_item(), 0_usize)];
    while let Some((item, depth)) = pending.pop() {
        if depth > 64 {
            return Err(InstallError::InvalidConfig(Client::Codex));
        }
        if let Some(table) = item.as_table_like() {
            pending.extend(table.iter().map(|(_, item)| (item, depth + 1)));
        } else {
            let mut index = 0;
            while let Some(child) = item.get(index) {
                pending.push((child, depth + 1));
                index += 1;
            }
        }
    }
    Ok(document)
}

fn arguments(origin: &Origin) -> [String; 3] {
    ["--base-url".to_owned(), origin.as_key(), "mcp".to_owned()]
}

fn executable() -> Result<String, InstallError> {
    std::env::current_exe()
        .map_err(InstallError::Executable)?
        .into_os_string()
        .into_string()
        .map_err(|_| InstallError::ExecutableEncoding)
}

fn codex(original: Option<&[u8]>, origin: &Origin) -> Result<Update, InstallError> {
    let raw = std::str::from_utf8(original.unwrap_or_default())
        .map_err(|_| InstallError::InvalidConfig(Client::Codex))?;
    // TOML diagnostics quote private configuration lines. Keep them out of errors.
    let mut document: DocumentMut = raw
        .parse()
        .map_err(|_| InstallError::InvalidConfig(Client::Codex))?;
    let mut args = Array::new();
    for argument in arguments(origin) {
        args.push(argument);
    }
    match document.get_mut("mcp_servers") {
        None => {
            let mut servers = Table::new();
            servers.insert("proofline", Item::Table(codex_server(args)?));
            document.insert("mcp_servers", Item::Table(servers));
        }
        Some(Item::Table(servers)) => {
            if servers.contains_key("proofline") {
                return Ok(Update::Existing);
            }
            servers.insert("proofline", Item::Table(codex_server(args)?));
        }
        Some(Item::Value(toml_edit::Value::InlineTable(servers))) => {
            if servers.contains_key("proofline") {
                return Ok(Update::Existing);
            }
            let mut server = InlineTable::new();
            server.insert("command", executable()?.into());
            server.insert("args", args.into());
            servers.insert("proofline", server.into());
        }
        Some(_) => {
            return Err(InstallError::ConfigShape {
                client: Client::Codex,
                member: "mcp_servers",
            });
        }
    }
    Ok(Update::Change(document.to_string().into_bytes()))
}

fn codex_server(args: Array) -> Result<Table, InstallError> {
    let mut server = Table::new();
    server.insert("command", toml_edit::value(executable()?));
    server.insert("args", toml_edit::value(args));
    Ok(server)
}

fn json(client: Client, original: Option<&[u8]>, origin: &Origin) -> Result<Update, InstallError> {
    let mut document = match original {
        None => RawObject(Vec::new()),
        Some(raw) => {
            // Validate duplicate members recursively before merging. Keep other
            // values raw so numbers and nested client settings are not rewritten.
            serde_json::from_slice::<UniqueJson>(raw)
                .map_err(|_| InstallError::InvalidConfig(client))?;
            serde_json::from_slice(raw).map_err(|_| InstallError::ConfigShape {
                client,
                member: "root",
            })?
        }
    };
    let position = document.0.iter().position(|(key, _)| key == "mcpServers");
    let mut servers = match position {
        Some(index) => {
            serde_json::from_str::<RawObject>(document.0[index].1.get()).map_err(|_| {
                InstallError::ConfigShape {
                    client,
                    member: "mcpServers",
                }
            })?
        }
        None => RawObject(Vec::new()),
    };
    if servers.0.iter().any(|(key, _)| key == "proofline") {
        return Ok(Update::Existing);
    }
    let mut server = Map::new();
    if matches!(client, Client::Cursor | Client::ClaudeCode) {
        server.insert("type".to_owned(), Value::String("stdio".to_owned()));
    }
    server.insert("command".to_owned(), Value::String(executable()?));
    server.insert(
        "args".to_owned(),
        Value::Array(arguments(origin).into_iter().map(Value::String).collect()),
    );
    servers.0.push((
        "proofline".to_owned(),
        to_raw_value(&Value::Object(server)).map_err(|_| InstallError::InvalidConfig(client))?,
    ));
    let value = to_raw_value(&servers).map_err(|_| InstallError::InvalidConfig(client))?;
    match position {
        Some(index) => document.0[index].1 = value,
        None => document.0.push(("mcpServers".to_owned(), value)),
    }
    let mut bytes =
        serde_json::to_vec_pretty(&document).map_err(|_| InstallError::InvalidConfig(client))?;
    bytes.push(b'\n');
    Ok(Update::Change(bytes))
}

struct RawObject(Vec<(String, Box<RawValue>)>);

impl fmt::Debug for RawObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawObject")
            .field("members", &self.0.len())
            .finish()
    }
}

impl Serialize for RawObject {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut object = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            object.serialize_entry(key, value)?;
        }
        object.end()
    }
}

impl<'de> Deserialize<'de> for RawObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RawObjectVisitor)
    }
}

#[derive(Debug)]
struct RawObjectVisitor;

impl<'de> Visitor<'de> for RawObjectVisitor {
    type Value = RawObject;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<Self::Value, A::Error> {
        let mut object = Vec::new();
        while let Some(entry) = values.next_entry()? {
            object.push(entry);
        }
        Ok(RawObject(object))
    }
}

#[derive(Debug)]
struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[derive(Debug)]
struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object members")
    }

    fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_i64<E: serde::de::Error>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_u64<E: serde::de::Error>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Self::Value, A::Error> {
        while values.next_element::<UniqueJson>()?.is_some() {}
        Ok(UniqueJson)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<Self::Value, A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = values.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON member"));
            }
            values.next_value::<UniqueJson>()?;
        }
        Ok(UniqueJson)
    }
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum as _;
    use serde_json::json;

    use super::{Client, InstallError, registration};

    #[test]
    fn json_extraction_uses_the_effective_container_and_registration() {
        for client in Client::value_variants()
            .iter()
            .copied()
            .filter(|client| *client != Client::Codex)
        {
            for (raw, expected) in [
                (br#"{}"#.as_slice(), None),
                (br#"{"mcpServers":{"other":{"command":"private-status-canary"}}}"#.as_slice(), None),
                (br#"{"mcpServers":{"proofline":null}}"#.as_slice(), Some(json!(null))),
                (br#"{"mcpServers":null,"mcpServers":{"proofline":null,"proofline":{"command":"old","command":"proofline","args":[],"args":["mcp"]}}}"#.as_slice(), Some(json!({"command":"proofline","args":["mcp"]}))),
                (br#"{"mcpServers":{"proofline":{},"proofline":null}}"#.as_slice(), Some(json!(null))),
            ] {
                assert_eq!(registration(client, raw).unwrap(), expected);
            }
            for raw in [b"[]".as_slice(), b"null".as_slice()] {
                assert!(matches!(
                    registration(client, raw),
                    Err(InstallError::ConfigShape { member: "root", .. })
                ));
            }
            for raw in [
                br#"{"mcpServers":null}"#.as_slice(),
                br#"{"mcpServers":[]}"#.as_slice(),
            ] {
                assert!(matches!(
                    registration(client, raw),
                    Err(InstallError::ConfigShape {
                        member: "mcpServers",
                        ..
                    })
                ));
            }
            for raw in [b"\xff".as_slice(), b"{".as_slice()] {
                assert!(matches!(
                    registration(client, raw),
                    Err(InstallError::InvalidConfig(_))
                ));
            }
        }
    }

    #[test]
    fn toml_extraction_accepts_tables_and_keeps_syntax_validation_strict() {
        for raw in [
            "[mcp_servers.proofline]\ncommand='proofline'\nargs=['mcp']\n",
            "mcp_servers={proofline={command='proofline',args=['mcp']}}\nwhen=2026-11-06T12:00:00Z\n",
            "'a.b' = { 'c.d' = '''{ [ x.y = z ] }''' } # { [ ignored.key\n[mcp_servers.proofline]\ncommand='proofline'\nargs=['mcp']\n",
        ] {
            assert_eq!(
                registration(Client::Codex, raw.as_bytes()).unwrap(),
                Some(json!({"command":"proofline","args":["mcp"]}))
            );
        }
        for raw in ["", "[mcp_servers.other]\ncommand='other'\n"] {
            assert!(
                registration(Client::Codex, raw.as_bytes())
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            registration(Client::Codex, b"mcp_servers={proofline=42}").unwrap(),
            Some(json!(42))
        );
        assert!(matches!(
            registration(Client::Codex, b"mcp_servers=[]"),
            Err(InstallError::ConfigShape {
                member: "mcp_servers",
                ..
            })
        ));
        for raw in [
            b"\xff".as_slice(),
            b"[mcp_servers.proofline".as_slice(),
            b"private='private-status-canary'\nprivate='duplicate'".as_slice(),
            b"[mcp_servers.proofline]\ncommand='first'\ncommand='last'".as_slice(),
        ] {
            assert!(matches!(
                registration(Client::Codex, raw),
                Err(InstallError::InvalidConfig(_))
            ));
        }
    }

    #[test]
    fn toml_inspection_bounds_structural_depth_including_dotted_keys_and_arrays() {
        for (raw, valid) in [
            (format!("{} = 1\n", vec!["x"; 64].join(".")), true),
            (format!("{} = 1\n", vec!["x"; 65].join(".")), false),
            (format!("a = {{ {} = 1 }}\n", vec!["x"; 63].join(".")), true),
            (
                format!("a = {{ {} = 1 }}\n", vec!["x"; 64].join(".")),
                false,
            ),
            (format!("a = {}1{}\n", "[".repeat(63), "]".repeat(63)), true),
            (
                format!("a = {}1{}\n", "[".repeat(64), "]".repeat(64)),
                false,
            ),
            (format!("[[{}]]\na = 1\n", vec!["x"; 62].join(".")), true),
            (format!("[[{}]]\na = 1\n", vec!["x"; 63].join(".")), false),
        ] {
            let result = registration(Client::Codex, raw.as_bytes());
            if valid {
                assert!(result.unwrap().is_none());
            } else {
                assert!(matches!(
                    result,
                    Err(InstallError::InvalidConfig(Client::Codex))
                ));
            }
        }
        for (ancestors, valid) in [(31, true), (32, false)] {
            let mut raw: String = (1..=ancestors)
                .map(|depth| format!("[[{}]]\n", vec!["x"; depth].join(".")))
                .collect();
            raw.push_str("a = 1\n");
            let result = registration(Client::Codex, raw.as_bytes());
            if valid {
                assert!(result.unwrap().is_none());
            } else {
                assert!(matches!(
                    result,
                    Err(InstallError::InvalidConfig(Client::Codex))
                ));
            }
        }
        let raw = format!(
            "{} = 1\n[mcp_servers]\nproofline = 42\n",
            vec!["x"; 65].join(".")
        );
        let origin = crate::origin::Origin::parse("https://proofline.sh").unwrap();
        assert!(matches!(
            super::prepare(Client::Codex, Some(raw.as_bytes()), &origin),
            Ok(super::Update::Existing)
        ));
    }
}
