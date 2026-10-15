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
        Client::Cursor | Client::Gemini | Client::Kiro => json(client, original, origin),
    }
}

fn arguments(origin: &Origin) -> [String; 3] {
    ["--base-url".to_owned(), origin.as_key(), "mcp".to_owned()]
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
            servers.insert("proofline", Item::Table(codex_server(args)));
            document.insert("mcp_servers", Item::Table(servers));
        }
        Some(Item::Table(servers)) => {
            if servers.contains_key("proofline") {
                return Ok(Update::Existing);
            }
            servers.insert("proofline", Item::Table(codex_server(args)));
        }
        Some(Item::Value(toml_edit::Value::InlineTable(servers))) => {
            if servers.contains_key("proofline") {
                return Ok(Update::Existing);
            }
            let mut server = InlineTable::new();
            server.insert("command", "proofline".into());
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

fn codex_server(args: Array) -> Table {
    let mut server = Table::new();
    server.insert("command", toml_edit::value("proofline"));
    server.insert("args", toml_edit::value(args));
    server
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
    if client == Client::Cursor {
        server.insert("type".to_owned(), Value::String("stdio".to_owned()));
    }
    server.insert("command".to_owned(), Value::String("proofline".to_owned()));
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
