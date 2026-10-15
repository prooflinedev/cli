//! The versioned CLI result preserves the public API's complete review document.

use serde_json::{Map, Value, json};

pub(crate) const FORMAT: &str = "proofline.review-result.v1";

#[derive(Debug, thiserror::Error)]
pub(crate) enum SchemaError {
    #[error("the bundled public API schema could not be read: {0}")]
    BundledContract(#[from] serde_json::Error),
    #[error("the bundled public API schema has no definition {0}")]
    MissingDefinition(String),
    #[error("the bundled public API schema uses an unsupported reference {0}")]
    UnsupportedReference(String),
}

/// Uses the schema of the exact public route the CLI polls. Definitions keep
/// their required fields and extension policy; only local references change.
pub(crate) fn schema() -> Result<Value, SchemaError> {
    let public: Value = serde_json::from_str(include_str!("../openapi.public.json"))?;
    let mut definitions = Map::new();
    let mut pending = vec!["CustomerReviewDetail".to_owned()];
    while let Some(name) = pending.pop() {
        if definitions.contains_key(&name) {
            continue;
        }
        let mut definition = public["components"]["schemas"]
            .get(&name)
            .ok_or_else(|| SchemaError::MissingDefinition(name.clone()))?
            .clone();
        local_references(&mut definition, &mut pending)?;
        definitions.insert(name, definition);
    }
    Ok(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": FORMAT,
        "type": "object",
        "required": ["schema", "outcome", "review_url", "review"],
        "additionalProperties": false,
        "properties": {
            "schema": { "const": FORMAT },
            "outcome": {
                "enum": ["COMPLETED", "INCOMPLETE", "FAILED", "STOPPED", null],
                "description": "The CLI's reading of completeness; null while the review runs."
            },
            "review_url": { "type": "string", "format": "uri" },
            "review": { "$ref": "#/$defs/CustomerReviewDetail" }
        },
        "$defs": definitions
    }))
}

fn local_references(node: &mut Value, pending: &mut Vec<String>) -> Result<(), SchemaError> {
    match node {
        Value::Object(properties) => {
            if let Some(reference) = properties.get_mut("$ref")
                && let Some(path) = reference.as_str()
            {
                let name = path
                    .strip_prefix("#/components/schemas/")
                    .ok_or_else(|| SchemaError::UnsupportedReference(path.to_owned()))?
                    .to_owned();
                *reference = json!(format!("#/$defs/{name}"));
                pending.push(name);
            }
            for property in properties.values_mut() {
                local_references(property, pending)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                local_references(item, pending)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}
