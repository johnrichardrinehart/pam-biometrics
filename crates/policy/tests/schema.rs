//! Checks that the published JSON Schema and the Rust types agree.

use std::path::{Path, PathBuf};

use boon::{Compiler, SchemaIndex, Schemas};
use pam_biometrics_policy::{Policy, Settings};
use serde_json::{Value, json};

const SCHEMA_ID: &str =
    "https://github.com/johnrichardrinehart/pam-biometrics/schema/policy.schema.json";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn compile() -> (Schemas, SchemaIndex) {
    let schema = read_json(&repository().join("schema/policy.schema.json"));
    assert_eq!(schema["$id"], SCHEMA_ID);
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler.add_resource(SCHEMA_ID, schema).unwrap();
    let index = compiler.compile(SCHEMA_ID, &mut schemas).unwrap();
    (schemas, index)
}

#[test]
fn examples_validate() {
    let (schemas, index) = compile();
    let mut count = 0;
    for entry in std::fs::read_dir(repository().join("examples")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let document = read_json(&path);
        if let Err(error) = schemas.validate(&document, index) {
            panic!("{}: {error}", path.display());
        }
        Policy::parse(&document.to_string(), &path.display().to_string())
            .unwrap_or_else(|error| panic!("{error}"));
        count += 1;
    }
    assert!(count >= 2, "found {count} examples");
}

#[test]
fn resolved_settings_are_a_valid_layer() {
    let (schemas, index) = compile();
    let document = json!({ "version": 1, "defaults": Settings::default() });
    schemas.validate(&document, index).unwrap();
    let mut prompted = Settings {
        password_prompt: Some("Password (type f to scan face): ".to_owned()),
        finish_prompt: Some("Type f to scan your face: ".to_owned()),
        ..Settings::default()
    };
    prompted.face.trigger = "f".to_owned();
    let document = json!({ "version": 1, "defaults": prompted });
    schemas.validate(&document, index).unwrap();
}

#[test]
fn schema_and_types_reject_the_same_documents() {
    let (schemas, index) = compile();
    for document in [
        json!({}),
        json!({ "version": 2 }),
        json!({ "version": 1, "extra": 1 }),
        json!({ "version": 1, "defaults": { "factors": ["iris"] } }),
        json!({ "version": 1, "defaults": { "factors": ["face", "face"] } }),
        json!({ "version": 1, "defaults": { "factors": null } }),
        json!({ "version": 1, "defaults": { "combine": "first" } }),
        json!({ "version": 1, "defaults": { "on_no_decision": "maybe" } }),
        json!({ "version": 1, "defaults": { "timeout_seconds": 0 } }),
        json!({ "version": 1, "defaults": { "timeout_seconds": 1.5 } }),
        json!({ "version": 1, "defaults": { "prompt": "Scan your face." } }),
        json!({ "version": 1, "defaults": { "password_prompt": " " } }),
        json!({ "version": 1, "defaults": { "password_prompt": "Pass\nword: " } }),
        json!({ "version": 1, "defaults": { "finish_prompt": "" } }),
        json!({ "version": 1, "defaults": { "finish_prompt": "Press\tEnter: " } }),
        json!({ "version": 1, "defaults": { "face": { "trigger": "f\n" } } }),
        json!({ "version": 1, "defaults": { "face": { "trigger": 1 } } }),
        json!({ "version": 1, "defaults": { "fingerprint": { "max_tries": 0 } } }),
        json!({ "version": 1, "defaults": { "fingerprint": { "tries": 2 } } }),
        json!({ "version": 1, "defaults": { "face": { "match_distance": 0 } } }),
        json!({ "version": 1, "defaults": { "face": { "reject_distance": -1 } } }),
        json!({ "version": 1, "defaults": { "face": { "min_reject_frames": 0 } } }),
        json!({ "version": 1, "services": { "sudo": { "unknown": true } } }),
        json!({ "version": 1, "users": { "alice": { "service": {} } } }),
    ] {
        assert!(
            schemas.validate(&document, index).is_err(),
            "schema accepted {document}"
        );
        assert!(
            Policy::parse(&document.to_string(), "test").is_err(),
            "types accepted {document}"
        );
    }
}
