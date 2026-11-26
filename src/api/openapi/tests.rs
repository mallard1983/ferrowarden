use super::*;

#[test]
fn the_embedded_spec_parses_and_is_openapi_3_1() {
    let spec = parse_spec().expect("docs/openapi.yaml must parse");
    assert_eq!(spec["openapi"], "3.1.0");
    assert!(spec["paths"].as_object().is_some_and(|p| !p.is_empty()));
}

#[test]
fn spec_version_is_the_crate_version() {
    let spec = parse_spec().unwrap();
    assert_eq!(spec["info"]["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn every_operation_has_a_unique_camel_case_operation_id() {
    let spec = parse_spec().unwrap();
    let mut ids = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for key in OPERATION_KEYS {
            let Some(op) = item.get(key) else { continue };
            let id = op["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{key} {path} has no operationId"));
            let mut chars = id.chars();
            assert!(
                chars.next().is_some_and(|c| c.is_ascii_lowercase())
                    && id.chars().all(|c| c.is_ascii_alphanumeric()),
                "{id} is not camelCase"
            );
            assert!(ids.insert(id.to_string()), "duplicate operationId {id}");
            assert!(
                !op["tags"].as_array().unwrap().is_empty(),
                "{id} has no tag"
            );
            assert!(op["summary"].is_string() && op["description"].is_string());
        }
    }
}

#[test]
fn every_ref_resolves() {
    fn walk(spec: &Value, v: &Value, bad: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "$ref" {
                        let target = x.as_str().unwrap();
                        let pointer = target.strip_prefix('#').expect("local ref");
                        if spec.pointer(pointer).is_none() {
                            bad.push(target.to_string());
                        }
                    } else {
                        walk(spec, x, bad);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(spec, x, bad)),
            _ => {}
        }
    }
    let spec = parse_spec().unwrap();
    let mut bad = Vec::new();
    walk(&spec, &spec, &mut bad);
    assert!(bad.is_empty(), "unresolved refs: {bad:?}");
}

#[test]
fn the_agent_view_has_no_trace_of_the_admin_api() {
    let spec = parse_spec().unwrap();
    let agent = agent_view(&spec);

    let ops: BTreeSet<String> = operations(&agent)
        .into_iter()
        .map(|(m, p)| format!("{m} {p}"))
        .collect();
    let expected: BTreeSet<String> = [
        "GET /health",
        "GET /v1/credentials",
        "POST /v1/forward",
        "GET /v1/sessions",
        "DELETE /v1/sessions/{name}",
        "GET /v1/openapi.json",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(ops, expected);

    // Nothing in the document mentions the operator API at all.
    let text = serde_json::to_string(&agent).unwrap().to_lowercase();
    assert!(!text.contains("admin"), "agent view mentions admin");
    assert!(
        !text.contains("unlockvault"),
        "agent view mentions unlockVault"
    );

    // Only the agent scheme is left, and the shared schemas are kept.
    let schemes = agent["components"]["securitySchemes"].as_object().unwrap();
    assert_eq!(schemes.keys().collect::<Vec<_>>(), ["agentKey"]);
    let schemas = agent["components"]["schemas"].as_object().unwrap();
    for kept in ["Error", "ForwardPayload", "ProxyRequest", "ProxyResponse"] {
        assert!(schemas.contains_key(kept), "{kept}");
    }
    for dropped in ["SecurityEvent", "CreateKeyRequest", "KeySummary", "Status"] {
        assert!(!schemas.contains_key(dropped), "{dropped}");
    }
    // Still a document whose every ref resolves.
    let text = serde_json::to_string(&agent).unwrap();
    let remaining: Vec<_> = text.match_indices("\"#/components/").collect();
    assert!(!remaining.is_empty());
    for (i, _) in remaining {
        let rest = &text[i + 1..];
        let end = rest.find('"').unwrap();
        let pointer = rest[..end].trim_start_matches('#');
        assert!(agent.pointer(pointer).is_some(), "{pointer}");
    }
}

#[test]
fn the_served_documents_carry_the_prefix_only_in_servers() {
    let docs = OpenApiDocs::build("/k7f3q9").unwrap();
    for body in [&docs.agent, &docs.admin] {
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["servers"][0]["url"], "/k7f3q9");
        assert_eq!(body.matches("k7f3q9").count(), 1);
        assert_eq!(v["servers"].as_array().unwrap().len(), 1);
    }
    let plain = OpenApiDocs::build("").unwrap();
    let v: Value = serde_json::from_str(&plain.admin).unwrap();
    assert_eq!(v["servers"][0]["url"], "/");
}

#[test]
fn health_stays_unprefixed_in_every_document() {
    let docs = OpenApiDocs::build("/k7f3q9").unwrap();
    for body in [&docs.agent, &docs.admin] {
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["paths"]["/health"]["get"]["servers"][0]["url"], "/");
    }
}
