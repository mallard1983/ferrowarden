
use super::*;

fn openapi() -> Value {
    let yaml = include_str!("../../../docs/openapi.yaml");
    serde_norway::from_str(yaml).expect("docs/openapi.yaml parses")
}

fn string_set(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string").to_string())
        .collect();
    out.sort();
    out
}

fn keys(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_object().expect("an object").keys().cloned().collect();
    out.sort();
    out
}

/// `http_request` takes exactly what `ProxyRequest` in the OpenAPI document
/// takes: the same properties, the same required ones, the same method
/// enum, string-valued headers, and no other properties.
#[test]
fn http_request_schema_matches_openapi_proxy_request() {
    let spec = openapi();
    let proxy = &spec["components"]["schemas"]["ProxyRequest"];
    let ours = Value::Object(http_request_schema());

    assert_eq!(ours["type"], proxy["type"]);
    assert_eq!(ours["additionalProperties"], json!(false));
    assert_eq!(proxy["additionalProperties"], json!(false));
    assert_eq!(keys(&ours["properties"]), keys(&proxy["properties"]));
    assert_eq!(
        string_set(&ours["required"]),
        string_set(&proxy["required"])
    );
    assert_eq!(
        string_set(&ours["properties"]["method"]["enum"]),
        string_set(&proxy["properties"]["method"]["enum"])
    );
    assert_eq!(
        ours["properties"]["method"]["type"],
        proxy["properties"]["method"]["type"]
    );
    assert_eq!(
        ours["properties"]["url"]["type"],
        proxy["properties"]["url"]["type"]
    );
    assert_eq!(
        ours["properties"]["headers"]["type"],
        proxy["properties"]["headers"]["type"]
    );
    assert_eq!(
        ours["properties"]["headers"]["additionalProperties"]["type"],
        proxy["properties"]["headers"]["additionalProperties"]["type"]
    );
    // body is any JSON value in both: no "type" keyword.
    assert!(proxy["properties"]["body"].get("type").is_none());
    assert!(ours["properties"]["body"].get("type").is_none());
}

/// The tool wraps `forwardRequest`: POST /v1/forward with a
/// `{ "request": ProxyRequest }` body.
#[test]
fn http_request_maps_to_forward_request_operation() {
    let spec = openapi();
    let op = &spec["paths"]["/v1/forward"]["post"];
    assert_eq!(op["operationId"], "forwardRequest");
    let payload = &spec["components"]["schemas"]["ForwardPayload"];
    assert_eq!(string_set(&payload["required"]), vec!["request"]);
    assert_eq!(keys(&payload["properties"]), vec!["request"]);

    let args: HttpRequestArgs = serde_json::from_value(json!({
        "method": "POST", "url": "https://api.example.com/x",
        "headers": {"A": "b"}, "body": {"k": 1}
    }))
    .unwrap();
    let sent = args.payload();
    assert_eq!(keys(&sent), vec!["request"]);
    assert_eq!(
        keys(&sent["request"]),
        vec!["body", "headers", "method", "url"]
    );
}

/// `list_credentials` takes no arguments and calls `listCredentials` with
/// `detail=true`, a parameter that exists in the OpenAPI document.
#[test]
fn list_credentials_maps_to_list_credentials_operation() {
    let spec = openapi();
    let op = &spec["paths"]["/v1/credentials"]["get"];
    assert_eq!(op["operationId"], "listCredentials");
    let params = op["parameters"].as_array().unwrap();
    assert!(params
        .iter()
        .any(|p| p["name"] == "detail" && p["in"] == "query"));

    let schema = Value::Object(list_credentials_schema());
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert!(schema["properties"].as_object().unwrap().is_empty());
    assert!(schema.get("required").is_none());
}

#[test]
fn exactly_two_tools_with_stable_names() {
    let tools = definitions();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, vec!["list_credentials", "http_request"]);
    for tool in &tools {
        assert!(tool.description.as_deref().is_some_and(|d| !d.is_empty()));
    }
}

#[test]
fn http_request_description_carries_the_key_rules() {
    let d = HTTP_REQUEST_DESCRIPTION;
    for needle in [
        "{{vault:NAME}}",
        "list_credentials",
        "not in the scheme, host or port",
        "bound to",
        "403 means the request is not allowed for this key or target",
        "do not retry it with other credentials, hosts or methods",
        "tell the user",
        "422",
        "[REDACTED]",
        "echo or transform",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}");
    }
    let l = LIST_CREDENTIALS_DESCRIPTION;
    for needle in ["placeholders", "verbatim", "bound_to"] {
        assert!(l.contains(needle), "description lacks {needle:?}");
    }
}

#[test]
fn arguments_reject_unknown_fields_and_wrong_types() {
    let bad = [
        json!({"method": "GET"}),
        json!({"method": "GET", "url": "https://a.example", "extra": 1}),
        json!({"method": "GET", "url": "https://a.example", "headers": {"A": 1}}),
        json!({"method": 5, "url": "https://a.example"}),
    ];
    for b in bad {
        assert!(serde_json::from_value::<HttpRequestArgs>(b).is_err());
    }
    let ok: HttpRequestArgs =
        serde_json::from_value(json!({"method": "GET", "url": "https://a.example", "body": null}))
            .unwrap();
    assert!(ok.body.is_none());
    assert!(ok.payload()["request"].get("body").is_none());
    assert!(ok.payload()["request"].get("headers").is_none());
}
