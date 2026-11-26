use super::*;
use crate::vault::model::FieldLookup;

fn parse(items: &str) -> CredentialMap {
    let raw = format!(r#"{{"success":true,"data":{{"object":"list","data":[{items}]}}}}"#);
    let body: BwResponse<BwListData> = serde_json::from_str(&raw).unwrap();
    let mut map = CredentialMap::new();
    for item in body.data.unwrap().data {
        if let Some((name, entry)) = entry_from_item(item) {
            map.entry(name).or_default().push(entry);
        }
    }
    map
}

#[test]
fn login_metadata_without_values() {
    let map = parse(
        r#"{"id":"1","name":"full","type":1,"reprompt":0,"notes":"N",
                "login":{"username":"u","password":"SECRET","totp":"JBSW",
                         "uris":[{"uri":"https://a.example"},{"uri":"^re$","match":4},
                                 {"uri":"https://never.example","match":5},{"uri":"b.example","match":0}]},
                "fields":[{"name":"api_key","value":"V","type":1},
                          {"name":"flag","value":"true","type":2},
                          {"name":"lu","type":3,"linkedId":100},
                          {"name":"lp","type":3,"linkedId":101},
                          {"name":"dup","value":"1","type":0},{"name":"dup","value":"2","type":0}]}"#,
    );
    let e = &map["full"][0];
    assert_eq!(e.kind, ItemKind::Login);
    assert!(e.has_username && e.has_password && e.has_totp && e.has_notes && !e.reprompt);
    assert_eq!(
        e.uris,
        vec!["https://a.example", "b.example"],
        "regex/never URIs dropped"
    );
    assert!(matches!(e.field("api_key"), FieldLookup::Unique(f) if f.kind == FieldKind::Hidden));
    assert!(matches!(e.field("flag"), FieldLookup::Unique(f) if f.kind == FieldKind::Boolean));
    assert!(matches!(e.field("lu"), FieldLookup::Unique(f) if f.kind == FieldKind::LinkedUsername));
    assert!(matches!(e.field("lp"), FieldLookup::Unique(f) if f.kind == FieldKind::LinkedPassword));
    assert!(matches!(e.field("dup"), FieldLookup::Duplicate));
    assert!(matches!(e.field("nope"), FieldLookup::Missing));
    // The debug form must not contain any value.
    let dbg = format!("{e:?}");
    assert!(!dbg.contains("SECRET") && !dbg.contains("JBSW"));
}

#[test]
fn secure_note_bindings_from_reserved_field_and_unsupported_types_skipped() {
    let map = parse(
        r#"{"id":"2","name":"note","type":2,"notes":"body","secureNote":{"type":0},
                "fields":[{"name":"ferrowarden_uris","value":"https://n.example, ssh://host\nhttps://m.example","type":0},
                          {"name":"token","value":"T","type":1}]},
               {"id":"3","name":"card","type":3,"card":{"number":"4111"}},
               {"id":"5","name":"key","type":5,"sshKey":{"privateKey":"K"}},
               {"id":"6","name":"rp","type":1,"reprompt":1,"login":{"password":"P"}}"#,
    );
    let n = &map["note"][0];
    assert_eq!(n.kind, ItemKind::SecureNote);
    assert_eq!(
        n.uris,
        vec!["https://n.example", "ssh://host", "https://m.example"]
    );
    assert!(!n.has_password && n.has_notes);
    assert!(
        matches!(n.field("ferrowarden_uris"), FieldLookup::Missing),
        "reserved field hidden"
    );
    assert!(!map.contains_key("card") && !map.contains_key("key"));
    assert!(map["rp"][0].reprompt);
}

#[test]
fn bindings_field_overrides_login_uris() {
    let map = parse(
        r#"{"id":"1","name":"x","type":1,"login":{"password":"P","uris":[{"uri":"https://autofill.example"}]},
                "fields":[{"name":"ferrowarden_uris","value":"https://api.example","type":0}]}"#,
    );
    assert_eq!(map["x"][0].uris, vec!["https://api.example"]);
}

fn item_doc(fields: &str) -> Value {
    serde_json::from_str(&format!(
            r#"{{"success":true,"data":{{"login":{{"username":"USER","password":"PASS"}},"fields":[{fields}]}}}}"#
        ))
        .unwrap()
}

#[test]
fn extract_field_values_and_links() {
    let doc = item_doc(
        r#"{"name":"k","value":"V","type":1},{"name":"lu","type":3,"linkedId":100},
               {"name":"lp","type":3,"linkedId":101},{"name":"d","value":"1","type":0},{"name":"d","value":"2","type":0},
               {"name":"empty","value":null,"type":0}"#,
    );
    assert_eq!(extract_field(&doc, "k", "x").unwrap().as_str(), "V");
    assert_eq!(extract_field(&doc, "lu", "x").unwrap().as_str(), "USER");
    assert_eq!(extract_field(&doc, "lp", "x").unwrap().as_str(), "PASS");
    assert!(matches!(
        extract_field(&doc, "d", "x"),
        Err(FerroError::AmbiguousField { .. })
    ));
    assert!(matches!(
        extract_field(&doc, "missing", "x"),
        Err(FerroError::CredentialNotFound(_))
    ));
    assert!(matches!(
        extract_field(&doc, "empty", "x"),
        Err(FerroError::CredentialNotFound(_))
    ));
}

#[test]
fn a_hidden_password_item_from_bw_serve_has_no_password_and_no_view_password_field() {
    // What `bw serve` returns for an organisation item whose collection hides
    // passwords from the account (checked against CLI 2026.11.0 and 2026.5.0):
    // no `viewPassword` field anywhere and a null `login.password`. The CLI
    // withholds the password itself, so Ferrowarden lists the item without a
    // password placeholder; it cannot tell the item apart (docs/native-vault.md).
    let map = parse(
        r#"{"id":"h1","name":"hidden","type":1,"reprompt":0,"organizationId":"org1",
                "collectionIds":["c1"],"notes":null,
                "login":{"username":"U","password":null,"totp":null,
                         "uris":[{"uri":"http://mock-api:7777","match":null}]}}"#,
    );
    let e = &map["hidden"][0];
    assert!(e.has_username && !e.has_password && !e.has_notes);
    assert_eq!(e.uris, vec!["http://mock-api:7777"]);
}
