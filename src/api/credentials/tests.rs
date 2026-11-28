use super::*;
use crate::proxy::placeholder::scan;
use crate::vault::model::FieldInfo;

fn field(name: &str, kind: FieldKind) -> FieldInfo {
    FieldInfo {
        name: name.into(),
        kind,
    }
}

#[test]
fn detail_offers_ready_placeholders_that_parse_back() {
    let mut e = CredentialEntry::login("1", &["https://pve.lan:8006"]);
    e.has_username = true;
    e.has_totp = true;
    e.fields = vec![
        field("api secret", FieldKind::Hidden),
        field("flag", FieldKind::Boolean),
        field("dup", FieldKind::Text),
        field("dup", FieldKind::Text),
        field("card", FieldKind::LinkedOther),
    ];
    let d = detail("Proxmox (prod)", &[e]);
    assert_eq!(d.kind, Some("login"));
    assert_eq!(d.placeholder.as_deref(), Some("{{vault:'Proxmox (prod)'}}"));
    assert_eq!(
        d.username.as_deref(),
        Some("{{vault:'Proxmox (prod)':username}}")
    );
    assert_eq!(d.totp.as_deref(), Some("{{vault:'Proxmox (prod)':totp}}"));
    assert_eq!(d.notes, None);
    assert_eq!(
        d.fields["api secret"],
        "{{vault:'Proxmox (prod)':field:'api secret'}}"
    );
    assert!(d.fields.contains_key("flag"));
    assert!(d.unavailable_fields["dup"].starts_with("ambiguous"));
    assert!(d.unavailable_fields.contains_key("card"));
    assert_eq!(d.bound_to, vec!["https://pve.lan:8006"]);
    // Every offered placeholder parses back to this item.
    for p in [&d.placeholder, &d.username, &d.totp]
        .into_iter()
        .flatten()
        .chain(d.fields.values())
    {
        let occ = scan(p).unwrap();
        assert_eq!(occ.len(), 1);
        assert!(
            matches!(&occ[0].token, crate::proxy::placeholder::Token::Vault(p) if p.item == "Proxmox (prod)")
        );
    }
}

#[test]
fn detail_marks_ambiguous_and_reprompt_items_unavailable() {
    let a = CredentialEntry::login("1", &[]);
    let d = detail("same", &[a.clone(), a]);
    assert!(d.unavailable.unwrap().starts_with("ambiguous: 2"));
    assert!(d.placeholder.is_none() && d.kind.is_none());

    let mut rp = CredentialEntry::login("2", &["https://x.example"]);
    rp.reprompt = true;
    let d = detail("guarded", &[rp]);
    assert!(d.unavailable.unwrap().contains("re-prompt"));
    assert!(d.placeholder.is_none());
}

fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn detail_param_accepts_existing_values() {
    assert!(!parse_detail(&[]).unwrap());
    for v in ["", "1", "true", "TRUE", "yes"] {
        assert!(parse_detail(&q(&[("detail", v)])).unwrap(), "{v}");
    }
    for v in ["false", "0", "no", "bogus"] {
        assert!(!parse_detail(&q(&[("detail", v)])).unwrap(), "{v}");
    }
}

#[test]
fn detail_param_rejects_unknown_and_repeated() {
    assert!(parse_detail(&q(&[("detial", "true")])).is_err());
    assert!(parse_detail(&q(&[("detail", "true"), ("x", "1")])).is_err());
    assert!(parse_detail(&q(&[("detail", "true"), ("detail", "false")])).is_err());
    assert!(parse_detail(&q(&[("detail", "true"), ("detail", "true")])).is_err());
    assert!(parse_detail(&q(&[("Detail", "true")])).is_err());
}

#[test]
fn detail_secure_note() {
    let mut n = CredentialEntry::login("3", &["https://n.example"]);
    n.kind = ItemKind::SecureNote;
    n.has_password = false;
    n.has_notes = true;
    n.fields = vec![field("token", FieldKind::Hidden)];
    let d = detail("note", &[n]);
    assert_eq!(d.kind, Some("secure_note"));
    assert!(d.placeholder.is_none());
    assert_eq!(d.notes.as_deref(), Some("{{vault:note:notes}}"));
    assert_eq!(d.fields["token"], "{{vault:note:field:token}}");
}

#[test]
fn detail_shows_the_next_placeholder_and_the_flag_only_while_a_rotation_is_pending() {
    let mut e = CredentialEntry::login("1", &["https://a.example"]);
    let d = detail("svc", &[e.clone()]);
    assert_eq!(d.next, None);
    assert!(!d.rotation_pending);
    let json = serde_json::to_value(&d).unwrap();
    assert!(json.get("next").is_none() && json.get("rotation_pending").is_none());

    e.has_next = true;
    let d = detail("Service (prod)", &[e.clone()]);
    assert_eq!(d.next.as_deref(), Some("{{vault:'Service (prod)':next}}"));
    assert!(d.rotation_pending);
    assert_eq!(d.placeholder.as_deref(), Some("{{vault:'Service (prod)'}}"));
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["rotation_pending"], true);
    assert_eq!(json["next"], "{{vault:'Service (prod)':next}}");
    // It parses back to the same item with the `next` selector.
    let occ = scan(d.next.as_deref().unwrap()).unwrap();
    assert!(matches!(
        &occ[0].token,
        crate::proxy::placeholder::Token::Vault(p)
            if p.item == "Service (prod)" && p.selector == Selector::Next
    ));
    // Not for an item that cannot be used (re-prompt) or a note.
    e.reprompt = true;
    assert_eq!(detail("svc", &[e.clone()]).next, None);
    e.reprompt = false;
    e.kind = ItemKind::SecureNote;
    assert_eq!(detail("svc", &[e]).next, None);
}
