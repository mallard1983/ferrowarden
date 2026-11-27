use super::*;
use crate::vault::model::ManagedCollection;

fn managed() -> ManagedState {
    ManagedState::Usable(ManagedCollection {
        id: "coll-1".to_string(),
        organization_id: "org-1".to_string(),
        name: "Ferrowarden managed".to_string(),
        items: 0,
    })
}

#[test]
fn items_with_the_same_name_get_distinct_ids_and_their_own_state() {
    let v = FakeVault::default();
    v.set_managed(managed());
    let a = v.add_managed_item("dup", &[], "value-a");
    let b = v.add_managed_item("dup", &[], "value-b");
    v.add_item("dup", &[]);
    assert_ne!(a, b);
    assert_eq!(v.password_of(&a).as_deref(), Some("value-a"));
    assert_eq!(v.password_of(&b).as_deref(), Some("value-b"));
    // A change to one is not a change to the other.
    v.edit_item(&a, |e| e.has_password = false);
    let listing = &v.items.lock().unwrap()["dup"];
    assert_eq!(listing.len(), 3);
    assert!(!listing.iter().find(|e| e.id == a).unwrap().has_password);
    assert!(listing.iter().find(|e| e.id == b).unwrap().has_password);
    // Every id this fake issues comes from one counter: seeds and created items
    // too, whatever their names.
    let ids: std::collections::HashSet<_> = listing.iter().map(|e| e.id.clone()).collect();
    assert_eq!(ids.len(), 3);
}

#[tokio::test]
async fn a_created_item_never_reuses_an_id_either() {
    let v = FakeVault::default();
    v.set_managed(managed());
    let seeded = v.add_managed_item("one", &[], "x");
    let new = |name: &str| NewLogin {
        name: name.to_string(),
        username: None,
        uris: vec![],
        password: Zeroizing::new("p".to_string()),
        created_by: "k".to_string(),
        approval_required: false,
    };
    let first = v.create_login(new("one")).await.unwrap().unwrap();
    let second = v.create_login(new("one")).await.unwrap().unwrap();
    assert_ne!(first, second);
    assert_ne!(first, seeded);
    assert_ne!(second, seeded);
}
