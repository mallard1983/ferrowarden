//! Equivalence of the two vault backends.
//!
//! Two Ferrowarden instances run side by side against the same Vaultwarden
//! account (docker-compose.test.yml): `ferrowarden` (port 3000, `bw serve`) and
//! `ferrowarden-native` (port 3003, the native backend). This suite proves they
//! behave the same, field for field. It is the gate for ever making `native`
//! the default backend (GitHub issue #36):
//!
//! 1. `GET /v1/credentials?detail=true` is identical: names, kinds, placeholders,
//!    bindings, unavailable reasons.
//! 2. For **every** placeholder the listing offers (and a set of deliberately
//!    bad ones), a forward to the mock API through each instance gives the same
//!    status and delivers the **same substituted value**. Values are compared in
//!    memory and never printed; a mismatch is reported by placeholder label and
//!    by which side differs.
//!
//! TOTP codes are compared inside one time window (the probes wait for a safe
//! moment and a mismatch is retried once, for a window boundary).
//!
//! Run (the stack must be up, see docs/setup.md):
//! ```sh
//! set -a; . ./.env.test; set +a
//! cargo test --test equivalence -- --nocapture --test-threads=1
//! ```
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `FERROWARDEN_INTEGRATION` | *(unset)* | `1` enables the test |
//! | `FERROWARDEN_TEST_URL` | `http://localhost:3000` | the bw serve instance |
//! | `FERROWARDEN_NATIVE_URL` | `http://localhost:3003` | the native instance |
//! | `FERROWARDEN_TEST_ADMIN_KEY` | *(required)* | admin key (shared by both) |
//! | `FERROWARDEN_EQUIVALENCE_REQUIRED` | *(unset)* | `1`: an unreachable native instance fails instead of skipping |
//! | `MOCK_API_URL` | `http://localhost:7777` | mock API |
//! | `MOCK_API_INTERNAL_URL` | `http://mock-api:7777` | mock API as the instances see it |

use std::collections::BTreeMap;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde_json::{json, Value};

struct Side {
    name: &'static str,
    url: String,
    agent_key: String,
    key_id: String,
}

struct Rig {
    client: Client,
    admin_key: String,
    mock_url: String,
    mock_internal: String,
    sides: [Side; 2],
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl Rig {
    /// `None` skips the test (integration tests not enabled, or the native
    /// instance is not up and not required).
    async fn start() -> Option<Self> {
        if env::var("FERROWARDEN_INTEGRATION").unwrap_or_default() != "1" {
            eprintln!("SKIP: set FERROWARDEN_INTEGRATION=1");
            return None;
        }
        let admin_key = env::var("FERROWARDEN_TEST_ADMIN_KEY")
            .expect("FERROWARDEN_TEST_ADMIN_KEY must be set when FERROWARDEN_INTEGRATION=1");
        let urls = [
            (
                "bw-serve",
                env::var("FERROWARDEN_TEST_URL").unwrap_or_else(|_| "http://localhost:3000".into()),
            ),
            (
                "native",
                env::var("FERROWARDEN_NATIVE_URL")
                    .unwrap_or_else(|_| "http://localhost:3003".into()),
            ),
        ];
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let required = env::var("FERROWARDEN_EQUIVALENCE_REQUIRED").unwrap_or_default() == "1";
        let mut sides = Vec::new();
        for (name, url) in urls {
            let reachable = client
                .get(format!("{url}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if !reachable {
                assert!(!required, "the {name} instance at {url} is not reachable");
                eprintln!("SKIP: the {name} instance at {url} is not reachable");
                return None;
            }
            // A key of this test's own, revoked at the end.
            let resp = client
                .post(format!("{url}/v1/admin/keys"))
                .header("X-Admin-Key", &admin_key)
                .json(
                    &json!({ "name": "equivalence-test", "credentials": ["*"], "methods": ["*"] }),
                )
                .send()
                .await
                .expect("creating the agent key failed");
            assert_eq!(resp.status(), 201, "creating an agent key on {name}");
            let created: Value = resp.json().await.unwrap();
            let token = created["token"].as_str().expect("token").to_string();
            record_secret_for_gate(&token);
            sides.push(Side {
                name,
                url,
                agent_key: token,
                key_id: created["id"].as_str().expect("id").to_string(),
            });
        }
        let [a, b]: [Side; 2] = sides.try_into().ok().unwrap();
        Some(Self {
            client,
            admin_key,
            mock_url: env::var("MOCK_API_URL").unwrap_or_else(|_| "http://localhost:7777".into()),
            mock_internal: env::var("MOCK_API_INTERNAL_URL")
                .unwrap_or_else(|_| "http://mock-api:7777".into()),
            sides: [a, b],
        })
    }

    async fn finish(self) {
        for s in &self.sides {
            let _ = self
                .client
                .delete(format!("{}/v1/admin/keys/{}", s.url, s.key_id))
                .header("X-Admin-Key", &self.admin_key)
                .send()
                .await;
        }
    }

    async fn get_json(&self, side: &Side, path: &str) -> Value {
        let resp = self
            .client
            .get(format!("{}{path}", side.url))
            .header("X-Agent-Key", &side.agent_key)
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status(), 200, "{path} on {}", side.name);
        resp.json().await.expect("not JSON")
    }

    /// Forward one request carrying `placeholder` in its JSON body and report what
    /// the mock API received. The captured value stays in memory.
    async fn probe(&self, side: &Side, placeholder: &str) -> Outcome {
        self.client
            .post(format!("{}/__reset__", self.mock_url))
            .send()
            .await
            .expect("mock reset failed");
        let resp = self
            .client
            .post(format!("{}/v1/forward", side.url))
            .header("X-Agent-Key", &side.agent_key)
            // The placeholder goes in a JSON body: unlike a header it can carry
            // any text (multi-line notes, Unicode), and the substitution into
            // the JSON structure is part of what is compared.
            .json(&json!({ "request": {
                "method": "POST",
                "url": format!("{}/mock-api/equivalence", self.mock_internal),
                "body": { "probe": placeholder },
            }}))
            .send()
            .await
            .expect("forward failed");
        let status = resp.status().as_u16();
        if status != 200 {
            return Outcome {
                status,
                value: None,
            };
        }
        let captured: Value = self
            .client
            .get(format!("{}/__requests__/last", self.mock_url))
            .send()
            .await
            .expect("mock request failed")
            .json()
            .await
            .expect("mock response was not JSON");
        let value = captured["body"].as_str().map(str::to_string);
        Outcome { status, value }
    }
}

/// What one instance did with a probe. `Debug` is not derived: the value is
/// a credential.
struct Outcome {
    status: u16,
    value: Option<String>,
}

fn record_secret_for_gate(value: &str) {
    use std::io::Write;
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/integration-secrets.txt");
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{value}");
    }
}

/// Which selector a placeholder uses, for the per-kind counts.
fn kind_of(placeholder: &str) -> &'static str {
    if placeholder.contains(":field:") {
        "field"
    } else if placeholder.ends_with(":username}}") {
        "username"
    } else if placeholder.ends_with(":totp}}") {
        "totp"
    } else if placeholder.ends_with(":notes}}") {
        "notes"
    } else {
        "password"
    }
}

/// Every placeholder a detailed listing offers, with a label for reports.
fn offered_placeholders(listing: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for item in listing.as_array().expect("listing is an array") {
        let name = item["name"].as_str().unwrap_or("?");
        for key in ["placeholder", "username", "totp", "notes"] {
            if let Some(p) = item[key].as_str() {
                out.push((format!("{name} ({key})"), p.to_string()));
            }
        }
        if let Some(fields) = item["fields"].as_object() {
            for (field, p) in fields {
                if let Some(p) = p.as_str() {
                    out.push((format!("{name} (field {field})"), p.to_string()));
                }
            }
        }
    }
    out
}

/// Wait until a safe point inside a 30 second TOTP window, so two forwards a
/// few milliseconds apart cannot straddle a boundary (60 s periods too).
async fn wait_for_window() {
    loop {
        let into = now() % 30;
        if (1..=24).contains(&into) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn credential_listings_are_identical() {
    let Some(rig) = Rig::start().await else {
        return;
    };
    let [bw, native] = &rig.sides;

    let plain_bw = rig.get_json(bw, "/v1/credentials").await;
    let plain_native = rig.get_json(native, "/v1/credentials").await;
    let detail_bw = rig.get_json(bw, "/v1/credentials?detail=true").await;
    let detail_native = rig.get_json(native, "/v1/credentials?detail=true").await;

    // Report any difference by credential name and key, never a whole value.
    let mut diffs = Vec::new();
    let index = |v: &Value| -> BTreeMap<String, Value> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|d| (d["name"].as_str().unwrap().to_string(), d.clone()))
            .collect()
    };
    let (ib, inat) = (index(&detail_bw), index(&detail_native));
    for name in ib
        .keys()
        .chain(inat.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        match (ib.get(name), inat.get(name)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => {
                let keys: std::collections::BTreeSet<_> = a
                    .as_object()
                    .unwrap()
                    .keys()
                    .chain(b.as_object().unwrap().keys())
                    .collect();
                for k in keys {
                    if a.get(k) != b.get(k) {
                        diffs.push(format!("{name}: `{k}` differs"));
                    }
                }
            }
            (Some(_), None) => diffs.push(format!("{name}: only in the bw serve listing")),
            (None, Some(_)) => diffs.push(format!("{name}: only in the native listing")),
            (None, None) => {}
        }
    }
    assert!(
        diffs.is_empty(),
        "detailed listings differ:\n{}",
        diffs.join("\n")
    );
    assert_eq!(plain_bw, plain_native, "name listings differ");
    assert_eq!(detail_bw, detail_native);

    // The listing must be meaningful: the new fixtures are in it, and the
    // item types that are not offered are in neither.
    let names: Vec<&str> = plain_bw
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for expected in [
        "fx_cipherkey_login",
        "fx_org_login",
        "fx_org_note_ck",
        "fx_totp_steam",
        "fx_fields_mix",
        "test_login_full",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing: is the stack seeded?"
        );
    }
    for hidden in ["fx_card", "fx_identity", "fx_ssh"] {
        assert!(!names.contains(&hidden), "{hidden} must not be offered");
    }
    println!(
        "listings identical: {} credentials, {} offered placeholders",
        names.len(),
        offered_placeholders(&detail_bw).len()
    );
    rig.finish().await;
}

#[tokio::test]
async fn every_offered_placeholder_substitutes_the_same_value() {
    let Some(rig) = Rig::start().await else {
        return;
    };
    let [bw, native] = &rig.sides;
    let listing = rig.get_json(bw, "/v1/credentials?detail=true").await;
    let mut probes = offered_placeholders(&listing);

    // Placeholders that must fail the same way on both sides.
    for (label, p) in [
        ("unknown item", "{{vault:does_not_exist}}"),
        ("ambiguous field", "{{vault:test_login_full:field:dup}}"),
        ("re-prompt item", "{{vault:test_reprompt}}"),
        ("bound to another host", "{{vault:test_unbound}}"),
        ("card is not offered", "{{vault:fx_card}}"),
        ("SSH key is not offered", "{{vault:fx_ssh}}"),
        ("identity is not offered", "{{vault:fx_identity:notes}}"),
        ("missing field", "{{vault:fx_cipherkey_login:field:nope}}"),
        (
            "note has no password",
            "{{vault:fx_cipherkey_note:password}}",
        ),
        ("no URIs", "{{vault:fx_edge_no_uris}}"),
        ("blank password", "{{vault:fx_edge_blank_password}}"),
        (
            "empty-string username",
            "{{vault:fx_edge_empty_username:username}}",
        ),
        ("archived item", "{{vault:fx_archived}}"),
    ] {
        probes.push((format!("negative: {label}"), p.to_string()));
    }

    wait_for_window().await;
    // kind -> (compared, with a value delivered)
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut mismatches = Vec::new();
    for (label, placeholder) in &probes {
        let mut a = rig.probe(bw, placeholder).await;
        let mut b = rig.probe(native, placeholder).await;
        if (a.status, &a.value) != (b.status, &b.value) && kind_of(placeholder) == "totp" {
            // A window boundary between the two forwards: once more, together.
            wait_for_window().await;
            a = rig.probe(bw, placeholder).await;
            b = rig.probe(native, placeholder).await;
        }
        let kind = if label.starts_with("negative") {
            "negative"
        } else {
            kind_of(placeholder)
        };
        let e = counts.entry(kind).or_default();
        e.0 += 1;
        e.1 += usize::from(a.value.is_some());
        if a.status != b.status {
            mismatches.push(format!(
                "{label}: HTTP status differs (bw-serve {}, native {})",
                a.status, b.status
            ));
        } else if a.value != b.value {
            // Never print either value: say only which sides delivered one.
            mismatches.push(format!(
                "{label}: the substituted values differ (bw-serve delivered {}, native delivered {})",
                a.value.as_ref().map_or("nothing".into(), |v| format!("{} chars", v.len())),
                b.value.as_ref().map_or("nothing".into(), |v| format!("{} chars", v.len())),
            ));
        }
    }

    println!("placeholders compared by kind (compared, with a value delivered):");
    for (k, (n, v)) in &counts {
        println!("  {k:<9} {n:>3} compared, {v:>3} delivered a value");
    }
    println!(
        "  total     {:>3} compared, {} mismatches",
        probes.len(),
        mismatches.len()
    );
    assert!(
        mismatches.is_empty(),
        "backends disagree:\n{}",
        mismatches.join("\n")
    );
    // The comparison must have covered every kind of value for real.
    for kind in ["password", "username", "totp", "notes", "field"] {
        assert!(
            counts.get(kind).is_some_and(|c| c.1 >= 3),
            "too few {kind} values were compared: {counts:?}"
        );
    }
    rig.finish().await;
}
