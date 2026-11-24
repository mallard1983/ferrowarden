//! Per-agent-key access policy: which credentials a key may reference and
//! which HTTP methods it may forward.
//!
//! # Semantics
//!
//! * `credentials` is a list of patterns matched against the credential
//!   (item) name, i.e. [`Placeholder::item`] after unquoting. `*` is the only
//!   wildcard; it matches any run of characters, including none. Matching is
//!   anchored at both ends and case-sensitive. There is no escaping: a literal
//!   `*` in a name is matched by the wildcard anyway.
//! * `methods` is a list drawn from [`METHODS`], case-insensitive on input and
//!   stored upper-case.
//! * `["*"]` is unrestricted, spelled out. `[]` means nothing is allowed.
//!   There is no "unset means everything" state anywhere: a key must be given
//!   both lists when it is created, and a legacy key without them is
//!   deny-all until a policy is set.
//!
//! # No null
//!
//! `null` is never a policy value, in a key file or in an API body: a client
//! bug or a typo must not turn into a different policy. The deserializers here
//! reject it, and [`Patch`] keeps "field absent" distinct from "field present".

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fmt;

use crate::error::{FerroError, FerroResult};
use crate::proxy::placeholder::Placeholder;

/// The HTTP methods a key can be allowed (and `/v1/forward` accepts), in
/// canonical order.
pub const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Most credential patterns on one key.
pub const MAX_PATTERNS: usize = 256;
/// Longest credential pattern, in characters.
pub const MAX_PATTERN_CHARS: usize = 256;

/// The access policy of one agent key. `Default` is deny-all (fail closed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyPolicy {
    /// Credential name patterns; `["*"]` = every credential, `[]` = none.
    pub credentials: Vec<String>,
    /// Allowed methods from [`METHODS`]; `["*"]` = all of them, `[]` = none.
    pub methods: Vec<String>,
}

impl KeyPolicy {
    /// Build a validated, normalised policy from raw lists.
    pub fn from_raw(credentials: Vec<String>, methods: Vec<String>) -> FerroResult<Self> {
        Ok(Self {
            credentials: validate_credentials(credentials)?,
            methods: validate_methods(methods)?,
        })
    }

    /// Apply a patch: a present field replaces the old value (and is
    /// validated), an absent one is left alone.
    pub fn patched(
        &self,
        credentials: Patch<Vec<String>>,
        methods: Patch<Vec<String>>,
    ) -> FerroResult<Self> {
        let mut out = self.clone();
        if let Patch::Value(list) = credentials {
            out.credentials = validate_credentials(list)?;
        }
        if let Patch::Value(list) = methods {
            out.methods = validate_methods(list)?;
        }
        Ok(out)
    }

    /// Does the policy let the key reference a credential called `name`?
    pub fn allows_credential(&self, name: &str) -> bool {
        self.credentials.iter().any(|p| wildcard_match(p, name))
    }

    /// Does the policy let the key use `method`? `method` must already be
    /// validated and upper-case (see `ProxyRequest::normalized_method`).
    pub fn allows_method(&self, method: &str) -> bool {
        METHODS.contains(&method) && self.methods.iter().any(|m| m == "*" || m == method)
    }

    /// The checks `/v1/forward` runs before anything else, in order: method,
    /// then every placeholder's credential name.
    ///
    /// The scope check looks only at the names the caller sent, never at the
    /// vault, so the result is identical whether or not a credential exists
    /// (no existence oracle). The first out-of-scope placeholder in sorted
    /// order is reported, which is again independent of the vault.
    pub fn check_request(
        &self,
        method: &str,
        placeholders: &BTreeSet<Placeholder>,
    ) -> FerroResult<()> {
        if !self.allows_method(method) {
            return Err(FerroError::MethodNotAllowed(method.to_string()));
        }
        match placeholders
            .iter()
            .find(|p| !self.allows_credential(&p.item))
        {
            Some(p) => Err(FerroError::CredentialOutOfScope(p.label())),
            None => Ok(()),
        }
    }

    /// Would replacing this policy with `draft` give the key more access? True
    /// if `draft` allows a method this one does not, or has a credential
    /// pattern that this policy's patterns do not cover. The pattern test is
    /// conservative and independent of the vault: a pattern is covered if one
    /// of ours matches it read literally (its `*` characters as plain text),
    /// which holds exactly when every name the pattern can match is matched.
    /// So `uptime_a*` is covered by `uptime_*`, `up*` is not.
    pub fn is_widened_by(&self, draft: &KeyPolicy) -> bool {
        let methods_wider = METHODS
            .iter()
            .any(|m| draft.allows_method(m) && !self.allows_method(m));
        let patterns_wider = draft.credentials.iter().any(|p| !self.allows_credential(p));
        methods_wider || patterns_wider
    }

    /// `{ "credentials": [...], "methods": [...] }`, as shown in API output
    /// and events.
    pub fn to_json(&self) -> Value {
        json!({ "credentials": self.credentials, "methods": self.methods })
    }
}

// ── Wildcard matching ─────────────────────────────────────────────────────────

/// Match `name` against `pattern`, where `*` matches any run of characters
/// (including none). Anchored at both ends, case-sensitive, by characters.
///
/// Iterative with a single backtrack point (the most recent `*`): O(n·m) in
/// the worst case, no recursion and no regex, so a hostile pattern or name
/// cannot blow the stack or cause exponential work.
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();

    // Cheap necessary condition: every non-wildcard character must be used.
    if p.iter().filter(|&&c| c != '*').count() > n.len() {
        return false;
    }

    let (mut pi, mut ni) = (0usize, 0usize);
    // Position of the last `*` in the pattern, and where in the name its
    // current expansion ends.
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ni;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some(s) = star {
            // Let the last `*` swallow one more character and retry.
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validate credential patterns. A pattern that is exactly `*` collapses the
/// list to `["*"]`; otherwise the result is de-duplicated, in the given order.
pub fn validate_credentials(patterns: Vec<String>) -> FerroResult<Vec<String>> {
    if patterns.len() > MAX_PATTERNS {
        return Err(FerroError::InvalidRequest(format!(
            "credentials may have at most {MAX_PATTERNS} patterns"
        )));
    }
    // No pre-sized allocation from the request-controlled length (the bound
    // above already holds, but growing on demand keeps that obvious).
    let mut out: Vec<String> = Vec::new();
    for (i, pattern) in patterns.into_iter().enumerate() {
        let chars = pattern.chars().count();
        if chars == 0 || chars > MAX_PATTERN_CHARS {
            return Err(FerroError::InvalidRequest(format!(
                "credentials[{i}]: a pattern must be 1-{MAX_PATTERN_CHARS} characters"
            )));
        }
        if pattern.chars().any(char::is_control) {
            return Err(FerroError::InvalidRequest(format!(
                "credentials[{i}]: a pattern may not contain control characters"
            )));
        }
        if !out.contains(&pattern) {
            out.push(pattern);
        }
    }
    if out.iter().any(|p| p == "*") {
        return Ok(vec!["*".to_string()]);
    }
    Ok(out)
}

/// Validate and normalise methods: case-insensitive, upper-cased,
/// de-duplicated, in canonical order. `["*"]` stays `["*"]` (all methods);
/// `*` mixed with other entries is rejected as ambiguous.
pub fn validate_methods(methods: Vec<String>) -> FerroResult<Vec<String>> {
    if methods.len() > MAX_PATTERNS {
        return Err(FerroError::InvalidRequest(format!(
            "methods may have at most {MAX_PATTERNS} entries"
        )));
    }
    let mut set = BTreeSet::new();
    for m in methods {
        let upper = m.to_ascii_uppercase();
        if upper != "*" && !METHODS.contains(&upper.as_str()) {
            return Err(FerroError::InvalidRequest(format!(
                "methods: unsupported method; allowed are {} or \"*\"",
                METHODS.join(", ")
            )));
        }
        set.insert(upper);
    }
    if set.contains("*") {
        if set.len() > 1 {
            return Err(FerroError::InvalidRequest(
                "methods: \"*\" must be the only entry".to_string(),
            ));
        }
        return Ok(vec!["*".to_string()]);
    }
    Ok(METHODS
        .iter()
        .filter(|m| set.contains(**m))
        .map(|m| m.to_string())
        .collect())
}

/// Normalise a request method: upper-case, and it must be one of [`METHODS`].
pub fn normalize_method(method: &str) -> FerroResult<String> {
    let upper = method.to_ascii_uppercase();
    if METHODS.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(FerroError::InvalidRequest(format!(
            "method must be one of {}",
            METHODS.join(", ")
        )))
    }
}

// ── Absent vs present, never null ─────────────────────────────────────────────

/// A request field that is either left out or given a value. There is no
/// third "null" state: it is a parse error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Patch<T> {
    #[default]
    Absent,
    Value(T),
}

impl<T> Patch<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Patch::Absent)
    }
}

/// Visitor for a policy list: an array of strings, anything else (null
/// included) is an error that names the field. The messages start with
/// "policy field `" so that `strict_json` passes them through to the client
/// (they never contain a value from the body).
struct ListVisitor(&'static str);

impl ListVisitor {
    fn wrong<E: de::Error>(&self, what: &str) -> E {
        E::custom(format!(
            "policy field `{}` must be an array of strings, not {what}",
            self.0
        ))
    }
}

impl<'de> Visitor<'de> for ListVisitor {
    type Value = Vec<String>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "an array of strings for `{}`", self.0)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom(format!(
            "policy field `{}` must be an array of strings, not null; \
             leave it out to keep the default, or send [\"*\"] to allow everything",
            self.0
        )))
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Err(self.wrong("a boolean"))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Err(self.wrong("a number"))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Err(self.wrong("a number"))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(self.wrong("a number"))
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Err(self.wrong("a string"))
    }
    fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.wrong("an object"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(item) = seq.next_element::<String>()? {
            out.push(item);
        }
        Ok(out)
    }
}

fn list<'de, D: Deserializer<'de>>(d: D, field: &'static str) -> Result<Vec<String>, D::Error> {
    // `deserialize_any` so that JSON null reaches `visit_unit` (serde_json's
    // `deserialize_seq` would report it as a generic type error).
    d.deserialize_any(ListVisitor(field))
}

/// `deserialize_with` helpers: one set per field so errors can name it.
/// `patch_*` is for PATCH/preview bodies (`#[serde(default)]`: absent =
/// [`Patch::Absent`]); `required_*` is for create bodies (no default, so a
/// missing field is a "missing field" error); `stored_*` is for the key file
/// (`Option`: absent = a legacy entry written before policies existed). All
/// reject `null`.
macro_rules! list_fields {
    ($patch:ident, $required:ident, $stored:ident, $field:literal) => {
        pub fn $patch<'de, D: Deserializer<'de>>(d: D) -> Result<Patch<Vec<String>>, D::Error> {
            list(d, $field).map(Patch::Value)
        }
        pub fn $required<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
            list(d, $field)
        }
        pub fn $stored<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
            list(d, $field).map(Some)
        }
    };
}
list_fields!(
    patch_credentials,
    required_credentials,
    stored_credentials,
    "credentials"
);
list_fields!(patch_methods, required_methods, stored_methods, "methods");

/// For an optional nested object (`request`): absent is `None`, `null` is an
/// error rather than another way of saying "absent".
pub fn some_not_null<'de, T: serde::Deserialize<'de>, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(c: &[&str], m: &[&str]) -> KeyPolicy {
        KeyPolicy::from_raw(
            c.iter().map(|s| s.to_string()).collect(),
            m.iter().map(|s| s.to_string()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn widening_is_detected_for_methods_and_patterns() {
        let saved = pol(&["uptime_*"], &["GET"]);
        // Same, narrower, or covered: not widening.
        assert!(!saved.is_widened_by(&saved));
        assert!(!saved.is_widened_by(&pol(&["uptime_api"], &["GET"])));
        assert!(!saved.is_widened_by(&pol(&["uptime_a*"], &["GET"])));
        assert!(!saved.is_widened_by(&pol(&[], &[])));
        assert!(!saved.is_widened_by(&pol(&["uptime_*"], &[])));
        // Wider patterns or methods.
        assert!(saved.is_widened_by(&pol(&["up*"], &["GET"])));
        assert!(saved.is_widened_by(&pol(&["*"], &["GET"])));
        assert!(saved.is_widened_by(&pol(&["uptime_*", "other"], &["GET"])));
        assert!(saved.is_widened_by(&pol(&["uptime_*"], &["GET", "POST"])));
        assert!(saved.is_widened_by(&pol(&["uptime_*"], &["*"])));
        // `*` covers everything; all methods cover each method.
        let all = pol(&["*"], &["*"]);
        assert!(!all.is_widened_by(&pol(&["a*", "b"], &["GET", "DELETE"])));
        assert!(!all.is_widened_by(&all));
        // A deny-all (legacy) key is widened by anything non-empty.
        let none = KeyPolicy::default();
        assert!(none.is_widened_by(&pol(&["a"], &[])));
        assert!(none.is_widened_by(&pol(&[], &["GET"])));
        assert!(!none.is_widened_by(&pol(&[], &[])));
    }
    use crate::api::strict_json::parse_strict;
    use serde::Deserialize;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // ── matcher ───────────────────────────────────────────────────────────────

    #[test]
    fn exact_match_and_anchoring() {
        assert!(wildcard_match("grafana", "grafana"));
        assert!(!wildcard_match("grafana", "grafana2"));
        assert!(!wildcard_match("grafana", "xgrafana"));
        assert!(!wildcard_match("grafana", "grafan"));
        assert!(!wildcard_match("uptime_*", "not_uptime_x"));
        assert!(wildcard_match("uptime_*", "uptime_kuma"));
        assert!(wildcard_match("uptime_*", "uptime_"));
        assert!(!wildcard_match("uptime_*", "uptime"));
    }

    #[test]
    fn prefix_suffix_infix_and_multiple_stars() {
        assert!(wildcard_match("*_token", "grafana_token"));
        assert!(!wildcard_match("*_token", "grafana_token_old"));
        assert!(wildcard_match("lab_*_ro", "lab_nas_ro"));
        assert!(wildcard_match("lab_*_ro", "lab__ro"));
        assert!(!wildcard_match("lab_*_ro", "lab_ro"));
        assert!(wildcard_match("*a*b*c*", "xxaxxbxxcxx"));
        assert!(wildcard_match("*a*b*c*", "abc"));
        assert!(!wildcard_match("*a*b*c*", "acb"));
        assert!(wildcard_match("a**b", "ab"));
        assert!(wildcard_match("a**b", "axxb"));
    }

    #[test]
    fn star_alone_matches_everything_including_empty() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "anything at all"));
        assert!(wildcard_match("**", ""));
    }

    #[test]
    fn empty_name_and_empty_pattern() {
        assert!(!wildcard_match("a", ""));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "a"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert!(!wildcard_match("Grafana", "grafana"));
        assert!(!wildcard_match("grafana_*", "GRAFANA_x"));
    }

    #[test]
    fn names_with_spaces_quotes_colons_and_unicode() {
        assert!(wildcard_match("Proxmox (*)", "Proxmox (prod)"));
        assert!(wildcard_match("*", "it's \"quoted\""));
        assert!(wildcard_match("it's *", "it's \"quoted\""));
        assert!(wildcard_match("db:*", "db:primary:admin"));
        assert!(wildcard_match("日本*", "日本語の名前"));
        assert!(wildcard_match("café_*", "café_x"));
        assert!(!wildcard_match("cafe_*", "café_x"));
        // `*` matches whole characters, not bytes.
        assert!(wildcard_match("?*", "?é"));
        assert!(wildcard_match("é*é", "éxé"));
    }

    #[test]
    fn question_mark_and_brackets_are_literal() {
        assert!(wildcard_match("a?c", "a?c"));
        assert!(!wildcard_match("a?c", "abc"));
        assert!(wildcard_match("[x]", "[x]"));
        assert!(!wildcard_match("[x]", "x"));
        assert!(wildcard_match("a.c", "a.c"));
        assert!(!wildcard_match("a.c", "abc"));
    }

    #[test]
    fn pathological_patterns_finish_fast() {
        let start = std::time::Instant::now();
        let name = "a".repeat(5000);
        // No `b` in the name: the classic exponential case for naive
        // recursive matchers. Ours is O(n*m).
        assert!(!wildcard_match("*a*a*a*a*b", &name));
        assert!(!wildcard_match(&format!("{}b", "*a".repeat(120)), &name));
        assert!(wildcard_match("*a*a*a*a*", &name));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            start.elapsed()
        );
    }

    // ── validation ────────────────────────────────────────────────────────────

    #[test]
    fn credential_validation_rules() {
        assert_eq!(
            validate_credentials(s(&["a_*", "b"])).unwrap(),
            s(&["a_*", "b"])
        );
        assert_eq!(validate_credentials(vec![]).unwrap(), Vec::<String>::new());
        // Duplicates collapse.
        assert_eq!(validate_credentials(s(&["a", "a"])).unwrap(), s(&["a"]));
        // `*` is "unrestricted spelled out"; the list collapses to it.
        assert_eq!(validate_credentials(s(&["*"])).unwrap(), s(&["*"]));
        assert_eq!(validate_credentials(s(&["a", "*"])).unwrap(), s(&["*"]));
        // Length bounds are in characters.
        assert!(validate_credentials(s(&[""])).is_err());
        assert!(validate_credentials(vec!["a".repeat(256)]).is_ok());
        assert!(validate_credentials(vec!["a".repeat(257)]).is_err());
        assert!(validate_credentials(vec!["é".repeat(256)]).is_ok());
        assert!(validate_credentials(vec!["é".repeat(257)]).is_err());
        // Count bound.
        let many: Vec<String> = (0..256).map(|i| format!("c{i}")).collect();
        assert!(validate_credentials(many.clone()).is_ok());
        let mut too_many = many;
        too_many.push("one_more".into());
        assert!(validate_credentials(too_many).is_err());
        // Control characters.
        for bad in ["a\nb", "a\0b", "\ta", "a\u{7f}", "a\u{85}"] {
            assert!(validate_credentials(s(&[bad])).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn method_validation_normalises_and_dedupes() {
        assert_eq!(
            validate_methods(s(&["get", "Post", "GET"])).unwrap(),
            s(&["GET", "POST"])
        );
        // Canonical order regardless of input order.
        assert_eq!(
            validate_methods(s(&["delete", "head"])).unwrap(),
            s(&["HEAD", "DELETE"])
        );
        assert_eq!(validate_methods(vec![]).unwrap(), Vec::<String>::new());
        assert_eq!(validate_methods(s(&["*"])).unwrap(), s(&["*"]));
        assert_eq!(validate_methods(s(&["*", "*"])).unwrap(), s(&["*"]));
        assert!(validate_methods(s(&["*", "GET"])).is_err());
        for bad in ["TRACE", "CONNECT", "FOO", "", "GET ", "G*", "ge t"] {
            assert!(validate_methods(s(&[bad])).is_err(), "{bad:?}");
        }
        let all = validate_methods(s(&METHODS)).unwrap();
        assert_eq!(all.len(), 7);
    }

    #[test]
    fn request_method_normalisation() {
        assert_eq!(normalize_method("get").unwrap(), "GET");
        assert_eq!(normalize_method("PaTcH").unwrap(), "PATCH");
        for bad in ["TRACE", "CONNECT", "FOO", "", " GET", "GET\n"] {
            assert!(normalize_method(bad).is_err(), "{bad:?}");
        }
    }

    // ── policy decisions ──────────────────────────────────────────────────────

    fn ph(name: &str) -> Placeholder {
        Placeholder {
            item: name.to_string(),
            selector: crate::proxy::placeholder::Selector::Password,
        }
    }

    fn set(names: &[&str]) -> BTreeSet<Placeholder> {
        names.iter().map(|n| ph(n)).collect()
    }

    #[test]
    fn default_policy_is_deny_all() {
        let p = KeyPolicy::default();
        assert_eq!(p, KeyPolicy::default());
        assert!(!p.allows_credential("anything"));
        for m in METHODS {
            assert!(!p.allows_method(m));
        }
        assert_eq!(p.to_json(), json!({"credentials": [], "methods": []}));
    }

    #[test]
    fn star_star_is_unrestricted_but_only_for_known_methods() {
        let p = KeyPolicy::from_raw(s(&["*"]), s(&["*"])).unwrap();
        assert!(p.allows_credential("anything"));
        for m in METHODS {
            assert!(p.allows_method(m));
        }
        assert!(!p.allows_method("TRACE"));
        assert_eq!(p.to_json(), json!({"credentials": ["*"], "methods": ["*"]}));
    }

    #[test]
    fn empty_lists_allow_nothing() {
        let p = KeyPolicy::from_raw(vec![], vec![]).unwrap();
        assert!(!p.allows_credential("x"));
        assert!(!p.allows_method("GET"));
        // A request with no placeholders still passes the scope check; only
        // the method matters then.
        let open = KeyPolicy::from_raw(vec![], s(&["*"])).unwrap();
        assert!(open.check_request("GET", &set(&[])).is_ok());
        assert!(open.check_request("GET", &set(&["x"])).is_err());
    }

    #[test]
    fn method_is_checked_before_scope() {
        let p = KeyPolicy::from_raw(s(&["a"]), s(&["GET"])).unwrap();
        assert!(matches!(
            p.check_request("POST", &set(&["not_a"])),
            Err(FerroError::MethodNotAllowed(m)) if m == "POST"
        ));
        assert!(matches!(
            p.check_request("GET", &set(&["not_a"])),
            Err(FerroError::CredentialOutOfScope(_))
        ));
        assert!(p.check_request("GET", &set(&["a"])).is_ok());
    }

    #[test]
    fn out_of_scope_error_does_not_depend_on_the_vault() {
        // The check takes only the policy and the placeholder names, so an
        // existing and a nonexistent out-of-scope name are indistinguishable.
        let p = KeyPolicy::from_raw(s(&["lab_*"]), s(&["*"])).unwrap();
        let a = p.check_request("GET", &set(&["prod_db"])).unwrap_err();
        let b = p
            .check_request("GET", &set(&["does_not_exist_anywhere"]))
            .unwrap_err();
        assert_eq!(a.status_code(), b.status_code());
        assert_eq!(a.status_code(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(
            a.to_string(),
            "Credential prod_db is not available to this agent key"
        );
        assert_eq!(
            b.to_string(),
            "Credential does_not_exist_anywhere is not available to this agent key"
        );
        // Scope wins over every later (vault-dependent) failure: an in-scope
        // unknown name does not mask an out-of-scope one.
        assert!(matches!(
            p.check_request("GET", &set(&["lab_unknown", "prod_db"])),
            Err(FerroError::CredentialOutOfScope(n)) if n == "prod_db"
        ));
    }

    #[test]
    fn scope_uses_the_unquoted_item_name_but_reports_the_label() {
        let p = KeyPolicy::from_raw(s(&["Proxmox (*)"]), s(&["*"])).unwrap();
        let quoted = Placeholder {
            item: "Proxmox (prod)".into(),
            selector: crate::proxy::placeholder::Selector::Username,
        };
        assert!(p.check_request("GET", &BTreeSet::from([quoted])).is_ok());
        let other = Placeholder {
            item: "Other (x)".into(),
            selector: crate::proxy::placeholder::Selector::Username,
        };
        let e = p
            .check_request("GET", &BTreeSet::from([other]))
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "Credential 'Other (x)':username is not available to this agent key"
        );
    }

    #[test]
    fn patching_a_deny_all_policy_leaves_the_other_field_denied() {
        let p = KeyPolicy::default()
            .patched(Patch::Value(s(&["a"])), Patch::Absent)
            .unwrap();
        assert_eq!(p.credentials, s(&["a"]));
        assert!(p.methods.is_empty());
        assert!(!p.allows_method("GET"));
    }

    #[test]
    fn patched_replaces_only_present_fields() {
        let base = KeyPolicy::from_raw(s(&["a"]), s(&["GET"])).unwrap();
        let p = base
            .patched(Patch::Value(s(&["b_*"])), Patch::Absent)
            .unwrap();
        assert_eq!(p.credentials, s(&["b_*"]));
        assert_eq!(p.methods, s(&["GET"]));
        let p = base
            .patched(Patch::Absent, Patch::Value(s(&["*"])))
            .unwrap();
        assert_eq!(p.credentials, s(&["a"]));
        assert_eq!(p.methods, s(&["*"]));
        // Lifting a restriction.
        let p = base
            .patched(Patch::Value(s(&["*"])), Patch::Value(s(&["*"])))
            .unwrap();
        assert_eq!(p, KeyPolicy::from_raw(s(&["*"]), s(&["*"])).unwrap());
        // Invalid values are rejected and leave `base` untouched.
        assert!(base.patched(Patch::Value(s(&[""])), Patch::Absent).is_err());
        assert!(base
            .patched(Patch::Absent, Patch::Value(s(&["TRACE"])))
            .is_err());
    }

    // ── null-rejecting parsing ────────────────────────────────────────────────

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Body {
        #[serde(default, deserialize_with = "patch_credentials")]
        credentials: Patch<Vec<String>>,
        #[serde(default, deserialize_with = "patch_methods")]
        methods: Patch<Vec<String>>,
    }

    fn parse(json: &str) -> Result<Body, String> {
        parse_strict(json.as_bytes())
    }

    #[test]
    fn patch_parsing_distinguishes_absent_null_and_value() {
        let b = parse("{}").unwrap();
        assert!(b.credentials.is_absent() && b.methods.is_absent());

        let b = parse(r#"{"credentials":["a"]}"#).unwrap();
        assert_eq!(b.credentials, Patch::Value(s(&["a"])));
        assert!(b.methods.is_absent());

        // An empty list is a value (meaning "nothing"), not absent.
        let b = parse(r#"{"methods":[]}"#).unwrap();
        assert_eq!(b.methods, Patch::Value(vec![]));

        let e = parse(r#"{"credentials":null}"#).unwrap_err();
        assert!(e.contains("`credentials`") && e.contains("null"), "{e}");
        let e = parse(r#"{"methods":null}"#).unwrap_err();
        assert!(e.contains("`methods`") && e.contains("null"), "{e}");
    }

    #[test]
    fn wrong_types_are_rejected_with_a_field_name_and_no_value() {
        for (json, field) in [
            (r#"{"credentials":"*"}"#, "credentials"),
            (r#"{"credentials":5}"#, "credentials"),
            (r#"{"methods":true}"#, "methods"),
            (r#"{"methods":{"a":1}}"#, "methods"),
            (r#"{"methods":[1]}"#, ""),
            (r#"{"methods":[null]}"#, ""),
            (r#"{"credentials":[["a"]]}"#, ""),
        ] {
            let e = parse(json).unwrap_err();
            assert!(e.contains(field), "{json}: {e}");
        }
        let e = parse(r#"{"credentials":"super-secret-looking"}"#).unwrap_err();
        assert!(!e.contains("super-secret"), "{e}");
    }

    #[test]
    fn unknown_fields_and_duplicate_keys_are_still_rejected() {
        assert!(parse(r#"{"credential":["a"]}"#).is_err());
        assert!(parse(r#"{"credentials":["a"],"credentials":["b"]}"#).is_err());
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Create {
        #[allow(dead_code)]
        #[serde(deserialize_with = "required_credentials")]
        credentials: Vec<String>,
        #[allow(dead_code)]
        #[serde(deserialize_with = "required_methods")]
        methods: Vec<String>,
    }

    #[test]
    fn required_fields_must_be_present_and_not_null() {
        assert!(parse_strict::<Create>(br#"{"credentials":["*"],"methods":["*"]}"#).is_ok());
        let e = parse_strict::<Create>(br#"{"methods":["*"]}"#).unwrap_err();
        assert!(e.contains("missing field `credentials`"), "{e}");
        let e = parse_strict::<Create>(br#"{"credentials":[]}"#).unwrap_err();
        assert!(e.contains("missing field `methods`"), "{e}");
        let e = parse_strict::<Create>(br#"{"credentials":null,"methods":[]}"#).unwrap_err();
        assert!(e.contains("`credentials`") && e.contains("null"), "{e}");
        let e = parse_strict::<Create>(br#"{"credentials":[],"methods":null}"#).unwrap_err();
        assert!(e.contains("`methods`") && e.contains("null"), "{e}");
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Nested {
        #[serde(default, deserialize_with = "some_not_null")]
        request: Option<Inner>,
    }
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Inner {
        #[allow(dead_code)]
        a: u8,
    }

    #[test]
    fn optional_object_rejects_null() {
        assert!(parse_strict::<Nested>(b"{}").unwrap().request.is_none());
        assert!(parse_strict::<Nested>(br#"{"request":{"a":1}}"#)
            .unwrap()
            .request
            .is_some());
        assert!(parse_strict::<Nested>(br#"{"request":null}"#).is_err());
    }
}
