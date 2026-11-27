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
//! * `approval` is a list of credential name patterns, with the same syntax,
//!   limits and matching as `credentials`: a credential whose name matches
//!   needs a human's approval before this key can use it (docs/approvals.md).
//!   It is an extra requirement only: absent in a key file or a create body it
//!   is `[]` (no extra requirement), which is what a key from before approvals
//!   existed has. Removing or narrowing patterns widens what the key can do.
//! * `create` is a list of credential name patterns, with the same syntax,
//!   limits, matching, "no null" rule and absent-means-`[]` as `approval`: the
//!   names this key may ask Ferrowarden to **create** in the managed
//!   collection (`POST /v1/credentials`, docs/managed-credentials.md). It is
//!   its own permission: it is independent of `credentials` (reading and
//!   using credentials) and of `methods` (forwarding). Adding or broadening a
//!   pattern widens what the key can do.
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
    /// Credential name patterns that need a human's approval for this key;
    /// `["*"]` = every credential, `[]` = no extra requirement.
    pub approval: Vec<String>,
    /// Credential name patterns this key may ask to have created in the
    /// managed collection; `["*"]` = any name, `[]` = none.
    pub create: Vec<String>,
}

impl KeyPolicy {
    /// Build a validated, normalised policy from raw lists.
    pub fn from_raw(
        credentials: Vec<String>,
        methods: Vec<String>,
        approval: Vec<String>,
        create: Vec<String>,
    ) -> FerroResult<Self> {
        Ok(Self {
            credentials: validate_credentials(credentials)?,
            methods: validate_methods(methods)?,
            approval: validate_approval(approval)?,
            create: validate_create(create)?,
        })
    }

    /// Apply a patch: a present field replaces the old value (and is
    /// validated), an absent one is left alone.
    pub fn patched(
        &self,
        credentials: Patch<Vec<String>>,
        methods: Patch<Vec<String>>,
        approval: Patch<Vec<String>>,
        create: Patch<Vec<String>>,
    ) -> FerroResult<Self> {
        let mut out = self.clone();
        if let Patch::Value(list) = credentials {
            out.credentials = validate_credentials(list)?;
        }
        if let Patch::Value(list) = methods {
            out.methods = validate_methods(list)?;
        }
        if let Patch::Value(list) = approval {
            out.approval = validate_approval(list)?;
        }
        if let Patch::Value(list) = create {
            out.create = validate_create(list)?;
        }
        Ok(out)
    }

    /// Does the key policy make using the credential called `name` need a
    /// human's approval? (The vault item's own field is the other source.)
    pub fn requires_approval(&self, name: &str) -> bool {
        self.approval.iter().any(|p| wildcard_match(p, name))
    }

    /// Does the policy let the key ask for a credential called `name` to be
    /// created?
    pub fn allows_create(&self, name: &str) -> bool {
        self.create.iter().any(|p| wildcard_match(p, name))
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
    /// if `draft` allows a method this one does not, has a credential
    /// pattern that this policy's patterns do not cover, or **removes or
    /// narrows an approval pattern** (one of ours that no approval pattern of
    /// the draft covers: the key could then use a credential without
    /// asking), or **adds or broadens a `create` pattern** (a name the key
    /// could not create before). The pattern test is conservative and independent of the
    /// vault: a pattern is covered if one of the other list's matches it
    /// read literally (its `*` characters as plain text), which holds exactly
    /// when every name the pattern can match is matched. So `uptime_a*` is
    /// covered by `uptime_*`, `up*` is not.
    pub fn is_widened_by(&self, draft: &KeyPolicy) -> bool {
        let methods_wider = METHODS
            .iter()
            .any(|m| draft.allows_method(m) && !self.allows_method(m));
        let patterns_wider = draft.credentials.iter().any(|p| !self.allows_credential(p));
        let approval_weaker = self.approval.iter().any(|p| !draft.requires_approval(p));
        let create_wider = draft.create.iter().any(|p| !self.allows_create(p));
        methods_wider || patterns_wider || approval_weaker || create_wider
    }

    /// `{ "credentials": [...], "methods": [...], "approval": [...], "create": [...] }`, as
    /// shown in API output and events.
    pub fn to_json(&self) -> Value {
        json!({
            "credentials": self.credentials,
            "methods": self.methods,
            "approval": self.approval,
            "create": self.create,
        })
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
    validate_patterns("credentials", patterns)
}

/// Validate the approval patterns: the same rules as the credential patterns.
pub fn validate_approval(patterns: Vec<String>) -> FerroResult<Vec<String>> {
    validate_patterns("approval", patterns)
}

/// Validate the create patterns: the same rules as the credential patterns.
pub fn validate_create(patterns: Vec<String>) -> FerroResult<Vec<String>> {
    validate_patterns("create", patterns)
}

fn validate_patterns(field: &str, patterns: Vec<String>) -> FerroResult<Vec<String>> {
    if patterns.len() > MAX_PATTERNS {
        return Err(FerroError::InvalidRequest(format!(
            "{field} may have at most {MAX_PATTERNS} patterns"
        )));
    }
    // No pre-sized allocation from the request-controlled length (the bound
    // above already holds, but growing on demand keeps that obvious).
    let mut out: Vec<String> = Vec::new();
    for (i, pattern) in patterns.into_iter().enumerate() {
        let chars = pattern.chars().count();
        if chars == 0 || chars > MAX_PATTERN_CHARS {
            return Err(FerroError::InvalidRequest(format!(
                "{field}[{i}]: a pattern must be 1-{MAX_PATTERN_CHARS} characters"
            )));
        }
        if pattern.chars().any(char::is_control) {
            return Err(FerroError::InvalidRequest(format!(
                "{field}[{i}]: a pattern may not contain control characters"
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
        let hint = if self.0 == "approval" {
            "leave it out for no extra approval requirement, or send [\"*\"] to require approval for every credential"
        } else if self.0 == "create" {
            "leave it out so the key cannot create credentials, or send [\"*\"] to let it create any name"
        } else {
            "leave it out to keep the default, or send [\"*\"] to allow everything"
        };
        Err(E::custom(format!(
            "policy field `{}` must be an array of strings, not null; {hint}",
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
list_fields!(
    patch_approval,
    required_approval,
    stored_approval,
    "approval"
);
list_fields!(patch_create, required_create, stored_create, "create");

/// For an optional nested object (`request`): absent is `None`, `null` is an
/// error rather than another way of saying "absent".
pub fn some_not_null<'de, T: serde::Deserialize<'de>, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests;
