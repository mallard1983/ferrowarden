//! Human approval of sensitive credentials (docs/approvals.md).
//!
//! A credential can be marked as needing approval, by the vault item (the
//! reserved `ferrowarden_approval` field) or by the agent key's policy (its
//! `approval` pattern list); either source is enough, and neither can switch
//! the other off. A forward request that uses such a credential is **held**
//! before any value is fetched or any connection is opened. A human decides in
//! the admin web UI or with the admin API; the agent's key can never decide.
//!
//! What this module holds:
//!
//! * the store ([`ApprovalStore`]): pending approvals, grants and denials in
//!   memory only (a restart empties it), keyed by (agent key, vault item,
//!   target origin), with the limits that keep an agent from flooding the
//!   operator;
//! * the gate ([`gate`]), which `POST /v1/forward` runs after every other
//!   check and before the first value is fetched: grant, denial, reuse of an
//!   open approval or a new prompt, then the hold;
//! * the lifecycle: the periodic sweep and the places that clear approvals
//!   (key revoke, policy change, vault lock), modelled on `sessions`;
//! * the events (never a value).
//!
//! Decisions (approve, deny, revoke a grant) are made by
//! `api::approval_service`, which only the admin API and the admin UI call.
//! No agent route reaches them.

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::watch;

use crate::config::ApprovalConfig;
use crate::error::{FerroError, FerroResult};
use crate::events::{truncate, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::policy::KeyPolicy;
use crate::sessions::Origin;
use crate::state::{AgentKey, AppState};

/// How often expired approvals, grants and denials are swept.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// The prompt-rate window of `approval.max_requests_per_key_per_hour`.
const PROMPT_WINDOW: ChronoDuration = ChronoDuration::hours(1);
/// Longest path (without query) recorded in an event and shown in a prompt.
pub const MAX_PATH_CHARS: usize = 200;
/// Longest request URL kept with a pending approval.
const MAX_URL_CHARS: usize = 2048;
/// Longest method kept with a pending approval.
const MAX_METHOD_CHARS: usize = 16;

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// A random, URL-safe id of 144 bits from the operating system. `None` only
/// if the OS RNG fails; the caller then fails the operation.
pub fn new_id() -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut bytes = [0u8; 18];
    getrandom::fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

/// Is `id` shaped like an id [`new_id`] makes? Checked before a path segment
/// is looked up, so nothing else is ever compared or echoed.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ── Why a credential needs approval ───────────────────────────────────────────

/// The sources that make one credential need approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reasons {
    /// The vault item carries a `ferrowarden_approval` field.
    pub vault_field: bool,
    /// The agent key's `approval` patterns match the item name.
    pub key_policy: bool,
}

impl Reasons {
    pub fn any(self) -> bool {
        self.vault_field || self.key_policy
    }

    /// The fixed codes: `vault_field`, `key_policy`.
    pub fn names(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.vault_field {
            out.push("vault_field");
        }
        if self.key_policy {
            out.push("key_policy");
        }
        out
    }
}

/// One credential (vault item name) that needs approval, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalNeed {
    pub item: String,
    pub reasons: Reasons,
}

impl ApprovalNeed {
    /// `{ "credential": "...", "reasons": ["vault_field", "key_policy"] }`.
    pub fn to_json(&self) -> Value {
        json!({ "credential": self.item, "reasons": self.reasons.names() })
    }
}

/// The items of a request that need approval, with the reasons. Empty: no
/// gate.
pub type Required = BTreeMap<String, Reasons>;

/// Combine the two sources. `vault_field` maps every item name of the request
/// to whether its vault item carries the field. Either source is enough, and
/// neither can exempt an item from the other.
pub fn required_items(policy: &KeyPolicy, vault_field: &BTreeMap<String, bool>) -> Required {
    vault_field
        .iter()
        .filter_map(|(item, field)| {
            let reasons = Reasons {
                vault_field: *field,
                key_policy: policy.requires_approval(item),
            };
            reasons.any().then(|| (item.clone(), reasons))
        })
        .collect()
}

/// [`Required`] as a sorted list.
pub fn needs(required: &Required) -> Vec<ApprovalNeed> {
    required
        .iter()
        .map(|(item, reasons)| ApprovalNeed {
            item: item.clone(),
            reasons: *reasons,
        })
        .collect()
}

// ── Views ─────────────────────────────────────────────────────────────────────

/// What became of a pending approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// One pending approval, as the UI, the admin API and the events show it.
/// Holds the request as the agent sent it: placeholders, never values.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingView {
    pub id: String,
    pub key_id: String,
    pub key_name: String,
    pub items: Vec<ApprovalNeed>,
    pub method: String,
    pub scheme: String,
    /// Host, with `:port` when it is not the scheme's default.
    pub host: String,
    pub port: u16,
    /// The URL as the agent sent it (truncated).
    pub url: String,
    pub request_id: String,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
}

impl PendingView {
    pub fn item_names(&self) -> Vec<&str> {
        self.items.iter().map(|n| n.item.as_str()).collect()
    }

    /// The path of the URL, without query or fragment, cut to
    /// [`MAX_PATH_CHARS`].
    pub fn path(&self) -> String {
        path_of(&self.url)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "key": { "id": self.key_id, "name": self.key_name },
            "credentials": self.items.iter().map(ApprovalNeed::to_json).collect::<Vec<_>>(),
            "method": self.method,
            "origin": { "scheme": self.scheme, "host": self.host, "port": self.port },
            "url": self.url,
            "request_id": self.request_id,
            "created_at": rfc3339(self.created),
            "expires_at": rfc3339(self.expires),
        })
    }
}

/// The path of `url` (as the agent sent it) without query and fragment, cut to
/// [`MAX_PATH_CHARS`] characters. Placeholders stay as written.
pub fn path_of(url: &str) -> String {
    let after = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = match after.find(['/', '?', '#']) {
        Some(i) if after.as_bytes()[i] == b'/' => &after[i..],
        _ => "/",
    };
    let path = path.split(['?', '#']).next().unwrap_or("/");
    truncate(path, MAX_PATH_CHARS)
}

/// One live grant, as the UI and the admin API show it.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantView {
    pub id: String,
    pub approval_id: String,
    pub key_id: String,
    pub key_name: String,
    pub items: Vec<String>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub approver: String,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
}

impl GrantView {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "approval_id": self.approval_id,
            "key": { "id": self.key_id, "name": self.key_name },
            "credentials": self.items,
            "origin": { "scheme": self.scheme, "host": self.host, "port": self.port },
            "approver": self.approver,
            "created_at": rfc3339(self.created),
            "expires_at": rfc3339(self.expires),
        })
    }
}

// ── The store ─────────────────────────────────────────────────────────────────

struct Pending {
    view: PendingView,
    origin: Origin,
    tx: watch::Sender<Decision>,
}

struct Grant {
    view: GrantView,
    origin: Origin,
}

struct Denial {
    key_id: String,
    item: String,
    origin: Origin,
    until: DateTime<Utc>,
}

#[derive(Default)]
struct Inner {
    pending: HashMap<String, Pending>,
    grants: HashMap<String, Grant>,
    denials: Vec<Denial>,
    /// When each key's prompts were created, for the hourly limit (sliding
    /// window: a prompt counts for one hour).
    prompts: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Held requests per key.
    waiters: HashMap<String, usize>,
}

/// Pending approvals, grants and denials of every agent key. In memory only:
/// nothing is written to disk and a restart empties it. Never holds a value.
pub struct ApprovalStore {
    inner: Mutex<Inner>,
    shutdown: watch::Sender<bool>,
    /// "No notifier is configured" was logged.
    warned_no_notifier: AtomicBool,
}

impl Default for ApprovalStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            shutdown: watch::channel(false).0,
            warned_no_notifier: AtomicBool::new(false),
        }
    }
}

/// Counts only: no key, credential or id.
impl std::fmt::Debug for ApprovalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        f.debug_struct("ApprovalStore")
            .field("pending", &inner.pending.len())
            .field("grants", &inner.grants.len())
            .finish_non_exhaustive()
    }
}

/// The request an approval is asked for.
pub struct AskFor<'a> {
    pub key_id: &'a str,
    pub key_name: &'a str,
    pub origin: &'a Origin,
    pub method: &'a str,
    /// The URL as the agent sent it.
    pub url: &'a str,
    pub request_id: &'a str,
}

/// A held request counts against its key's `max_waiters_per_key` until this
/// is dropped (the answer, a timeout, or the client going away).
pub struct WaiterGuard {
    store: Arc<ApprovalStore>,
    key_id: String,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        let mut inner = self.store.lock();
        if let Some(n) = inner.waiters.get_mut(&self.key_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.waiters.remove(&self.key_id);
            }
        }
    }
}

/// What the gate has to do for one request.
pub enum Check {
    /// Every required item has a live grant.
    Granted,
    /// A required item was denied recently.
    Denied,
    /// Too many open approvals, or too many prompts this hour.
    LimitReached,
    /// An approval is open, but this request is not held (the key has too
    /// many held requests). `created`: a new prompt went out for it.
    Pending { view: PendingView, created: bool },
    /// An approval is open; hold the request until it is decided.
    Wait {
        view: PendingView,
        created: bool,
        rx: watch::Receiver<Decision>,
        guard: WaiterGuard,
    },
}

/// The approval is not pending (decided, expired or cleared): 409.
#[derive(Debug, PartialEq, Eq)]
pub struct NotPending;

/// Approvals and grants removed together (a key revoked or changed, the vault
/// locked), for the events that record them.
#[derive(Debug, Default)]
pub struct Cleared {
    pub pending: Vec<PendingView>,
    pub grants: Vec<GrantView>,
}

/// What a sweep removed.
#[derive(Debug, Default)]
pub struct Swept {
    pub expired: Vec<PendingView>,
    pub grants: Vec<GrantView>,
}

impl ApprovalStore {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock only means another thread panicked mid-update; the
        // maps are still structurally valid.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Decide what a request needs: a grant, a refusal, or a hold on an
    /// approval that is open (found, or newly created and counted against the
    /// limits). `now` is the clock.
    pub fn check(
        self: &Arc<Self>,
        ask: &AskFor<'_>,
        required: &Required,
        cfg: &ApprovalConfig,
        now: DateTime<Utc>,
    ) -> FerroResult<Check> {
        let mut guard = self.lock();
        // Plain `&mut` so that the borrow checker sees the fields as disjoint.
        let inner: &mut Inner = &mut guard;

        // 1. Items without a live grant. None: the request may go on.
        let needed: Vec<&String> = required
            .keys()
            .filter(|item| !inner.has_grant(ask.key_id, ask.origin, item, now))
            .collect();
        if needed.is_empty() {
            return Ok(Check::Granted);
        }

        // 2. A recent denial of any of them stands.
        if needed
            .iter()
            .any(|item| inner.is_denied(ask.key_id, ask.origin, item, now))
        {
            return Ok(Check::Denied);
        }

        // 3. An open approval for exactly this key, origin and item set.
        let found = inner
            .pending
            .values()
            .find(|p| {
                p.view.key_id == ask.key_id
                    && p.origin == *ask.origin
                    && p.view.expires > now
                    && p.view.items.len() == needed.len()
                    && p.view
                        .items
                        .iter()
                        .zip(&needed)
                        .all(|(n, item)| n.item == **item)
            })
            .map(|p| (p.view.clone(), p.tx.subscribe()));
        let (view, rx, created) = match found {
            Some((view, rx)) => (view, rx, false),
            None => {
                // 4. A new one, within the limits.
                let open = inner
                    .pending
                    .values()
                    .filter(|p| p.view.key_id == ask.key_id && p.view.expires > now)
                    .count();
                if open >= cfg.max_pending_per_key {
                    return Ok(Check::LimitReached);
                }
                let prompts = inner.prompts.entry(ask.key_id.to_string()).or_default();
                while prompts.front().is_some_and(|t| *t <= now - PROMPT_WINDOW) {
                    prompts.pop_front();
                }
                if prompts.len() >= cfg.max_requests_per_key_per_hour {
                    return Ok(Check::LimitReached);
                }
                let id = new_id()
                    .ok_or_else(|| FerroError::Internal("no random id for an approval".into()))?;
                prompts.push_back(now);
                let ttl = ChronoDuration::seconds(i64::try_from(cfg.pending_ttl_secs).unwrap_or(0));
                let view = PendingView {
                    id: id.clone(),
                    key_id: ask.key_id.to_string(),
                    key_name: ask.key_name.to_string(),
                    items: needed
                        .iter()
                        .map(|item| ApprovalNeed {
                            item: (*item).clone(),
                            reasons: required[*item],
                        })
                        .collect(),
                    method: truncate(ask.method, MAX_METHOD_CHARS),
                    scheme: ask.origin.scheme().to_string(),
                    host: ask.origin.host_label(),
                    port: ask.origin.port(),
                    url: truncate(ask.url, MAX_URL_CHARS),
                    request_id: truncate(ask.request_id, 64),
                    created: now,
                    expires: now + ttl,
                };
                let (tx, rx) = watch::channel(Decision::Pending);
                inner.pending.insert(
                    id,
                    Pending {
                        view: view.clone(),
                        origin: ask.origin.clone(),
                        tx,
                    },
                );
                (view, rx, true)
            }
        };

        // Hold the request, unless the key already has too many held.
        let held = inner.waiters.get(ask.key_id).copied().unwrap_or(0);
        if held >= cfg.max_waiters_per_key {
            return Ok(Check::Pending { view, created });
        }
        *inner.waiters.entry(ask.key_id.to_string()).or_default() += 1;
        Ok(Check::Wait {
            view,
            created,
            rx,
            guard: WaiterGuard {
                store: self.clone(),
                key_id: ask.key_id.to_string(),
            },
        })
    }

    /// Does the key hold a live grant for every one of `required`, at `origin`?
    pub fn all_granted(
        &self,
        key_id: &str,
        origin: &Origin,
        required: &Required,
        now: DateTime<Utc>,
    ) -> bool {
        let inner = self.lock();
        required
            .keys()
            .all(|item| inner.has_grant(key_id, origin, item, now))
    }

    /// Approve `id`: a grant of `minutes` for every item of the approval,
    /// which replaces any denial of them, and the held requests are woken.
    /// `grant_id` is a fresh id for the grant.
    pub fn approve(
        &self,
        id: &str,
        grant_id: String,
        minutes: u32,
        approver: &str,
        now: DateTime<Utc>,
    ) -> Result<(PendingView, GrantView), NotPending> {
        let mut inner = self.lock();
        if !inner.pending.get(id).is_some_and(|p| p.view.expires > now) {
            return Err(NotPending);
        }
        let Some(pending) = inner.pending.remove(id) else {
            return Err(NotPending);
        };
        let view = &pending.view;
        let grant = GrantView {
            id: grant_id,
            approval_id: view.id.clone(),
            key_id: view.key_id.clone(),
            key_name: view.key_name.clone(),
            items: view.items.iter().map(|n| n.item.clone()).collect(),
            scheme: view.scheme.clone(),
            host: view.host.clone(),
            port: view.port,
            approver: truncate(approver, 128),
            created: now,
            expires: now + ChronoDuration::minutes(i64::from(minutes)),
        };
        inner.denials.retain(|d| {
            !(d.key_id == view.key_id
                && d.origin == pending.origin
                && grant.items.contains(&d.item))
        });
        inner.grants.insert(
            grant.id.clone(),
            Grant {
                view: grant.clone(),
                origin: pending.origin.clone(),
            },
        );
        let _ = pending.tx.send(Decision::Approved);
        Ok((pending.view, grant))
    }

    /// Deny `id`: its items are refused for the key and origin for `ttl`, and
    /// the held requests are woken.
    pub fn deny(
        &self,
        id: &str,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<PendingView, NotPending> {
        let mut inner = self.lock();
        if !inner.pending.get(id).is_some_and(|p| p.view.expires > now) {
            return Err(NotPending);
        }
        let Some(pending) = inner.pending.remove(id) else {
            return Err(NotPending);
        };
        let until = now + ChronoDuration::from_std(ttl).unwrap_or(ChronoDuration::zero());
        for need in &pending.view.items {
            inner.denials.push(Denial {
                key_id: pending.view.key_id.clone(),
                item: need.item.clone(),
                origin: pending.origin.clone(),
                until,
            });
        }
        let _ = pending.tx.send(Decision::Denied);
        Ok(pending.view)
    }

    /// End a live grant early.
    pub fn revoke_grant(&self, id: &str, now: DateTime<Utc>) -> Result<GrantView, NotPending> {
        let mut inner = self.lock();
        if !inner.grants.get(id).is_some_and(|g| g.view.expires > now) {
            return Err(NotPending);
        }
        inner.grants.remove(id).map(|g| g.view).ok_or(NotPending)
    }

    /// Open approvals (oldest first) and live grants (soonest to expire first).
    pub fn list(&self, now: DateTime<Utc>) -> (Vec<PendingView>, Vec<GrantView>) {
        let inner = self.lock();
        let mut pending: Vec<PendingView> = inner
            .pending
            .values()
            .filter(|p| p.view.expires > now)
            .map(|p| p.view.clone())
            .collect();
        pending.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        let mut grants: Vec<GrantView> = inner
            .grants
            .values()
            .filter(|g| g.view.expires > now)
            .map(|g| g.view.clone())
            .collect();
        grants.sort_by(|a, b| (a.expires, &a.id).cmp(&(b.expires, &b.id)));
        (pending, grants)
    }

    /// One open approval.
    pub fn get(&self, id: &str, now: DateTime<Utc>) -> Option<PendingView> {
        self.lock()
            .pending
            .get(id)
            .filter(|p| p.view.expires > now)
            .map(|p| p.view.clone())
    }

    /// How many approvals are open and how many grants are live (the metrics
    /// gauges).
    pub fn counts(&self, now: DateTime<Utc>) -> (usize, usize) {
        let inner = self.lock();
        (
            inner
                .pending
                .values()
                .filter(|p| p.view.expires > now)
                .count(),
            inner
                .grants
                .values()
                .filter(|g| g.view.expires > now)
                .count(),
        )
    }

    /// Remove every approval, grant and denial of one key.
    pub fn clear_key(&self, key_id: &str) -> Cleared {
        self.drain(|k| k == key_id)
    }

    /// Remove every approval, grant and denial of every key.
    pub fn clear_all(&self) -> Cleared {
        self.drain(|_| true)
    }

    fn drain(&self, pick: impl Fn(&str) -> bool) -> Cleared {
        let mut inner = self.lock();
        let ids: Vec<String> = inner
            .pending
            .iter()
            .filter(|(_, p)| pick(&p.view.key_id))
            .map(|(id, _)| id.clone())
            .collect();
        let mut cleared = Cleared::default();
        for id in ids {
            if let Some(p) = inner.pending.remove(&id) {
                let _ = p.tx.send(Decision::Expired);
                cleared.pending.push(p.view);
            }
        }
        let grant_ids: Vec<String> = inner
            .grants
            .iter()
            .filter(|(_, g)| pick(&g.view.key_id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in grant_ids {
            if let Some(g) = inner.grants.remove(&id) {
                cleared.grants.push(g.view);
            }
        }
        inner.denials.retain(|d| !pick(&d.key_id));
        cleared
            .pending
            .sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        cleared.grants.sort_by(|a, b| a.id.cmp(&b.id));
        cleared
    }

    /// Remove what has expired: open approvals (their held requests are
    /// woken), grants, denials and old prompt records.
    pub fn sweep(&self, now: DateTime<Utc>) -> Swept {
        let mut inner = self.lock();
        let mut swept = Swept::default();
        let ids: Vec<String> = inner
            .pending
            .iter()
            .filter(|(_, p)| p.view.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(p) = inner.pending.remove(&id) {
                let _ = p.tx.send(Decision::Expired);
                swept.expired.push(p.view);
            }
        }
        let grant_ids: Vec<String> = inner
            .grants
            .iter()
            .filter(|(_, g)| g.view.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in grant_ids {
            if let Some(g) = inner.grants.remove(&id) {
                swept.grants.push(g.view);
            }
        }
        inner.denials.retain(|d| d.until > now);
        inner.prompts.retain(|_, q| {
            while q.front().is_some_and(|t| *t <= now - PROMPT_WINDOW) {
                q.pop_front();
            }
            !q.is_empty()
        });
        swept
            .expired
            .sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        swept.grants.sort_by(|a, b| a.id.cmp(&b.id));
        swept
    }

    /// The process is stopping: wake every held request, which answers
    /// `approval_pending` (the approval itself is not decided).
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Log once that nobody will hear about an approval.
    fn warn_no_notifier_once(&self) -> bool {
        !self.warned_no_notifier.swap(true, Ordering::Relaxed)
    }
}

impl Inner {
    fn has_grant(&self, key_id: &str, origin: &Origin, item: &str, now: DateTime<Utc>) -> bool {
        self.grants.values().any(|g| {
            g.view.key_id == key_id
                && g.origin == *origin
                && g.view.expires > now
                && g.view.items.iter().any(|i| i == item)
        })
    }

    fn is_denied(&self, key_id: &str, origin: &Origin, item: &str, now: DateTime<Utc>) -> bool {
        self.denials
            .iter()
            .any(|d| d.key_id == key_id && d.origin == *origin && d.item == item && d.until > now)
    }
}

// ── The gate ──────────────────────────────────────────────────────────────────

/// How a request that needed approval got through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateResult {
    /// Every item already had a live grant.
    GrantedByGrant,
    /// The request was held and approved while it waited.
    ApprovedWhileWaiting,
}

impl GateResult {
    /// The value of the `approval` detail on a `forward` event and of the
    /// `result` label of `ferrowarden_forward_approval_total`.
    pub fn as_str(self) -> &'static str {
        match self {
            GateResult::GrantedByGrant => "granted_by_grant",
            GateResult::ApprovedWhileWaiting => "approved_while_waiting",
        }
    }
}

/// The `approval` detail of a `forward` event that was stopped by the gate, or
/// `None` for an error that is not the gate's.
pub fn refusal_result(error: &FerroError) -> Option<&'static str> {
    match error {
        FerroError::ApprovalPending { .. } => Some("pending"),
        FerroError::ApprovalDenied => Some("denied"),
        FerroError::ApprovalLimitReached => Some("limit_reached"),
        _ => None,
    }
}

enum Waited {
    Decision(Decision),
    Timeout,
    Shutdown,
}

async fn wait_for_decision(
    mut rx: watch::Receiver<Decision>,
    mut shutdown: watch::Receiver<bool>,
    wait: Duration,
) -> Waited {
    tokio::select! {
        // `Err`: the approval was dropped without a decision.
        r = rx.wait_for(|d| *d != Decision::Pending) => {
            Waited::Decision(r.map_or(Decision::Expired, |d| *d))
        }
        _ = shutdown.wait_for(|s| *s) => Waited::Shutdown,
        _ = tokio::time::sleep(wait) => Waited::Timeout,
    }
}

/// The approval gate of `POST /v1/forward`. Runs after every other check and
/// before any value is fetched or any connection is opened.
///
/// `required` is the set of items of the request that need approval (never
/// empty here). Returns how the request got through, or the refusal:
/// `approval_denied`, `approval_pending` (with the id to approve) or
/// `approval_limit_reached`. No lock is held while the request waits.
pub async fn gate(
    state: &Arc<AppState>,
    agent: &AgentKey,
    ctx: &RequestContext,
    method: &str,
    url: &str,
    origin: &Origin,
    required: &Required,
) -> FerroResult<GateResult> {
    let cfg = &state.config.approval;
    let store = &state.approvals;
    let ask = AskFor {
        key_id: &agent.id,
        key_name: &agent.name,
        origin,
        method,
        url,
        request_id: &ctx.request_id,
    };
    match store.check(&ask, required, cfg, Utc::now())? {
        Check::Granted => Ok(GateResult::GrantedByGrant),
        Check::Denied => Err(FerroError::ApprovalDenied),
        Check::LimitReached => Err(FerroError::ApprovalLimitReached),
        Check::Pending { view, created } => {
            if created {
                announce(state, ctx, &view);
            }
            Err(FerroError::ApprovalPending { id: view.id })
        }
        Check::Wait {
            view,
            created,
            rx,
            guard,
        } => {
            if created {
                announce(state, ctx, &view);
            }
            let waited = wait_for_decision(
                rx,
                store.shutdown.subscribe(),
                Duration::from_secs(cfg.wait_secs),
            )
            .await;
            drop(guard);
            match waited {
                Waited::Decision(Decision::Approved) => {
                    // Re-check: the grant may have been revoked, or cleared
                    // by a key change, in the instant since it was made.
                    if store.all_granted(&agent.id, origin, required, Utc::now()) {
                        Ok(GateResult::ApprovedWhileWaiting)
                    } else {
                        Err(FerroError::ApprovalPending { id: view.id })
                    }
                }
                Waited::Decision(Decision::Denied) => Err(FerroError::ApprovalDenied),
                // Undecided, expired, cleared or the process stopping: the
                // agent retries the same request.
                Waited::Decision(_) | Waited::Timeout | Waited::Shutdown => {
                    Err(FerroError::ApprovalPending { id: view.id })
                }
            }
        }
    }
}

/// A new approval was opened: record `approval_requested` (which the notifier
/// turns into the prompt) and, once, warn when nobody will be told.
fn announce(state: &AppState, ctx: &RequestContext, view: &PendingView) {
    if !state.notify.snapshot().enabled() && state.approvals.warn_no_notifier_once() {
        tracing::warn!(
            "An approval is waiting but no notifier is configured: nobody is told. \
             Decide in the admin UI (Approvals) or with the admin API, or set up a notifier \
             (docs/notifications.md)."
        );
    }
    let link = state.config.ui.approval_link(&view.id);
    state.events.emit(requested_event(ctx, view, link));
}

// ── Events ────────────────────────────────────────────────────────────────────

fn reasons_json(items: &[ApprovalNeed]) -> Value {
    Value::Object(
        items
            .iter()
            .map(|n| (n.item.clone(), json!(n.reasons.names())))
            .collect(),
    )
}

/// `approval_requested`: key, items and why, method, host, path (no query),
/// approval id, expiry and the link. Never a value.
pub fn requested_event(
    ctx: &RequestContext,
    v: &PendingView,
    link: Option<String>,
) -> SecurityEvent {
    let mut event = SecurityEvent::new(Action::ApprovalRequested)
        .request(ctx)
        .key_named(&v.key_id, &v.key_name)
        .method(&v.method)
        .url(&v.url)
        .credentials(v.item_names())
        .detail("approval_id", v.id.as_str())
        .detail("reasons", reasons_json(&v.items))
        .detail("host", v.host.as_str())
        .detail("path", v.path())
        .detail("expires_at", rfc3339(v.expires));
    if let Some(link) = link {
        event = event.detail("link", link);
    }
    event
}

/// `approval_expired`, with the cause: `timeout`, `key_revoke`,
/// `key_policy_change` or `vault_lock`.
pub fn expired_event(v: &PendingView, cause: &'static str) -> SecurityEvent {
    SecurityEvent::new(Action::ApprovalExpired)
        .key_named(&v.key_id, &v.key_name)
        .credentials(v.item_names())
        .detail("approval_id", v.id.as_str())
        .detail("host", v.host.as_str())
        .detail("cause", cause)
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

/// Why approvals were cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearCause {
    KeyRevoke,
    KeyPolicyChange,
    VaultLock,
}

impl ClearCause {
    pub fn as_str(self) -> &'static str {
        match self {
            ClearCause::KeyRevoke => "key_revoke",
            ClearCause::KeyPolicyChange => "key_policy_change",
            ClearCause::VaultLock => "vault_lock",
        }
    }
}

fn record_cleared(state: &AppState, cleared: Cleared, cause: ClearCause) {
    for v in &cleared.pending {
        state.events.emit(expired_event(v, cause.as_str()));
    }
    for g in &cleared.grants {
        state.events.emit(
            SecurityEvent::new(Action::GrantRevoked)
                .key_named(&g.key_id, &g.key_name)
                .credentials(&g.items)
                .detail("grant_id", g.id.as_str())
                .detail("approval_id", g.approval_id.as_str())
                .detail("host", g.host.as_str())
                .detail("cause", cause.as_str()),
        );
    }
}

/// Remove every approval and grant of a key (revoked, or its policy changed)
/// and record each.
pub fn clear_key(state: &AppState, key_id: &str, cause: ClearCause) {
    record_cleared(state, state.approvals.clear_key(key_id), cause);
}

/// Remove every approval and grant of every key (the vault was locked) and
/// record each.
pub fn clear_all(state: &AppState, cause: ClearCause) {
    record_cleared(state, state.approvals.clear_all(), cause);
}

/// Remove what has expired and record it (`approval_expired` with cause
/// `timeout`, `grant_expired`).
pub fn sweep_once(state: &AppState, now: DateTime<Utc>) {
    let swept = state.approvals.sweep(now);
    for v in &swept.expired {
        state.events.emit(expired_event(v, "timeout"));
    }
    for g in &swept.grants {
        state.events.emit(
            SecurityEvent::new(Action::GrantExpired)
                .key_named(&g.key_id, &g.key_name)
                .credentials(&g.items)
                .detail("grant_id", g.id.as_str())
                .detail("approval_id", g.approval_id.as_str()),
        );
    }
}

/// Start the periodic sweep. Expired entries are already treated as absent
/// when looked up; the sweep frees them, wakes held requests and records the
/// expiry.
pub fn spawn_sweeper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.tick().await; // fires immediately; there is nothing to sweep yet
        loop {
            ticker.tick().await;
            sweep_once(&state, Utc::now());
        }
    });
}

#[cfg(test)]
mod tests;
