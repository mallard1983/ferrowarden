//! The Approvals pages of the admin UI (docs/approvals.md).
//!
//! A list of the approvals waiting for a decision and of the live grants, a
//! detail page per approval, and the three decisions: approve (with a
//! duration), deny, and end a grant early. Every decision goes through
//! `api::approval_service`, the code the admin API uses.
//!
//! The rules are those of the other sensitive actions (`admin_pages`):
//!
//! * a session is required; the id in a link is **not** a capability, so a
//!   link only ever leads to a sign-in;
//! * a decision needs a sign-in within the sudo window (checked on the GET of
//!   the detail page **and** on every POST), the session's CSRF token and the
//!   same-origin proof;
//! * everything shown goes through askama's escaping; the request is shown as
//!   the agent sent it (placeholders), never a value.
//!
//! The approver recorded is the vault account signed in to the UI.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
};
use chrono::Utc;

use crate::api::{approval_service, rotate_credential};
use crate::approvals::{self, ApprovalNeed, GrantView, PendingView};
use crate::error::FerroError;
use crate::middleware::request_context::RequestContext;
use crate::ui::admin_pages::{begin_post, caller, fmt_time, nav};
use crate::ui::handlers::{page, Reply};
use crate::ui::pages::{
    ApprovalDetail, ApprovalListRow, ApprovalPage, ApprovalRow, ApprovalsPage, CreateRow, GrantRow,
    Preset, RotateRow, RotationRow,
};
use crate::ui::session::SessionView;
use crate::ui::web::{parse_form, Transport};
use crate::ui::UiState;

/// The duration presets offered next to the free number field, in minutes.
pub const PRESETS: [u32; 4] = [5, 15, 60, 240];
/// The preset that is selected when the page opens.
const DEFAULT_PRESET: u32 = 15;

const BACK: Option<(&str, &str)> = Some(("/ui/approvals", "Approvals"));

/// The notice behind `?m=`: a fixed list, never echoed.
fn notice_text(code: &str) -> Option<&'static str> {
    match code {
        "approved" => Some(
            "Approved. The agent's next request for these credentials passes until the grant ends.",
        ),
        "approved_create" => Some(
            "Approved. Ferrowarden generates the password and stores the credential now; the agent never sees it. This approval covers that one credential only.",
        ),
        "approved_rotate" => Some(
            "Approved. Ferrowarden generates the new password and stores it on the item as a pending value now; the current password stays until the agent commits. The agent never sees either. This approval covers that one rotation only.",
        ),
        "rotation_aborted" => Some(
            "Rotation aborted. The pending new password was removed and the item's password is unchanged.",
        ),
        "denied" => Some("Denied. The agent is refused for these credentials for a while."),
        "revoked" => Some("Grant revoked. The next request asks again."),
        _ => None,
    }
}

fn notice_from_query(uri: &Uri) -> Option<&'static str> {
    uri.query()
        .and_then(|q| parse_form(q.as_bytes(), &["m"]).ok())
        .and_then(|mut f| f.take("m"))
        .and_then(|m| notice_text(&m))
}

/// `vault field`, `key policy` or both.
fn row(need: &ApprovalNeed) -> ApprovalRow {
    let mut why = Vec::new();
    if need.reasons.vault_field {
        why.push("vault field");
    }
    if need.reasons.key_policy {
        why.push("key policy");
    }
    ApprovalRow {
        name: need.item.clone(),
        why: why.join(" and "),
    }
}

/// `scheme://host[:port]`.
fn target(v: &PendingView) -> String {
    format!("{}://{}", v.scheme, v.host)
}

/// `create` details of a pending approval, for the detail page.
fn create_row(v: &PendingView) -> CreateRow {
    match &v.create {
        None => CreateRow::default(),
        Some(c) => CreateRow {
            name: c.name.clone(),
            has_username: c.username.is_some(),
            username: c.username.clone().unwrap_or_default(),
            uris: c.uris.clone(),
            charset: c.charset.clone(),
            length: c.length,
            approval_required: c.approval_required,
            collection: c.collection.clone(),
        },
    }
}

/// `rotate` details of a pending approval, for the detail page.
fn rotate_row(v: &PendingView) -> RotateRow {
    match &v.rotate {
        None => RotateRow::default(),
        Some(r) => RotateRow {
            name: r.name.clone(),
            charset: r.charset.clone(),
            length: r.length,
            collection: r.collection.clone(),
        },
    }
}

fn pending_row(v: &PendingView) -> ApprovalListRow {
    ApprovalListRow {
        id: v.id.clone(),
        kind: v.kind.as_str(),
        is_create: v.create.is_some(),
        is_rotate: v.rotate.is_some(),
        key_name: v.key_name.clone(),
        collection: v
            .create
            .as_ref()
            .map(|c| c.collection.clone())
            .or_else(|| v.rotate.as_ref().map(|r| r.collection.clone()))
            .unwrap_or_default(),
        credentials: v.items.iter().map(row).collect(),
        method: v.method.clone(),
        target: target(v),
        path: v.path(),
        created: fmt_time(v.created),
        expires: fmt_time(v.expires),
    }
}

fn grant_row(g: &GrantView) -> GrantRow {
    GrantRow {
        id: g.id.clone(),
        key_name: g.key_name.clone(),
        credentials: g.items.clone(),
        target: format!("{}://{}", g.scheme, g.host),
        approver: g.approver.clone(),
        expires: fmt_time(g.expires),
    }
}

/// The signed-in vault account, as the approver recorded in events.
async fn approver(ui: &UiState) -> String {
    ui.account_email().await.unwrap_or_else(|| "ui".to_string())
}

async fn no_longer_pending(ui: &UiState, view: &SessionView) -> Reply {
    ui.message_in(
        view,
        StatusCode::CONFLICT,
        "No longer pending",
        "That approval is no longer pending: it was decided, has expired or was cleared. \
         Nothing was changed.",
        BACK,
    )
    .await
}

async fn grant_gone(ui: &UiState, view: &SessionView) -> Reply {
    ui.message_in(
        view,
        StatusCode::NOT_FOUND,
        "No such grant",
        "That grant is not live any more: it was revoked, has expired or was cleared.",
        BACK,
    )
    .await
}

async fn failed(ui: &UiState, view: &SessionView, e: &FerroError) -> Reply {
    match e {
        FerroError::ApprovalNotPending => no_longer_pending(ui, view).await,
        FerroError::GrantNotFound => grant_gone(ui, view).await,
        FerroError::NoRotationPending(_) => {
            ui.message_in(
                view,
                StatusCode::CONFLICT,
                "No rotation pending",
                "That credential has no pending rotation any more. Nothing was changed.",
                BACK,
            )
            .await
        }
        FerroError::VaultConflict => {
            ui.message_in(
                view,
                StatusCode::CONFLICT,
                "The item was changed",
                "Someone changed the item in the vault, or it needs a person to fix it. Nothing was overwritten. Open the item in the vault, check it, and try again.",
                BACK,
            )
            .await
        }
        FerroError::CredentialNotManaged(_) | FerroError::CredentialNotFound(_) => {
            ui.message_in(
                view,
                StatusCode::NOT_FOUND,
                "Not in the managed collection",
                "There is no such credential in the managed collection. Nothing was changed.",
                BACK,
            )
            .await
        }
        _ => {
            ui.message_in(
                view,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Ferrowarden could not complete that. See the logs and try again.",
                BACK,
            )
            .await
        }
    }
}

// -- The list -------------------------------------------------------------------

pub async fn approvals_list(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    uri: Uri,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    let (pending, grants) = ui.app.approvals.list(Utc::now());
    let email = ui.account_email().await.unwrap_or_default();
    let rotations = pending_rotations(&ui).await;
    page(
        StatusCode::OK,
        ApprovalsPage {
            css_path: &ui.css_path,
            nav: nav(&ui, "approvals", &email, &view),
            sudo: ui.sudo_info(&view),
            csrf: &view.csrf,
            notice: notice_from_query(&uri),
            pending: pending.iter().map(pending_row).collect(),
            grants: grants.iter().map(grant_row).collect(),
            rotations,
        }
        .render(),
    )
}

/// The credentials in the managed collection that have a rotation pending.
async fn pending_rotations(ui: &UiState) -> Vec<RotationRow> {
    use crate::vault::{model::ManagedState, Vault};
    let Ok(ManagedState::Usable(collection)) = ui.app.vault.managed_collection().await else {
        return Vec::new();
    };
    ui.app
        .credentials
        .read()
        .await
        .iter()
        .filter(|(_, entries)| {
            entries
                .iter()
                .any(|e| e.has_next && e.collection_ids.contains(&collection.id))
        })
        .map(|(name, _)| RotationRow { name: name.clone() })
        .collect()
}

// -- The detail page --------------------------------------------------------------

fn presets(selected: Option<u32>) -> Vec<Preset> {
    PRESETS
        .iter()
        .map(|m| Preset {
            minutes: *m,
            checked: Some(*m) == selected.or(Some(DEFAULT_PRESET)),
        })
        .collect()
}

fn detail_page(
    ui: &UiState,
    view: &SessionView,
    email: &str,
    v: &PendingView,
    status: StatusCode,
    error: Option<&str>,
) -> Reply {
    page(
        status,
        ApprovalPage {
            css_path: &ui.css_path,
            nav: nav(ui, "approvals", email, view),
            sudo: ui.sudo_info(view),
            csrf: &view.csrf,
            error,
            d: ApprovalDetail {
                id: v.id.clone(),
                kind: v.kind.as_str(),
                is_create: v.create.is_some(),
                is_rotate: v.rotate.is_some(),
                create: create_row(v),
                rotate: rotate_row(v),
                key_id: v.key_id.clone(),
                key_name: v.key_name.clone(),
                credentials: v.items.iter().map(row).collect(),
                method: v.method.clone(),
                target: target(v),
                path: v.path(),
                url: v.url.clone(),
                request_id: v.request_id.clone(),
                created: fmt_time(v.created),
                expires: fmt_time(v.expires),
            },
            presets: presets(None),
            max_minutes: ui.app.config.approval.max_grant_minutes,
        }
        .render(),
    )
}

pub async fn approval_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    if !approvals::valid_id(&id) {
        return no_longer_pending_get(&ui, &view).await;
    }
    // A decision needs a recent sign-in, so the page that offers one asks for
    // it first: a link from a notification goes through the sign-in and comes
    // back here.
    if let Err(redirect) = ui.require_sudo(&view, &format!("/ui/approvals/{id}")) {
        return redirect;
    }
    let Some(pending) = ui.app.approvals.get(&id, Utc::now()) else {
        return no_longer_pending_get(&ui, &view).await;
    };
    let email = ui.account_email().await.unwrap_or_default();
    detail_page(&ui, &view, &email, &pending, StatusCode::OK, None)
}

/// A GET of an approval that is gone: a plain 404 page (a POST says 409).
async fn no_longer_pending_get(ui: &UiState, view: &SessionView) -> Reply {
    ui.message_in(
        view,
        StatusCode::NOT_FOUND,
        "No longer pending",
        "That approval is not pending any more: it was decided, has expired or was cleared.",
        BACK,
    )
    .await
}

// -- Decisions ------------------------------------------------------------------------

/// The minutes of an approve form: the free number field when it has
/// something in it, else the selected preset. Digits only.
fn minutes_of(preset: Option<&str>, custom: Option<&str>) -> Result<u64, &'static str> {
    const BAD: &str = "Enter the grant length as a whole number of minutes.";
    let custom = custom.map(str::trim).filter(|c| !c.is_empty());
    let text = match (custom, preset) {
        (Some(c), _) => c,
        (None, Some(p)) => p,
        (None, None) => return Err("Choose how long the approval lasts."),
    };
    if text.len() > 6 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    text.parse().map_err(|_| BAD)
}

pub async fn approve_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    Path(id): Path<String>,
    request: Request,
) -> Reply {
    let (view, mut form) = match begin_post(
        &ui,
        &ctx,
        &transport,
        request,
        "/ui/approvals/{id}/approve",
        &["csrf", "preset", "minutes"],
    )
    .await
    {
        Ok(ok) => ok,
        Err(reply) => return reply,
    };
    if !approvals::valid_id(&id) {
        return no_longer_pending(&ui, &view).await;
    }
    if let Err(redirect) = ui.require_sudo(&view, &format!("/ui/approvals/{id}")) {
        return redirect;
    }
    // An approval to create a credential has no duration: it allows exactly
    // one operation, once. Approve or deny, nothing else.
    let one_shot = ui.app.approvals.kind_of(&id, Utc::now());
    if matches!(
        one_shot,
        Some(approvals::ApprovalKind::Create | approvals::ApprovalKind::Rotate)
    ) {
        if form.take("preset").is_some() || form.take("minutes").is_some() {
            let email = ui.account_email().await.unwrap_or_default();
            return match ui.app.approvals.get(&id, Utc::now()) {
                Some(v) => detail_page(
                    &ui,
                    &view,
                    &email,
                    &v,
                    StatusCode::BAD_REQUEST,
                    Some("An approval to create a credential has no duration: it covers that one credential."),
                ),
                None => no_longer_pending(&ui, &view).await,
            };
        }
        return match approval_service::approve_create(
            &ui.app,
            caller(&ctx),
            &id,
            &approver(&ui).await,
        ) {
            Ok(_) if one_shot == Some(approvals::ApprovalKind::Rotate) => {
                Reply::redirect("/ui/approvals?m=approved_rotate")
            }
            Ok(_) => Reply::redirect("/ui/approvals?m=approved_create"),
            Err(e) => failed(&ui, &view, &e).await,
        };
    }
    let preset = form.take("preset");
    let custom = form.take("minutes");
    let minutes = minutes_of(
        preset.as_ref().map(|p| p.as_str()),
        custom.as_ref().map(|c| c.as_str()),
    )
    .and_then(|m| {
        approval_service::check_minutes(ui.app.config.approval.max_grant_minutes, m)
            .map_err(|_| "out of range")
    });
    let email = ui.account_email().await.unwrap_or_default();
    let minutes = match minutes {
        Ok(m) => m,
        Err(text) => {
            let text = if text == "out of range" {
                format!(
                    "The grant must last from 1 to {} minutes.",
                    ui.app.config.approval.max_grant_minutes
                )
            } else {
                text.to_string()
            };
            return match ui.app.approvals.get(&id, Utc::now()) {
                Some(v) => {
                    detail_page(&ui, &view, &email, &v, StatusCode::BAD_REQUEST, Some(&text))
                }
                None => no_longer_pending(&ui, &view).await,
            };
        }
    };
    match approval_service::approve(&ui.app, caller(&ctx), &id, minutes, &approver(&ui).await) {
        Ok(_) => Reply::redirect("/ui/approvals?m=approved"),
        Err(e) => failed(&ui, &view, &e).await,
    }
}

pub async fn deny_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    Path(id): Path<String>,
    request: Request,
) -> Reply {
    let (view, _form) = match begin_post(
        &ui,
        &ctx,
        &transport,
        request,
        "/ui/approvals/{id}/deny",
        &["csrf"],
    )
    .await
    {
        Ok(ok) => ok,
        Err(reply) => return reply,
    };
    if !approvals::valid_id(&id) {
        return no_longer_pending(&ui, &view).await;
    }
    if let Err(redirect) = ui.require_sudo(&view, &format!("/ui/approvals/{id}")) {
        return redirect;
    }
    match approval_service::deny(&ui.app, caller(&ctx), &id, &approver(&ui).await) {
        Ok(_) => Reply::redirect("/ui/approvals?m=denied"),
        Err(e) => failed(&ui, &view, &e).await,
    }
}

pub async fn grant_revoke_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    Path(id): Path<String>,
    request: Request,
) -> Reply {
    let (view, _form) = match begin_post(
        &ui,
        &ctx,
        &transport,
        request,
        "/ui/grants/{id}/revoke",
        &["csrf"],
    )
    .await
    {
        Ok(ok) => ok,
        Err(reply) => return reply,
    };
    if !approvals::valid_id(&id) {
        return grant_gone(&ui, &view).await;
    }
    if let Err(redirect) = ui.require_sudo(&view, "/ui/approvals") {
        return redirect;
    }
    match approval_service::revoke_grant(&ui.app, caller(&ctx), &id, &approver(&ui).await) {
        Ok(_) => Reply::redirect("/ui/approvals?m=revoked"),
        Err(e) => failed(&ui, &view, &e).await,
    }
}

/// `POST /ui/rotations/abort`: throw away the pending new password of the
/// credential named in the form. Needs the same sign-in, CSRF token and
/// same-origin proof as every decision.
pub async fn rotation_abort_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    request: Request,
) -> Reply {
    let (view, mut form) = match begin_post(
        &ui,
        &ctx,
        &transport,
        request,
        "/ui/rotations/abort",
        &["csrf", "name"],
    )
    .await
    {
        Ok(ok) => ok,
        Err(reply) => return reply,
    };
    if let Err(redirect) = ui.require_sudo(&view, "/ui/approvals") {
        return redirect;
    }
    let Some(name) = form.take("name").map(|n| n.to_string()) else {
        return failed(&ui, &view, &FerroError::NoRotationPending(String::new())).await;
    };
    match rotate_credential::admin_abort(&ui.app, caller(&ctx), &name, &approver(&ui).await).await {
        Ok(_) => Reply::redirect("/ui/approvals?m=rotation_aborted"),
        Err(e) => failed(&ui, &view, &e).await,
    }
}

// -- Short links -------------------------------------------------------------------------

/// `/approvals` -> `/ui/approvals`: the link of a prompt is
/// `<ui.public_url>/approvals/<id>`, and the UI itself lives under `/ui`.
pub async fn alias_list() -> Reply {
    Reply::redirect("/ui/approvals")
}

/// `/approvals/{id}` -> `/ui/approvals/{id}` (a valid id only; the sign-in and
/// the sudo window are the detail page's business).
pub async fn alias_detail(Path(id): Path<String>) -> Reply {
    if approvals::valid_id(&id) {
        Reply::redirect(&format!("/ui/approvals/{id}"))
    } else {
        Reply::redirect("/ui/approvals")
    }
}
