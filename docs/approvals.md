# Human approval

Some credentials should not be used without a person saying yes: the Proxmox root token, the firewall, the NAS admin account. You want the agent to **ask**, rather than have blanket access or none at all.

With approval, a request that uses such a credential is **held**. Ferrowarden does not fetch the value from the vault and does not open a connection to the target. It sends you a prompt through your notifier, you approve or deny in the admin web UI (or with the admin API), and the request goes on or is refused. The agent's own key can never decide.

This page describes what it does, how to turn it on and where it stops. For the API see [api-reference.md](api-reference.md#approvals) and [openapi.yaml](openapi.yaml).

## Contents

- [Which credentials need approval](#which-credentials-need-approval)
- [What the agent sees](#what-the-agent-sees)
- [Deciding](#deciding)
- [Grants](#grants)
- [Limits](#limits)
- [The prompt](#the-prompt)
- [Configuration](#configuration)
- [Reverse proxies and timeouts](#reverse-proxies-and-timeouts)
- [Events and metrics](#events-and-metrics)
- [What ends a grant or an approval](#what-ends-a-grant-or-an-approval)
- [What this does not protect against](#what-this-does-not-protect-against)

## Which credentials need approval

There are two sources. **Either one is enough**, and neither can switch the other off.

**1. The vault item.** Add a custom field named `ferrowarden_approval` to the item, with the value `required`. It is a reserved field, like [`ferrowarden_uris`](native-vault.md): Ferrowarden reads it and does not offer it as a field, so `{{vault:name:field:ferrowarden_approval}}` is an unknown field (`422`) and the field does not show in the credential listing. The name matches in any letter case and with surrounding spaces, so a mistyped capital still requires approval.

The value is compared after trimming, in any letter case, and `required` is the only spelling that is clean. **Any other value, including an empty one, also means required.** A typo can only make a credential stricter. Ferrowarden counts such items in the `vault_sync` event, as `warnings.approval_field_invalid`, and logs a warning, so you can fix the spelling.

**2. The agent key's policy.** A key has an `approval` list of credential name patterns, with the same syntax, limits and wildcard matching as `credentials`. A credential whose name matches needs approval **for that key**:

```bash
curl -s -X POST https://ferrowarden.lan:3000/v1/admin/keys \
  -H "X-Admin-Key: $FERROWARDEN_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name":"homelab-agent","credentials":["*"],"methods":["*"],"approval":["proxmox_*","firewall"]}'
```

`approval` is optional when you create a key and is `[]` when left out: no extra requirement. This is what a key created before this feature has, and a key file without the field loads that way. `null` is rejected like every other policy value. `PATCH /v1/admin/keys/{id}` takes it with the same rules as the other lists (a field that is left out is unchanged). `["*"]` requires approval for every credential.

A key policy can **never exempt** an item that carries the vault field. A policy that removes or narrows approval patterns is treated as a **widening** of access: the admin UI asks you to confirm it, as it does for more credentials or more methods.

Approval is granted per **agent key**, **vault item** and **target origin** (scheme, host and port). The selector does not matter: approving `proxmox` covers `{{vault:proxmox}}`, `{{vault:proxmox:username}}` and `{{vault:proxmox:field:x}}` for that key at that origin. Captured sessions (`{{session:...}}`) never need approval themselves: the login that produced them did.

The policy preview (`POST /v1/admin/keys/{id}/preview`) says which credentials the draft reaches would need approval and why (`vault_field`, `key_policy` or both), and, for a request you give it, which of its credentials would. A preview never creates an approval.

## What the agent sees

The gate is the last check of `POST /v1/forward`: after the key's policy, the vault state, the target policy, host binding and sessions, and before any value is fetched or any connection is opened. So nobody is asked about a request that would be refused anyway.

1. If every item that needs approval has a live grant for this key and origin, the request goes on.
2. If a human denied one of them in the last `approval.pending_ttl_secs`, the answer is `403` with `code` `approval_denied`, at once, with no new prompt.
3. Otherwise the request is **held** for up to `approval.wait_secs` (60 by default). If an approval for the same key, origin and items is already open, the request waits on it and no second prompt is sent. If not, one is opened and a prompt goes out.
   - **Approved** while it waits: the request goes on and the answer is the target's.
   - **Denied**: `403`, `code` `approval_denied`. The agent should stop and tell its human.
   - **Nobody decided** when the wait ends: `403`, `code` `approval_pending`, with an `approval_id`. The message tells the agent to ask its human to approve in the Ferrowarden admin UI and then **retry the same request**.
   - The client **disconnects**: the approval stays open, and the retry will find it.

```json
{
  "error": "Approval required: a human has to approve this request. Ask your human to approve approval 2m3x8Qk0Zr1YtV5pUa9bLw in the Ferrowarden admin UI, then retry the same request.",
  "code": "approval_pending",
  "approval_id": "2m3x8Qk0Zr1YtV5pUa9bLw"
}
```

The pending approval stays open for `approval.pending_ttl_secs` (10 minutes by default) after it was opened. If a human approves it after the request gave up, the grant exists and the agent's retry passes. The MCP server renders these answers for the agent ([mcp.md](mcp.md)).

| Status | `code` | Meaning |
|---|---|---|
| `403` | `approval_pending` | Nobody has decided yet. Ask your human, then retry the same request. |
| `403` | `approval_denied` | A human said no. Stop. |
| `429` | `approval_limit_reached` | This key has too many open or recent approval requests. Do not retry now. |

These codes are stable, and are also the event reason codes ([events.md](events.md#reason-codes)).

## Deciding

**Admin web UI.** The **Approvals** page lists the approvals waiting for a decision and the live grants. The navigation shows how many are waiting. The page of one approval shows the agent key, the credentials and why each needs approval, the method, the target's scheme, host and port, the path, the full URL **as the agent sent it** (with placeholders, never values), the request id and when the approval was opened and closes. Approve takes a duration: presets of 5, 15, 60 and 240 minutes, or a number of minutes from 1 to `approval.max_grant_minutes`. Deny needs nothing more.

Approve, Deny and Revoke are **sensitive actions**, like creating a key: they need a sign-in with the vault master password within the last 10 minutes, the session's CSRF token and a same-origin request. A link in a notification opens the approval page; it asks you to sign in first when needed, and brings you back. The id in a link is **not** a capability: it is unguessable (at least 128 bits), but approving always needs a signed-in session. The approver recorded in events is the vault account you signed in as.

**Admin API** (the admin key, for automation):

| Route | |
|---|---|
| `GET /v1/admin/approvals` | the pending approvals and the live grants |
| `POST /v1/admin/approvals/{id}/approve` | body `{ "minutes": N }`: required, 1 to `approval.max_grant_minutes`, strict JSON, no default |
| `POST /v1/admin/approvals/{id}/deny` | no body |
| `DELETE /v1/admin/grants/{id}` | end a grant early |

The approver recorded for these is `admin_api`. An approval that is no longer pending (decided, expired or cleared) is a `409` and nothing changes. The agent API has no route that decides, and an agent key is refused on every admin route.

## Grants

Approving creates a **grant** for the approval's agent key, its credentials and its origin. It lasts the minutes the approver chose. While it lives, every request of that key for those credentials at that origin passes without a prompt, whatever its method, path or selector: **a grant is not tied to the request that was shown**. The approval page says so. Grants live in memory only: a restart clears them.

Approvers pick the duration to match the task: 5 minutes for one call, an hour for a multi-step job. Each grant is listed, with who approved it and when it ends, on the Approvals page and in `GET /v1/admin/approvals`, and can be revoked early.

A denial works the other way: for `approval.pending_ttl_secs` after it, the same key's requests for that credential at that origin get `approval_denied` at once. A later approval of an approval that was already open replaces a denial.

## Limits

An agent cannot flood you with prompts. These are in addition to the agent rate limiter:

| Setting | Default | What happens beyond it |
|---|---|---|
| `approval.max_pending_per_key` | 3 | A fourth distinct open approval is `429 approval_limit_reached`. |
| `approval.max_requests_per_key_per_hour` | 20 | New prompts per key in a **sliding** hour (each prompt counts for 60 minutes): the next is `429 approval_limit_reached`. |
| `approval.max_waiters_per_key` | 8 | Requests of one key that are held at once; beyond it a request is answered `approval_pending` at once instead of being held. |

Requests that wait on an approval that is already open do not count against the first two.

## The prompt

A new approval sends **one** notification, in the category `approval`. It is on by default whenever a notifier is configured: an approval nobody hears about is useless. Decisions and expiry do not notify by default; they are [events](#events-and-metrics). The prompt has the agent key name, the credential names, the method, the target host (with the port when it is not the default), the path **without the query string**, cut to 200 characters, the approval id, when it closes and a link.

The prompt carries the **path**, which other notifications do not (they show the host only). You need it to decide, and the query string, headers and body are still never included. A path can still hold something the agent chose to put there: the agent writes it. Never a credential value: Ferrowarden has not read one yet. See [notifications.md](notifications.md#the-approval-prompt).

The link is `<ui.public_url>/approvals/<id>`. Set `ui.public_url` to the address you reach the admin UI at: an absolute `https://` URL, or `http://` only with `ui.insecure_http`. Without it, the prompt says to open the Approvals page of the admin UI. If an approval is opened and no notifier is configured, Ferrowarden logs a warning once; the UI and the API still work.

## Configuration

```toml
[approval]
wait_secs = 60                    # 1 to 300: how long a request is held
pending_ttl_secs = 600            # at least wait_secs, at most 3600
max_grant_minutes = 480           # 1 to 10080
max_pending_per_key = 3           # 1 to 50
max_requests_per_key_per_hour = 20  # 1 to 1000
max_waiters_per_key = 8           # 1 to 100

[ui]
public_url = "https://ferrowarden-admin.example.com"
```

Environment variables: `FERROWARDEN_APPROVAL__WAIT_SECS` and so on, and `FERROWARDEN_UI__PUBLIC_URL`. All are validated at start. Add `approval` to `notify.events` if you set that list yourself.

## Reverse proxies and timeouts

A held request lasts up to `approval.wait_secs` and then the forward itself (`forward_timeout_secs`, 30 by default). Ferrowarden does not cut it off earlier: the server has no request timeout of its own. **A reverse proxy in front of the API port needs a read timeout above `wait_secs`**, 300 seconds at most, plus the forward time. Without that, the proxy gives up first and the agent sees a gateway error, not `approval_pending`.

The MCP server's default timeout is 400 seconds so that it never gives up before Ferrowarden answers. If you set `FERROWARDEN_MCP_TIMEOUT_SECS` yourself, keep it above `approval.wait_secs` plus `forward_timeout_secs`. Agents that call the API directly need the same.

When Ferrowarden stops, held requests are answered `approval_pending` at once instead of delaying the shutdown.

## Events and metrics

Events (never a value): `approval_requested` (key, credentials, reasons, method, host, path without query, approval id, expiry, link), `approval_granted` (approver, minutes, grant expiry), `approval_denied` (approver), `approval_expired` (with `cause`: `timeout`, `key_revoke`, `key_policy_change` or `vault_lock`), `grant_revoked` (approver, grant id) and `grant_expired`. The `forward` event has an `approval` detail when the gate ran: `granted_by_grant`, `approved_while_waiting`, `pending`, `denied` or `limit_reached`. See [events.md](events.md).

Metrics: `ferrowarden_approval_requests_total{outcome}` (`granted`, `denied`, `expired`, `limit_reached`), `ferrowarden_approvals_pending`, `ferrowarden_approval_grants_active` and `ferrowarden_forward_approval_total{result}`. See [metrics.md](metrics.md).

## What ends a grant or an approval

- Time: the grant's minutes, or `approval.pending_ttl_secs` for an open approval (`approval_expired`, cause `timeout`; `grant_expired`).
- Revoking the key, or changing its policy (any change): its open approvals and grants are cleared, with the cause.
- The vault locking: every approval and grant is cleared.
- A restart: nothing is written to disk.
- A person revoking a grant (UI or `DELETE /v1/admin/grants/{id}`).

## What this does not protect against

- **A grant is not tied to the shown request.** The approver sees one request, but approves its key, credentials and origin for the minutes chosen. A prompt-injected agent can use that window. Choose short grants for sensitive items, and revoke early.
- **The approver is a person.** The page shows the request as the agent sent it. An agent that disguises what it is doing (an innocent path that the target treats as destructive) is not stopped by Ferrowarden. Read the prompt.
- **Approval does not make the target safe.** After a yes, the usual limits apply (host binding, target policy, scrubbing), and no more.
- **It is not authentication of the agent.** It decides about requests that agent key makes.
- **Notifications can be lost or read by others.** The prompt shows the path. Use a notifier you trust, over TLS ([notifications.md](notifications.md)). If you prefer not to receive paths, leave `approval` out of `notify.events` and check the Approvals page.
- **Items with master password re-prompt** are still refused ([security.md](security.md)): approval is not that feature.
