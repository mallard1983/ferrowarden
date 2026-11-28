# Managed credentials: agents that create and rotate credentials

Ferrowarden can create a credential for an agent, with a password the agent never sees. An agent asks for a new login, a human approves it, and Ferrowarden generates a random password, stores it in one Vaultwarden collection you chose, and answers with a placeholder (`{{vault:name}}`). The agent then uses the placeholder, for example to set up a new service, without ever holding the password.

It can also **rotate** the password of a credential in that collection, in two phases, so that the service is never locked out and a person's edit is never overwritten ([Rotating a credential](#rotating-a-credential)).

This page describes creating and rotating credentials. Reminders are a separate feature planned for a later release (they will extend this page).

What the feature guarantees, and what it asks you to trust:

- **The generated value never reaches the agent.** It is generated inside Ferrowarden, encrypted there and sent to Vaultwarden. The response to the agent, every event, every log line and every metric carry names and codes, never the value.
- **Writes go to one collection only.** Ferrowarden creates items in the **managed collection** and nowhere else, whatever an agent key's policy says. Your own items are out of reach.
- **A human approves every create and every rotation.** Nothing is generated or written before a person has approved that one operation.
- **Rotation changes only the managed collection, and never overwrites a person.** Only an item in the managed collection can be rotated, only the members Ferrowarden owns are changed, and a write that finds the item edited by someone else fails with `409 vault_conflict` (the one case the server cannot detect is an edit landing between Ferrowarden's read and its write within the same second: see [native vault](native-vault.md#the-window-that-remains)).
- **The cost:** Ferrowarden's Vaultwarden account now needs *edit* rights on one collection. Everything else about its access is unchanged (see "What you are trusting").

## Set it up

### 1. Make the managed collection in Vaultwarden

1. Use an **organisation** (a free Vaultwarden organisation is fine). Create a collection in it, for example `Ferrowarden managed`.
2. Make Ferrowarden's Vaultwarden account (the one whose API key Ferrowarden uses) a member of the organisation with access to that collection. Set its permission to **Can edit**. It must **not** be "View only", and **Hide passwords** must be off (an owner or admin of the organisation can edit every collection, which also works).
3. Keep it dedicated. Moving an item into the collection puts it under agent maintenance on purpose; do not put your own credentials in it.

### 2. Tell Ferrowarden which collection

```toml
[vault.managed]
collection = "Ferrowarden managed"   # a collection id (UUID) or its name
```

or `FERROWARDEN_VAULT__MANAGED__COLLECTION`. Use the id when two collections share a name: a name that matches more than one collection is refused, and Ferrowarden never guesses.

Without this setting, creating is off: `POST /v1/credentials` answers `403 credential_create_disabled`.

### 3. What Ferrowarden checks

On every unlock and sync, Ferrowarden checks that the collection is **usable**: it exists in the account's sync, the account does not have "View only" on it, "Hide passwords" is off, and the organisation key needed to encrypt into it is available (a flag the server did not send counts against the collection).

- **At startup** with file unlock (`unlock_mode = "file"`): if the collection is configured but not usable, **Ferrowarden does not start**, and the log says why. A service you set up to create credentials does not run in a state where it cannot.
- **Otherwise** (manual unlock, or the collection becomes unusable later, for example an owner takes edit rights away): create requests get `503 managed_collection_unavailable` with a `reason` (`not_found`, `read_only`, `hides_passwords`, `ambiguous_name`, `no_organization_key`), Ferrowarden writes one warning to the log and a `vault_sync` event with `warnings.managed_collection`, and nothing falls back to another collection or to the personal vault.

The admin status endpoint (`GET /v1/admin/status`, `managed_collection`) and the **Status** page of the admin UI show the collection's name and id and whether it is usable, with no secrets.

### 4. Give a key permission to create

Creating is its own permission. Add a `create` list of name patterns to the agent key, with the same syntax as `credentials`:

```bash
curl -s -X POST http://localhost:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name": "homelab-claude", "credentials": ["*"], "methods": ["*"],
       "create": ["agent_*"]}'
```

- `create` is optional. Left out it is `[]`: the key cannot create anything. `null` is rejected.
- It is independent of `credentials` (which items the key may *use*) and `methods` (which HTTP methods it may *forward*). A key that may create `agent_*` may use only what its `credentials` list allows.
- Adding or broadening a `create` pattern gives the key more access: the admin UI asks for confirmation, like for any widening.
- Patch it with `PATCH /v1/admin/keys/{id}` (`{"create": ["agent_*"]}`).

## The request

```
POST /v1/credentials
X-Agent-Key: <the agent key>
Content-Type: application/json
```

```json
{
  "name": "agent_keycloak_admin",
  "username": "admin",
  "uris": ["https://keycloak.example.com"],
  "generate": { "length": 32, "charset": "alphanumeric" },
  "approval_required": false
}
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | 1 to 128 characters, no control characters. It must be writable as a `{{vault:...}}` placeholder (any text is: a name with spaces or quotes gets a quoted placeholder). The key's `create` patterns must match it. |
| `username` | no | 1 to 256 characters, no control characters. |
| `uris` | yes | 1 to 16 absolute `http` or `https` URLs, without a username or password. Each must pass the outbound target policy, so a credential can only be created for places Ferrowarden may reach anyway. They become the credential's host bindings. |
| `generate.length` | no | 16 to 128, default 32. |
| `generate.charset` | no | `alphanumeric` (default), `ascii`, `hex` or `base64url`. |
| `approval_required` | no | Default `false`. When `true`, the new item carries a `ferrowarden_approval = required` field, so every later use of it needs a human's approval too ([approvals](approvals.md)). |

The body is parsed strictly: unknown fields, duplicate keys and `null` are rejected with `400`.

**Charsets.** Every character is chosen uniformly at random from the operating system's random generator (rejection sampling, no modulo bias). A password is not guaranteed to contain a character of every kind.

| `charset` | Characters |
|---|---|
| `alphanumeric` | `A-Z a-z 0-9` |
| `ascii` | letters, digits and the symbols `-_.~!@#%^*+=:,` (none of the characters that most often break a shell command, a URL or a JSON string: no quotes, backslash, `$`, backtick, space, `&`, `;`, `|`, `<`, `>`. A few of the symbols still mean something in some places, such as `*` and `!` in a shell and `#` and `%` in a URL, so quote or encode the value where that matters) |
| `hex` | `0-9 a-f` |
| `base64url` | `A-Z a-z 0-9 - _`, no padding |

### The order of the checks

Every check comes before any prompt, and every prompt before any generation or write:

1. The agent key (`401`), then the strict body and every field (`400`), then each URI against the outbound target policy (`403`).
2. The key's `create` patterns match the name (`403 credential_create_out_of_scope`).
3. Creating is on (`403 credential_create_disabled`) and the managed collection is usable (`503 managed_collection_unavailable`).
4. A **fresh sync**, then the name must not exist anywhere in the vault, in any collection (`409 credential_exists`).
5. **A human approves** (below).
6. Ferrowarden generates the password, encrypts it, writes it, then syncs and refreshes its credential cache so `{{vault:name}}` works at once.

Creates are serialised past the approval: the name is checked again, the item written and the cache refreshed while one lock is held, so two approved requests for one name cannot both succeed.

### The answer

```json
{ "name": "agent_keycloak_admin",
  "placeholder": "{{vault:agent_keycloak_admin}}",
  "cache_refreshed": true }
```

`201`, and **never the value**. If the item was written but the cache could not be refreshed, it is still `201` with `"cache_refreshed": false`: the placeholder works once the next refresh has run.

| Status and `code` | Meaning |
|---|---|
| `201` | Created. |
| `400` | The body is not acceptable. |
| `401` | No valid agent key. |
| `403` `credential_create_out_of_scope` | The key has no `create` pattern for this name. |
| `403` `credential_create_disabled` | No managed collection is configured. |
| `403` `approval_pending` | Nobody decided in time. Retry the **identical** request after your human approves; the answer carries `approval_id`. |
| `403` `approval_denied` | A human said no. Stop and tell them. |
| `403` (no code) | A URI is blocked by the outbound target policy. |
| `409` `credential_exists` | A vault item with that name exists. Nothing was asked of a human. |
| `429` `approval_limit_reached` | The key has too many open or recent approval requests. |
| `502` `vault_write_failed` | Vaultwarden refused the credentials **before anything was written** (a refused login), or the write was never sent. Nothing was created; a retry needs a new approval. |
| `502` `vault_write_unknown` | Any other failure of the write (a timeout, a lost connection, a server error, an unrecognised `4xx`): the item **may have been created**. Read the credentials again (`GET /v1/credentials?detail=true`) before retrying: if the name is listed, the create was applied (and a retry would be `409 credential_exists`). |
| `503` | The vault is locked or unreachable, or `managed_collection_unavailable` (with a `reason`). |

A write whose answer Vaultwarden gave with a success status but that Ferrowarden could not read (cut off, not the expected JSON) **was applied**: it is treated as a success.

## Approval

Every create needs a human's approval of **exactly that operation**. The approval store of [approvals](approvals.md) holds two kinds: `forward` (use a credential that needs approval: approving gives a timed grant) and `create` (approving allows one operation, once).

- The operation is identified by a fingerprint of the agent key, `name`, `username`, the sorted `uris`, `generate` and `approval_required`. Change any of them, or ask from another key, and it is a different operation that needs its own approval.
- The request is held up to `approval.wait_secs` (60 s by default). Approved while waiting: it proceeds. Denied: `403 approval_denied`. Undecided: `403 approval_pending` with an `approval_id`, and the agent retries the identical request.
- An approved create is **consumed** by the first matching request: the one that was waiting, or the first retry within `approval.pending_ttl_secs`. It never becomes a grant. A second identical request needs a new approval (and will hit `409` anyway, since the name now exists).
- Denial cooldown, reuse of an open approval with the same fingerprint, and the per-key limits (`max_pending_per_key`, `max_requests_per_key_per_hour`, `max_waiters_per_key`) apply as for forwards, and a create approval counts towards the same limits.
- Open approvals are cleared when the key is revoked, its policy changes, or the vault locks.
- The prompt (UI, admin API, notification) shows: the key, the credential name, the username, the URIs, the character set and length, whether the item will itself need approval, and the **managed collection** it will go to. It has **no value**: there is none yet.

Deciding, with the admin API:

```bash
# See what is waiting. Each entry has "kind": "forward" or "create".
curl -s http://localhost:3000/v1/admin/approvals -H "X-Admin-Key: $ADMIN_KEY"

# Approve a create: no body, no duration.
curl -s -X POST http://localhost:3000/v1/admin/approvals/$ID/approve -H "X-Admin-Key: $ADMIN_KEY"

# Deny (either kind).
curl -s -X POST http://localhost:3000/v1/admin/approvals/$ID/deny -H "X-Admin-Key: $ADMIN_KEY"
```

`approve` takes `{"minutes": N}` for a `forward` approval and **no body** (or `{}`) for a `create` approval; a `minutes` on a create is `400`. The answer is `{"status": "approved", "kind": "create"}` (a forward answers with its `grant` as before). In the admin UI, the approval page of a create has Approve and Deny and no duration.

## What the item looks like in Vaultwarden

A Login item in the managed collection:

- **Name**: the requested name. **Username**: as asked. **URIs**: as asked, each with the checksum the web vault writes.
- **Password**: the generated value.
- A text field `ferrowarden_created_by` with the **name of the agent key** that asked. It is reserved: Ferrowarden writes it, and it is not offered to agents as a field.
- Optionally `ferrowarden_approval = required`.
- No notes, TOTP or favourite, and master password re-prompt off.

Because it is an ordinary item in an organisation collection, everyone with access to that collection can see it (that is how you read the password when you need it, for example to log in to the new service yourself).

## Walkthrough: deploying a new service without the agent seeing its password

You ask your agent to deploy Keycloak and give it an admin account. The agent never learns the admin password.

1. **Create** the credential. The agent sends:

   ```json
   POST /v1/credentials
   { "name": "agent_keycloak_admin", "username": "admin",
     "uris": ["https://keycloak.example.com"],
     "generate": { "length": 32, "charset": "alphanumeric" } }
   ```

   The request is held. A prompt reaches you (admin UI, Gotify, ntfy or webhook): "key homelab-claude wants to create the credential agent_keycloak_admin with username admin for https://keycloak.example.com in the collection Ferrowarden managed: a 32-character alphanumeric password that Ferrowarden generates and the agent never sees."
2. **Approve** it in the admin UI (or with the admin API). The held request goes on: Ferrowarden generates the password, writes it, and answers `201` with `{{vault:agent_keycloak_admin}}`.
3. **Forward the password into the service's setup API.** The agent uses the placeholder in the request that creates the admin account, so Ferrowarden substitutes the value on the way out:

   ```json
   POST /v1/forward
   { "request": { "method": "POST",
       "url": "https://keycloak.example.com/admin/setup",
       "body": { "username": "{{vault:agent_keycloak_admin:username}}",
                 "password": "{{vault:agent_keycloak_admin}}" } } }
   ```

   The credential is bound to `https://keycloak.example.com`, so it can only be sent there. If the service echoes the password back, Ferrowarden scrubs it from the response.
4. **Later requests** sign in with the same placeholders (or [capture a session](sessions.md)). When you need the password yourself, open the item in Vaultwarden.

The agent's whole context contains the name, the placeholders and the service's answers, never the password.

## Rotating a credential

Ferrowarden can also **rotate the password** of a credential that is in the managed collection, with a new password the agent never sees. A password cannot be changed in the vault and at the service it belongs to in one step, and doing it in the wrong order locks the service out. So a rotation has **two phases**, and the old password is never lost:

1. **Start.** The agent asks, a human approves, and Ferrowarden generates a new password and stores it on the item as a **pending** value (a reserved hidden field, `ferrowarden_next`). Nothing else changes: `{{vault:name}}` is still the current password, and `{{vault:name:next}}` is the new one.
2. **Set it at the service.** The agent makes the service's own change-password call through Ferrowarden, signing in with `{{vault:name}}` and sending `{{vault:name:next}}`.
3. **Finish.** The agent **commits** (the new password becomes the password; the old one is kept in the item's password history) or **aborts** (the pending value is thrown away, nothing else changes). Neither needs a second approval: the approval of the start covered the rotation.

### Which items can be rotated

Only an item that is **all** of these:

- in the **managed collection** (its collections include it). It need not have been created by Ferrowarden: moving an item into the collection puts it under agent maintenance on purpose, so to let an agent maintain an existing service account, move the item there (and give the key a `rotate` pattern for it);
- a **Login** with a **password**, with **master password re-prompt off**, and whose name is **unique** in the vault;
- matched by the key's **`rotate`** patterns **and** within the key's `credentials` scope: the name has to be in **both** lists (`rotate` says what the key may ask to rotate, `credentials` what it may see and use, and it needs the latter to use the placeholders anyway).

Anything else is refused **before any prompt**, with a stable code:

| Code | Meaning |
|---|---|
| `credential_rotate_out_of_scope` | The key has no `rotate` pattern for this name. |
| `credential_not_managed` | There is no such item in the managed collection. The answer is the same whether the name exists somewhere else in the vault or not at all, and for a name outside the key's `credentials` scope, so it is not a way to find out what the vault holds. |
| `credential_not_rotatable` | The item is not a login, has no password, or has master password re-prompt on. |
| (`409`, no code) | The managed collection has the name, and another vault item, in the collection or outside it, shares it. A name that no item of the collection has is `credential_not_managed` however many items elsewhere share it. |

Rotating is also off without a managed collection (`403 credential_create_disabled`) and refused while the collection is unusable (`503 managed_collection_unavailable`), like creating.

### Give a key permission to rotate

Rotating is its own permission, a `rotate` list of name patterns with the same syntax as `create`:

```bash
curl -s -X POST http://localhost:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name": "homelab-claude", "credentials": ["*"], "methods": ["*"],
       "create": ["agent_*"], "rotate": ["agent_*"]}'
```

`rotate` is optional (left out it is `[]`: the key cannot rotate anything; `null` is rejected), independent of `create`, `credentials` and `methods`, and adding or broadening a pattern needs confirmation in the admin UI. Patch it with `PATCH /v1/admin/keys/{id}` (`{"rotate": ["agent_*"]}`). The policy preview shows it.

### The requests

```
POST /v1/credentials/{name}/rotate           start (a human approves)
POST /v1/credentials/{name}/rotate/commit    make the pending password the password
POST /v1/credentials/{name}/rotate/abort     throw the pending password away
```

`{name}` is the credential's name, **URL-encoded**: every character that is not a letter, a digit or one of `-` `_` `.` `~` is written as `%XX`. A space is `%20`, a `/` is `%2F`, `Service (prod)` is `Service%20%28prod%29`. (It is the plain name, not the placeholder.)

The start takes an optional body (leave it out for the defaults), parsed strictly like a create's:

```json
{ "generate": { "length": 32, "charset": "alphanumeric" } }
```

`generate` is exactly that of [creating](#the-request): `length` 16 to 128 (default 32) and `charset` `alphanumeric` (default), `ascii`, `hex` or `base64url`.

A commit and an abort take a **required** strict body that names the rotation they mean:

```json
{ "rotation_id": "6WnQ3xZk0m1YtV5pUa9bLw" }
```

`rotation_id` is the opaque identifier of exactly the pending value the start created (the first 16 bytes of the SHA-256 of the pending field's **ciphertext**, base64url: it is not derived from the password, and every start has a fresh one). A commit or an abort writes only if the pending value on the item **now** is the one the id names; otherwise it is `409 rotation_mismatch` and nothing is written. So a request repeated after its answer was lost cannot finish a *later* rotation, and one that was started before a person replaced the pending value cannot accept the replacement.

**The order of the checks for a start**, every check before any prompt and every prompt before any generation or write:

1. The agent key (`401`), then the strict body (`400`).
2. The key's `rotate` patterns match the name (`403 credential_rotate_out_of_scope`).
3. Rotating is on and the managed collection is usable (`403 credential_create_disabled`, `503 managed_collection_unavailable`).
4. A **fresh sync**, then the item checks above (`403 credential_not_managed`, `409` for a duplicate name, `422 credential_not_rotatable`). Membership comes first: a name that no item of the managed collection has is `credential_not_managed` before it can be called ambiguous, and a name outside the key's `credentials` scope is answered like one that does not exist.
5. No rotation is already pending on the item (`409 rotation_in_progress`).
6. **A human approves** this one operation (same hold, retry, denial and limits as a create: [approvals](approvals.md)).
7. Under the same lock as creates, a fresh sync and the checks again, **and the item must be the one that was approved** (the approval names its id: another item with the same name, say one a person made after deleting the original, is `409 vault_conflict`, "start again", and nothing is written); then Ferrowarden generates the value, writes the pending field, syncs and refreshes its cache.

The answer is `202`, and **never a value**:

```json
{ "name": "agent_keycloak_svc",
  "current": "{{vault:agent_keycloak_svc}}",
  "next": "{{vault:agent_keycloak_svc:next}}",
  "rotation_id": "6WnQ3xZk0m1YtV5pUa9bLw" }
```

A commit (`200 { "name", "placeholder" }`) and an abort (`200`, the same shape) run the same policy and item checks, under the lock, and answer `409 no_rotation_pending` when none was started. **Keep the `rotation_id`.** If the answer of a start is lost, the detailed listing (`GET /v1/credentials?detail=true`) shows `rotation_id` next to `rotation_pending: true`, so the rotation can still be finished or aborted.

| Status and `code` | Meaning |
|---|---|
| `202` / `200` | Started / committed or aborted. |
| `400` | The body or the name is not acceptable. |
| `401` | No valid agent key. |
| `403` `credential_rotate_out_of_scope`, `credential_not_managed`, `credential_create_disabled` | See above. |
| `403` `approval_pending` / `approval_denied` | Start only. Retry the **identical** request after your human approves / stop and tell them. |
| `409` `rotation_in_progress` | Start only: one is already pending. Commit or abort it first. |
| `409` `no_rotation_pending` | Commit or abort with nothing pending. |
| `409` `rotation_mismatch` | Commit or abort: the pending value is not the one `rotation_id` names (it was finished, or replaced, since). **Nothing was written.** Read the credential again for the current `rotation_id`. |
| `409` `vault_conflict` | Someone changed or deleted the item (or replaced it while the approval was pending), a person changed the password after the rotation started (commit only), or it needs a person to fix it. **Nothing was overwritten.** See below. |
| `422` `credential_not_rotatable` | Not a login with a password and no re-prompt. |
| `429` `approval_limit_reached` | Too many open or recent approval requests. |
| `502` `vault_write_failed` | Vaultwarden refused the credentials **before anything was written**, or the write was never sent. Nothing was changed (a start needs a new approval). |
| `502` `vault_write_unknown` | Any other failure of the write (a timeout, a lost connection, a server error, an unrecognised `4xx`): the write **may have been applied**. Read the credential again (`GET /v1/credentials?detail=true`): `rotation_pending` and `rotation_id` tell which state the item is in. |
| `503` | The vault is locked or unreachable, or `managed_collection_unavailable`. |

### Using the pending password: `{{vault:name:next}}`

`{{vault:NAME:next}}` is the pending value, and it works **only while a rotation is pending** (otherwise it is the ordinary unknown-placeholder error). It follows the rules of the item's password in every other way: the same host binding (it can only be sent where the item may go), the same `credentials` scope, the same approval rules (an item that needs approval for use needs it for `:next` too), and the same scrubbing from responses. The detailed credential listing shows the placeholder, a `rotation_pending: true` flag and the `rotation_id` while a rotation is pending. A pending value that is empty or only whitespace is no password: `{{vault:NAME:next}}` is then the ordinary unknown-placeholder error, and a commit refuses it (`409 vault_conflict`, nothing written).

`ferrowarden_next` is a **reserved field**, like `ferrowarden_uris`, `ferrowarden_approval` and `ferrowarden_created_by`: it is matched by name (trimmed, any letter case), never offered as a `field:` placeholder, and hidden from the listing's fields.

### Walkthrough: rotating a service account's password through the service's own API

A service account `agent_keycloak_svc` for Keycloak was created earlier (see above). Policy says its password should change, and you want the agent to do it, without ever holding either password.

1. **Start.** The agent sends `POST /v1/credentials/agent_keycloak_svc/rotate`. The request is held. A prompt reaches you (admin UI, Gotify, ntfy or webhook): "key homelab-claude wants to rotate the password of the credential agent_keycloak_svc in the collection Ferrowarden managed: Ferrowarden generates a new 32-character alphanumeric password that the agent never sees, and the current password stays until the agent commits." The Approvals page of the admin UI shows the same, with Approve and Deny and no duration.
2. **Approve.** The held request goes on, and the answer is `202` with the two placeholders. In Vaultwarden the item now has a hidden custom field `ferrowarden_next`; its password has not changed.
3. **Change it at the service.** The agent changes the password through Keycloak's **Admin REST API** (`PUT /admin/realms/{realm}/users/{id}/reset-password`), authenticated with an admin token it captured from the token endpoint (see [sessions](sessions.md)), and sends the new password as the value:

   ```json
   POST /v1/forward
   { "request": { "method": "PUT",
       "url": "https://keycloak.example.com/admin/realms/lab/users/USER-ID/reset-password",
       "headers": { "Content-Type": "application/json",
                    "Authorization": "Bearer {{session:kc_admin}}" },
       "body": { "type": "password", "value": "{{vault:agent_keycloak_svc:next}}", "temporary": false } } }
   ```

   Keycloak answers `204` when it took the password. (The admin token comes from `POST /realms/master/protocol/openid-connect/token` with an admin account's credentials, captured with `"capture": [{ "from": "json:/access_token", "as": "kc_admin" }]`; the user id is in `GET /admin/realms/lab/users?username=...`. This reflects Keycloak's documented Admin REST API of the current releases, written from the documentation and not re-verified against a running Keycloak here; check the paths against your version.)
4. **Commit.** If the service accepted the change, `POST /v1/credentials/agent_keycloak_svc/rotate/commit` with the `rotation_id`. `{{vault:agent_keycloak_svc}}` is now the new password, and the old one is the newest entry of the item's **password history** in Vaultwarden (you can still read it there). **Abort only if the service confirmed that it rejected the change** (`.../rotate/abort`, with the same `rotation_id`): the password stays as it was, and the discarded value goes to the item's password history, so nothing is ever lost from the vault. **If the outcome is unknown** (a timeout, a lost answer), first find out which password the service accepts, for example with a harmless authenticated call that uses `{{vault:agent_keycloak_svc:next}}`: if the service takes it, commit; if it does not, abort. If that cannot be established, ask a human. A service that took the new password never ends up with a vault that does not have it.

What the operator sees: the prompt, the pending approval, the events `credential_rotate_start` and `credential_rotate_commit` (or `..._abort`), and in Vaultwarden the item's revision history. Nothing contains either password.

### A rotation that is stuck

A rotation stays pending until it is committed or aborted, by design, so that an agent that crashed between the service call and the commit does not leave the vault behind the service. If the agent has gone away:

- **The admin UI**: the **Approvals** page has a "Rotations in progress" list with an **Abort rotation** button per credential (it needs a recent sign-in, like any decision). The button is shown only for a rotation the abort would accept; one that needs fixing by hand (say, two pending fields) is listed as "needs manual repair in Vaultwarden". The form names the rotation the page showed, so a stale page cannot abort a later one.
- **The admin API**: `POST /v1/admin/credentials/{name}/rotate/abort` with the admin key (`{name}` URL-encoded) and the body `{ "rotation_id": "..." }` (the id is in the detailed listing). It removes the pending value and changes nothing else. Only items in the managed collection are accepted.
- Or a person deletes the `ferrowarden_next` field in Vaultwarden.

**Before aborting, check which password the service accepts.** If the agent changed it at the service and then lost the answer (or died before the commit), the service may already use the pending value, and aborting would leave the vault with the old one. An abort therefore **keeps the discarded value in the item's password history** (newest entry, five are kept): if the service had switched, a person can still recover it there. The pending value is the only copy until it is committed or kept in the history.

### Conflicts: a person edited the item

Ferrowarden edits the item as it is **now** (it reads it, changes only the members it owns and writes everything else back as it came) and names the revision it read in every write. If a person edited the item in the vault since, the write is refused and the answer is `409 vault_conflict`. **Ferrowarden does not overwrite a person's change** (except for the same-second window described below). The message says what to do: read the credential again and retry. The pending value is still there, and the retry works on the item as the person left it, so their change survives. The same answer is given, and for the same reason, when the item has two `ferrowarden_next` fields, or a pending value that is empty or does not decrypt, or a base that is missing, repeated or unreadable: those need a person to fix them. A deleted item is `409 vault_conflict` too, saying that it no longer exists.

Vaultwarden compares the revision with a tolerance of a second, so Ferrowarden adds its own protections: it re-reads the item immediately before every write, and it writes only to the pending value the `rotation_id` names.

**What a person may change during a rotation.** Every write is built from a fresh read of the item, so a person's edit of the **notes, URIs or other fields** is kept, and the commit goes through. A change of the **password**, or of the **pending value**, is different: a commit would replace it. A start therefore also stores a second reserved hidden field, `ferrowarden_rotation` (a record, encrypted under the item's key, of a random rotation id and the ciphertexts of the password the rotation started from and of the pending value; nothing is hashed; like `ferrowarden_next` it is never offered as a field and is not in the listing), and a commit refuses with `409 vault_conflict` ("the password was changed after the rotation started; nothing was changed") when the password is no longer that one, and with `409 rotation_mismatch` when the pending value is no longer the one written. The record is on the item, so this holds after a restart of Ferrowarden too. Abort the rotation (always possible: it needs only the rotation id; the pending value goes to the item's history) or ask a person to look at the item. A missing, repeated or unreadable record is a `409 vault_conflict`. The one case that remains is an edit that lands in the milliseconds between Ferrowarden's read and its write, within the same second: see [native vault](native-vault.md#the-window-that-remains).

### Events and metrics

`credential_rotate_start`, `credential_rotate_commit` and `credential_rotate_abort` (with `by`: `agent` or `admin`), and `ferrowarden_credential_rotations_total{stage,outcome}`. See [events](events.md) and [metrics](metrics.md). A successful commit or abort is announced to the opt-in `admin` notification category; the approval prompt of the start is a normal `approval` notification.

## What you are trusting

- **The Ferrowarden account has edit rights on one collection.** Before this feature the account only read the vault. Now a compromised Ferrowarden could create or change items in the managed collection (it cannot touch collections the account cannot edit, and it does not write outside the collection it was configured for). Keep that collection dedicated, and keep the account's other access as narrow as you can.
- **An agent can ask, a human decides.** The agent key's `create` patterns bound *what it may ask for*; the approval is what lets one specific operation happen. A key with `create: ["*"]` can ask for anything, so every create still stops at the approval.
- **Approvals are one operation.** An approved create cannot be reused for another name, another username or other URIs, and an approved rotation cannot be reused for another item or other options.
- **A rotation edits an existing item.** That is a new kind of write (see [native vault](native-vault.md#editing-an-item-the-rotation)): Ferrowarden reads the item, changes the members it owns (a hidden field, and on a commit the password, its history and its change date), and writes the rest back as it came. It cannot touch an item outside the managed collection, and it never overwrites a change a person made in between. A person who moves an item into the collection is deliberately putting it under agent maintenance.
- **No value in the agent's reach.** There is no read path: nothing here returns the generated value, and a placeholder only ever delivers it to the hosts the credential is bound to. The honest limit is the same as for any credential: a target that behaves badly can reveal what it was sent (see [security](security.md)).

See also: [native vault](native-vault.md) (how the writes are made and verified), [approvals](approvals.md), [security](security.md), [events](events.md) (`credential_create`, `credential_rotate_*`), [metrics](metrics.md) (`ferrowarden_credential_creates_total`, `ferrowarden_credential_rotations_total`).
