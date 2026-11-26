# Managed credentials: agents that create credentials

Ferrowarden can create a credential for an agent, with a password the agent never sees. An agent asks for a new login, a human approves it, and Ferrowarden generates a random password, stores it in one Vaultwarden collection you chose, and answers with a placeholder (`{{vault:name}}`). The agent then uses the placeholder, for example to set up a new service, without ever holding the password.

This page describes creating credentials. Rotation and reminders are separate features planned for later releases (they will extend this page).

What the feature guarantees, and what it asks you to trust:

- **The generated value never reaches the agent.** It is generated inside Ferrowarden, encrypted there and sent to Vaultwarden. The response to the agent, every event, every log line and every metric carry names and codes, never the value.
- **Writes go to one collection only.** Ferrowarden creates items in the **managed collection** and nowhere else, whatever an agent key's policy says. Your own items are out of reach.
- **A human approves every create.** Nothing is generated or written before a person has approved that one operation.
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
| `502` `vault_write_failed` | Vaultwarden refused or failed the write. Nothing was created; a retry needs a new approval. |
| `503` | The vault is locked or unreachable, or `managed_collection_unavailable` (with a `reason`). |

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

## What you are trusting

- **The Ferrowarden account has edit rights on one collection.** Before this feature the account only read the vault. Now a compromised Ferrowarden could create or change items in the managed collection (it cannot touch collections the account cannot edit, and it does not write outside the collection it was configured for). Keep that collection dedicated, and keep the account's other access as narrow as you can.
- **An agent can ask, a human decides.** The agent key's `create` patterns bound *what it may ask for*; the approval is what lets one specific operation happen. A key with `create: ["*"]` can ask for anything, so every create still stops at the approval.
- **Approvals are one operation.** An approved create cannot be reused for another name, another username or other URIs.
- **No value in the agent's reach.** There is no read path: nothing here returns the generated value, and a placeholder only ever delivers it to the hosts the credential is bound to. The honest limit is the same as for any credential: a target that behaves badly can reveal what it was sent (see [security](security.md)).

See also: [native vault](native-vault.md) (how the write is made and verified), [approvals](approvals.md), [security](security.md), [events](events.md) (`credential_create`), [metrics](metrics.md) (`ferrowarden_credential_creates_total`).
