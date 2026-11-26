# The native vault backend

Ferrowarden can read the vault in two ways, chosen with `vault.backend`:

| | `bw-serve` (default) | `native` |
|---|---|---|
| How | The Bitwarden CLI (`bw serve`) logs in, syncs and decrypts; Ferrowarden calls its local REST API | Ferrowarden speaks the Bitwarden client protocol to Vaultwarden itself and does the cryptography in Rust |
| Extra containers | `bw-serve` (Node.js, the `bw` CLI) | none |
| Where secrets are decrypted | In `bw serve`; a value crosses a local HTTP connection to Ferrowarden | In Ferrowarden, one value at a time, on request; nothing decrypted crosses a network |
| Vault in memory | Decrypted, inside `bw serve` | Ciphertext; only metadata (names, URIs, field names) is decrypted |
| Status | Default | Opt-in, behind the switch (issue #36) |

Both back ends implement the same internal `Vault` interface, and everything else (placeholders, host binding, policy, scrubbing, events, the admin UI) is the same code. The two are tested against each other: see [Equivalence](#equivalence-with-bw-serve).

## Switching

```toml
[vault]
backend = "native"                 # or FERROWARDEN_VAULT__BACKEND=native
url     = "https://vaultwarden"    # FERROWARDEN_VAULT__URL
ca_file = "/ca-public/ca.crt"      # FERROWARDEN_VAULT__CA_FILE (extra CA, PEM; optional)
```

and the Vaultwarden **personal API key** (Account settings, Security, Keys, View API key), as secrets:

```sh
FERROWARDEN_VAULT_CLIENT_ID_FILE=/run/secrets/bw_client_id          # user.<uuid>
FERROWARDEN_VAULT_CLIENT_SECRET_FILE=/run/secrets/bw_client_secret
```

(`FERROWARDEN_VAULT_CLIENT_ID` and `FERROWARDEN_VAULT_CLIENT_SECRET` also work; a direct variable wins over its `_FILE`.) These are the same two files the `bw serve` container already uses. The values never come from `ferrowarden.toml`.

- `unlock_mode` and `unlock_file` work exactly as before: **file mode** logs in, syncs and unlocks at startup and again when the vault locks; **manual mode** waits for `POST /v1/unlock` (or the admin UI) to supply the master password.
- `bw_serve_url` is ignored in native mode (Ferrowarden warns if it is set), and the API key variables are ignored in `bw-serve` mode.
- `vault.url` and `vault.ca_file` are *the* setting for how Ferrowarden reaches Vaultwarden. They replace `ui.vaultwarden_url` and `ui.vaultwarden_ca_file`, which still work as deprecated aliases (a warning is logged; if both are set and differ, `vault.*` wins). `vault.url` must be `https://` (plain `http://` only for loopback hosts, for tests). Certificate verification is never switched off.
- Native mode does not need the `bw-serve` container, the Bitwarden CLI or Node.js. `docker-compose.yml` keeps `bw-serve` as the active default; the native settings are there as comments.
- `vault.allow_hidden_passwords` (`FERROWARDEN_VAULT__ALLOW_HIDDEN_PASSWORDS`, default `false`): see [Hidden passwords](#hidden-passwords-collections-that-hide-them).
- The startup event and `GET /v1/admin/status` report the backend (`vault_backend`), and so does the admin UI's status page.

Switching back is the same setting. Nothing is stored by either back end between runs.

## How it works

1. **Login.** `POST /identity/connect/token` with `grant_type=client_credentials`, `scope=api`, a fixed per-key `device_identifier` (UUID v5 of a constant and `ferrowarden-vault:<client_id>`, so Vaultwarden keeps one device row), and `Bitwarden-Client-Name` / `Bitwarden-Client-Version` headers. The version, `2024.12.0`, is the **protocol version Ferrowarden implements**, not a claim to be that client: Vaultwarden includes SSH-key items in the sync only from that version on, which keeps the item list the same as the CLI's. API-key login returns no refresh token, so Ferrowarden logs in again shortly before `expires_in` and when a request gets a 401.
2. **Sync.** `GET /api/sync?excludeDomains=true` returns the account's keys and every item as ciphertext. Ferrowarden keeps the items exactly as received.
3. **Unlock.** The master password goes through the account's KDF (PBKDF2 or Argon2id, with the same bounds as the admin UI: a hostile server cannot make Ferrowarden burn minutes of CPU or gigabytes of memory), on a blocking thread. HKDF-Expand stretches the master key into an `enc` and a `mac` key, which decrypt the **user key** (`profile.key`). The user key decrypts the **RSA private key**, which unwraps each **organisation key**. The master password and master key are wiped as soon as the user key exists; they are not kept.
4. **Metadata.** For each login or secure note, Ferrowarden decrypts only what the credential map needs: the name, the URIs (and their match types), custom field names and kinds, and the value of the reserved `ferrowarden_uris` field. Which secrets exist (password, username, TOTP, notes) is read from the presence of the ciphertext, not from decrypting it.
5. **Values on demand.** When a request needs a secret, Ferrowarden decrypts that one value into a `Zeroizing<String>`, substitutes it, and drops (wipes) it. TOTP codes are computed from the stored secret at that moment. There is no "fetch the whole item and wipe the rest" step.
6. **Refresh.** On every refresh tick: log in again if the token is about to expire, ask `GET /api/accounts/revision-date`, and fetch the full vault only when the revision changed (plus a periodic safety sync every ten ticks, at least every five minutes). If Vaultwarden is unreachable, Ferrowarden keeps serving the copy in memory and emits the usual `vault_sync` failure event.
7. **Lock.** A changed user key (`profile.key`) or `securityStamp` means the password was changed or the keys rotated: the keys in memory no longer match the account, so the vault locks (cause `vault_key_changed` or `security_stamp_changed`), dropping every key and the credential map; in file mode Ferrowarden then unlocks again from the password file.

## Fail closed, per item

An item is **left out** of the credential map, with a counted reason, if anything needed to read it cannot be read safely. It is never read with a weaker method.

| Reason code | Cause |
|---|---|
| `unsupported_encstring_type` | An EncString of a type outside the allow-list (below) |
| `malformed_encstring` | Bad layout, bad or non-canonical base64, wrong IV/MAC/ciphertext length |
| `mac_failure` | The MAC does not verify: altered data or the wrong key |
| `bad_key_length` | A per-item key that is not exactly 64 bytes |
| `missing_org_key` | The item belongs to an organisation whose key could not be unwrapped |
| `item_key_undecryptable` | The item's own key could not be unwrapped |
| `invalid_utf8` | Decrypted text that is not UTF-8 |
| `hidden_password` | The item's collection hides passwords from this account and `vault.allow_hidden_passwords` is off ([below](#hidden-passwords-collections-that-hide-them)) |
| `decrypt_failure`, `missing_name`, `malformed_item` | Padding failure, no name, an unreadable structure |

One `vault_sync` event per sync carries the counts by reason and up to 20 item **ids** (random UUIDs: never names or values). A user key whose MAC fails is not an item problem: it is an unlock failure (`vault_unlock` with reason `unlock_failed`), because it means the wrong password or an altered key.

## Hidden passwords: collections that hide them

An organisation collection can be shared with a member as **"Hide passwords"**: the member can use the item but is not meant to see its password. Vaultwarden then marks the item `viewPassword: false` in that member's sync. Ferrowarden holds the account's keys and would hand the password to an agent, which the collection's owner chose to keep from this account. So the default is to refuse:

- **Native backend:** an item with `viewPassword: false` is **left out** (reason `hidden_password` in the `vault_sync` event, with the count and the item ids, never a name or a value; also counted in `ferrowarden_vault_excluded_items`). It is not listed by `/v1/credentials`, the MCP server or the policy preview, and a placeholder naming it fails like an unknown item. Only an explicit `false` counts: an item without the field (an older server) is not affected.
- **`vault.allow_hidden_passwords = true`** (`FERROWARDEN_VAULT__ALLOW_HIDDEN_PASSWORDS`, default `false`) is the opt-in for operators who want the account's agents to use such items anyway. Ferrowarden logs a warning at startup, and the `startup` event records `vault_allow_hidden_passwords`.
- **`bw-serve` backend:** `bw serve` does **not** report `viewPassword` (neither the list nor the single-item JSON has the field, and the collection list has no `hidePasswords`), so Ferrowarden cannot tell such an item apart. The CLI withholds the password itself, though: the item's `login.password` is `null` and `GET /object/password/<id>` answers "No password available for this login". With `bw-serve` the item therefore **is listed** (with its username and notes placeholders, but no password placeholder) and its password is never released, whatever `vault.allow_hidden_passwords` says (it has no effect with `bw-serve`; Ferrowarden warns if it is set). The equivalence suite asserts this difference and that neither backend ever releases the password. Use the native backend if you need the whole item left out.

## Supported formats

| EncString type | Algorithm | Accepted |
|---|---|---|
| 2 | AES-256-CBC with PKCS#7, HMAC-SHA256 MAC (checked, in constant time, **before** decrypting) | yes: every value and key encrypted with a symmetric key |
| 3 | RSA-OAEP, SHA-256 | yes, for RSA-encrypted keys only |
| 4 | RSA-OAEP, SHA-1 | yes, for RSA-encrypted keys only (what clients write for organisation keys) |
| 0 | AES-256-CBC, no MAC | **never**: unauthenticated |
| 1, 5, 6 | removed or deprecated | refused |
| 7 and newer | COSE (XChaCha20-Poly1305, "V2" accounts) | refused (not implemented) |

The type number decides the algorithm; nothing is guessed from the shape of the data. Keys must be exactly 64 bytes (32 for AES, 32 for HMAC): a 32-byte legacy key is refused. The RSA key must be PKCS#8, 2048 to 4096 bits.

| Item type | Offered | Notes |
|---|---|---|
| Login (1) | yes | username, password, TOTP, notes, custom fields |
| Secure note (2) | yes | notes, custom fields, bindings through `ferrowarden_uris` |
| Card (3), identity (4), SSH key (5) | no | parsed enough to know they exist; same as `bw-serve` mode |
| In the trash (`deletedDate`) | no | |
| Archived (`archivedDate`) | no | `bw serve` does not list them either (checked by the equivalence suite) |
| Organisation items, with or without a per-item key | yes | except items whose collection hides passwords from the account (`viewPassword = false`): left out unless `vault.allow_hidden_passwords` is on, see below |

**Format drift.** A client format Ferrowarden does not know is not guessed at: the affected items are excluded and counted in the `vault_sync` event, so a newer client writing a new format shows up as a number to investigate rather than as a silent failure or a weaker decryption. Every other item keeps working. The `bw-serve` backend remains available as the fallback for formats not yet implemented.

TOTP: RFC 6238 with SHA-1, SHA-256 or SHA-512; `otpauth://` URIs (`algorithm`, `digits` 1 to 10, `period` above 0), bare base32 secrets (case-insensitive; spaces and `=` ignored) and `steam://`. A specification that cannot produce a code behaves like a missing TOTP (the placeholder fails with "not found").

## Equivalence with bw serve

`docker-compose.test.yml` runs **two Ferrowarden instances** against the same Vaultwarden account: `ferrowarden` (`bw serve`, port 3000) and `ferrowarden-native` (native, port 3003, admin UI on 3004). `tests/equivalence.rs` proves they behave the same:

1. `GET /v1/credentials?detail=true` is identical: names, kinds, placeholders, bindings, unavailable reasons.
2. For **every** placeholder the listing offers, and a set of deliberately bad ones, a forward to the mock API through each instance gives the same status and the same substituted value. Values are compared in memory and never printed; a mismatch is reported by placeholder label and side only.

The fixture vault (`tests/seed/credentials.json`, written by `docker/bw-seed.js` with Node's `crypto`, no `bw` CLI) covers per-item keys, an organisation with a collection, organisation items with and without per-item keys, card/identity/SSH items, a custom-field mix of every kind, URI match types, TOTP in all three shapes (SHA-256 with 8 digits and a 60 second period, Steam, a bare secret with spaces), and edge cases: a whitespace-only password, an empty-string username, an item without URIs, Unicode and very long values, and an archived item.

The fixture vault also has the **hidden-password** case: `docker/bw-seed-hidden.js` registers a second account that owns a second organisation, and shares one item (`tests/seed/hidden.json`) with the test account as an ordinary member whose collection has "Hide passwords" (owners and admins always see passwords, so the test account cannot be the owner). The equivalence suite asserts the one deliberate difference described above.

## Tested Vaultwarden versions

The native backend implements the protocol itself, so the Vaultwarden release matters. CI runs the whole stack (both instances' integration suites, the equivalence suite, the MCP suite and the secret gate) against **two** releases ([cicd.md](cicd.md#vaultwarden-versions-in-ci)):

| Vaultwarden | Test account KDF | Bitwarden CLI for `bw serve` |
|---|---|---|
| 1.37.5 (current) | PBKDF2-SHA256, 600 000 iterations | 2026.11.0 |
| 1.36.0 (previous minor) | Argon2id, 64 MiB, 3 iterations, parallelism 4 | 2026.5.0 |

The statement of support is: the current and the previous minor release. A newer Vaultwarden that changes the formats is first run against the stack. The default backend changes only when the equivalence suite is green on both, and on a vault written by a real web vault or extension client with organisation items, as set out in #36.

## A vault written by the web vault

The fixtures above are written by our own seeder, so a format that only real clients write would not show up in them. `src/vault/native/testdata/webvault/` closes that gap: a throwaway account created **by hand in the web vault bundled with Vaultwarden 1.37.5**, with Argon2id (32 MiB, 6 iterations, parallelism 4), a login with TOTP and a custom field of every kind (text, hidden, checkbox, linked), an otpauth TOTP, a login bound elsewhere, a secure note bound through `ferrowarden_uris`, a card, an identity, an SSH key, an organisation with a collection holding a login and a note, a trashed item and an archived item. The token and `/api/sync` responses are kept verbatim (ciphertext only), and the expected values are what the Bitwarden CLI 2026.11.0 decrypted from the same account. A unit test unlocks the capture with the native backend and checks every name, binding and value against that reference, and that cards, identities, SSH keys, trashed and archived items are not offered.

What the capture showed:

- Only EncString types 2 (items) and 4 (the organisation key). No type 7 (COSE) and no V2 key material. A second test fails by name if a future capture brings either.
- **Every** item has a per-item key, including organisation items.
- An emptied notes field is stored as `""`; Ferrowarden treats an empty value as absent (nothing to substitute).

`testdata/webvault-hidden/` is the same organisation seen by a second account that is an ordinary member of the collection with **"Hide passwords"**. Vaultwarden marks the items `viewPassword: false` but **still sends the password's ciphertext**: hiding is enforced by clients only, which is why the native backend refuses these items itself by default. Tests check that both items are left out by default (no value of any kind is released) and are usable, with the owner's values, when `vault.allow_hidden_passwords` is on.

Changing the KDF from the bundled web vault (Settings, Security, Keys) left two test accounts unable to sign in with their password afterwards; avoid doing that on a Vaultwarden 1.37.5 account you depend on until the cause is known.



## Provenance and licence

Ferrowarden is licensed under FSL-1.1-ALv2. The native backend is **implemented from the observed wire format** (what Vaultwarden sends and accepts) **and the published descriptions of the algorithms** (AES-CBC, HMAC, HKDF RFC 5869, RSA-OAEP, TOTP RFC 6238). It uses **no Bitwarden SDK crate and no code ported from one**: those are GPL-3.0 or under the Bitwarden SDK License, which is not compatible with Ferrowarden's licence. The known-answer test vectors were generated for this project with Node's `crypto` module (`tests/native-vectors/gen.js`), not taken from the SDK's tests. The cryptography uses RustCrypto crates, all MIT OR Apache-2.0:

| Crate | Use |
|---|---|
| `aes` 0.9, `cbc` 0.2 | AES-256-CBC |
| `hmac` 0.13, `sha2` 0.11, `sha1` 0.11 | MAC, HKDF, OAEP, TOTP |
| `hkdf` 0.13 | HKDF-Expand |
| `rsa` 0.10 | RSA-OAEP (0.10 or later: earlier releases carry RUSTSEC-2023-0071, the Marvin timing side channel) |
| `libc` 0.2 (Linux) | `PR_SET_DUMPABLE`, `RLIMIT_CORE` |

All are pure Rust (except the two `libc` calls) and build for the static musl image. See [security.md](security.md) for the security trade-offs of this back end.
