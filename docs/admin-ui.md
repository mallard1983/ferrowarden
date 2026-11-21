# Admin Web UI

Ferrowarden has an optional web UI for its operator. **Phase 1** (this release) is the sign-in and a read-only status page. Managing agent keys and policies, and viewing the audit trail, follow in a later release; until then use the [admin API](api-reference.md).

The UI is **off by default**. When you turn it on, it listens on its own port, separate from the agent and admin API.

---

## What you get

- **Sign in with your Vaultwarden master password**, including two-step login (authenticator app, email code or YubiKey OTP). Vaultwarden itself checks the password; Ferrowarden has no password of its own to guard.
- A **status page**: vault locked or unlocked, credential count, last sync, Ferrowarden version, TLS/HTTPS state, agent key count and how many keys have **no policy** (those keys are deny-all until a policy is set), events dropped, the signed-in account and when your session ends. A **Sign out** button.
- No JavaScript, no external fonts, scripts or CDNs. Works at phone width and in light and dark mode.

The UI accepts the vault master password, so it is the most sensitive part of Ferrowarden. Read [What the UI does with your password](#what-the-ui-does-with-your-password) and the [threat model](security.md#16-the-admin-web-ui) before exposing it.

---

## Enabling it

Set `ui.bind` (an address and port). Empty, the default, means the UI is disabled.

```toml
# ferrowarden.toml
[ui]
bind = "0.0.0.0:3001"
```

or in the environment (`docker-compose.yml`):

```yaml
FERROWARDEN_UI__BIND: "0.0.0.0:3001"
```

| Config key | Environment variable | Default |
|---|---|---|
| `ui.bind` | `FERROWARDEN_UI__BIND` | *(empty: UI disabled)* |
| `ui.vaultwarden_url` | `FERROWARDEN_UI__VAULTWARDEN_URL` | `https://vaultwarden` |
| `ui.vaultwarden_ca_file` | `FERROWARDEN_UI__VAULTWARDEN_CA_FILE` | *(empty; the Compose files set `/ca-public/ca.crt`)* |
| `ui.insecure_http` | `FERROWARDEN_UI__INSECURE_HTTP` | `false` |
| `ui.session_idle_minutes` | `FERROWARDEN_UI__SESSION_IDLE_MINUTES` | `15` |
| `ui.session_max_hours` | `FERROWARDEN_UI__SESSION_MAX_HOURS` | `8` |

Then publish the port. In `docker-compose.yml` the mapping is commented out; for a reverse proxy on the same host, bind it to loopback:

```yaml
ports:
  - "127.0.0.1:3001:3001"
```

The UI is a **separate server**. The agent and admin API is never reachable on the UI port and the UI is never reachable on the API port, so an agent that can reach `:3000` cannot reach the sign-in page. Both listeners stop together on SIGTERM.

At startup the `startup` event records `ui_enabled`, `ui_tls` and `ui_insecure_http`.

### How Ferrowarden trusts Vaultwarden

The sign-in talks to Vaultwarden over HTTPS at `ui.vaultwarden_url` (host `vaultwarden` on the `vault-internal` network). That certificate comes from the stack's private CA, so Ferrowarden needs the CA certificate. It must **not** get the CA private key: anyone who holds the key can issue a certificate for `vaultwarden` and capture the master password.

So the `internal-certs` one-shot copies **only `ca.crt`** into a second volume, `internal-ca-public`, and Ferrowarden mounts that read-only at `/ca-public`. The `internal-pki` volume, which holds `ca.key`, is never mounted into Ferrowarden:

```sh
docker compose exec ferrowarden ls -l /ca-public
# -rw-r--r-- 1 root root 639 ... ca.crt        <- and nothing else
```

The copy runs on every `docker compose up` (the one-shot is re-run), so an existing deployment gets the new volume the next time you start the stack, and a regenerated CA is picked up. The file is world-readable (`0644`) because Ferrowarden runs as UID 999; the key stays `0600` in `internal-pki`. `ui.vaultwarden_ca_file` adds the CA **on top of** the public roots; certificate verification is never disabled.

If you run Ferrowarden without Docker, point `vaultwarden_ca_file` at your CA certificate, or leave it empty when Vaultwarden has a publicly trusted certificate. `vaultwarden_url` must be `https://` (plain `http://` is accepted for loopback addresses only, for tests).

---

## HTTPS is required

A request counts as **secure** if

- the UI listener itself serves TLS (`tls_enabled = true`: the UI uses the same certificate as the API), **or**
- the TCP peer is in `trusted_proxies` and its `X-Forwarded-Proto` is `https` (the rightmost value: the proxy nearest to Ferrowarden).

`X-Forwarded-Proto` from any other peer is ignored, because a client could send it.

If a request is not secure, every UI page except the stylesheet answers `400` with a plain page explaining how to fix it. **The sign-in form is never rendered.** The refusal is a `ui_login` event with reason `insecure_transport`, throttled to one per 30 seconds (with a `suppressed` count).

Cookies are always `Secure`; browsers accept `Secure` cookies on `http://localhost`.

### Behind a reverse proxy (Pangolin and similar)

1. Terminate TLS at the proxy and forward to `ferrowarden:3001`.
2. Add the proxy's address to `trusted_proxies` (`FERROWARDEN_TRUSTED_PROXIES`, for example `172.17.0.1`). This is the same setting that makes `X-Forwarded-For` trusted for the client IP, which the lockouts below key on. Without it every client looks like the proxy and one attacker could lock everybody out.
3. Make the proxy send `X-Forwarded-Proto: https` (most do by default) and the original `Host` or `X-Forwarded-Host`. For the same-origin check, Ferrowarden compares the browser's `Origin` with `https://<Host>`; behind a trusted proxy it uses `X-Forwarded-Host` first when there is one.
4. Put the UI behind the proxy's own authentication if you can (an SSO rule, an IP allow-list). The master-password sign-in is a second layer, not a reason to expose the page to the internet. Do **not** add the UI path to an "authentication bypass" rule meant for the agent API.

Pangolin: create a resource that targets `http://ferrowarden:3001` (or `https://` when `tls_enabled`), enable its authentication, and make sure Ferrowarden's container sees the proxy's address as the TCP peer, then list that address in `trusted_proxies`.

### Local testing without TLS

`ui.insecure_http = true` serves the form over plain HTTP. Ferrowarden logs a startup warning and the `startup` event records it. Use it only on a machine you control (`docker-compose.test.yml` sets it for the integration tests).

---

## Signing in

`GET /ui/login` shows one field, the master password. There is **no email field**: Ferrowarden signs in as the account it already serves (the email `bw serve` reports), and only that account.

What happens when you submit:

1. The request is checked: same-origin proof, CSRF token, then the **lockouts** (below). Nothing else runs if a check fails.
2. Ferrowarden asks Vaultwarden for the account's KDF settings (`prelogin`) and **bounds** them (PBKDF2 5 000 to 2 000 000 iterations; Argon2id 16 to 1024 MiB, 2 to 10 iterations, 1 to 16 lanes). Anything outside is refused, so a compromised server cannot make Ferrowarden burn CPU or memory.
3. It derives the Bitwarden login hash on a blocking thread, wipes the password, and sends **the hash** (not the password) to `POST /identity/connect/token`, exactly as the Bitwarden clients do.
4. Vaultwarden's answer decides: success, two-step required, wrong password, or an upstream problem.

On success Ferrowarden **drops Vaultwarden's response unread**: the access and refresh tokens and the encrypted vault keys in it are never deserialized or stored. All that survives is a Ferrowarden session.

### Two-step login

Supported second factors:

| Provider | Supported |
|---|---|
| Authenticator app (TOTP) | yes: a 6 to 8 digit code |
| Email code | yes: **Send code** asks Vaultwarden to email it; at most one request per minute |
| YubiKey OTP | yes: the 44-character code the key types |
| WebAuthn / FIDO2 | no: browsers bind it to Vaultwarden's own origin, so it cannot work here |
| Duo | no |
| Recovery code | no, deliberately: a successful recovery login **deletes all two-step providers** on the account |

If the account has none of the supported ones, the page says so. Add an authenticator app, an email address or a YubiKey to the account (in the web vault) to use the UI.

The pending sign-in (your verified password hash, waiting for the code) is kept in memory for **3 minutes** (Vaultwarden's own window), is bound to your client IP, allows **3 wrong codes**, and exists **once** globally: starting a new password sign-in replaces an older one. It is wiped on success, expiry, the third wrong code and logout. The password and hash never go into a cookie, form field or URL: the browser only holds a random id (`__Host-fw_pending`).

Codes are format-checked locally before anything is sent; a malformed code costs no attempt.

### The new-device email

Vaultwarden can email you when a new device signs in. Ferrowarden registers one device, `ferrowarden-admin-ui` (device type 22), with an identifier derived from the account email, so it stays the same across restarts and you get **at most one** such email, not one per sign-in.

---

## Lockouts

Vaultwarden allows a burst of 10 logins per source IP, and **every** attempt Ferrowarden makes comes from one container IP. An attacker who hammered the UI could use up that budget and lock you out of your own vault. So Ferrowarden stops attackers first:

- **Per client IP:** 5 failures (wrong password or wrong second-factor code) within 15 minutes lock that IP for 15 minutes.
- **Global:** 10 failures within 15 minutes, from all IPs together, refuse **every password submission** for 15 minutes. A second-factor code for an already-pending sign-in is still accepted (its password was right), but its failures count towards both limits.

Both are checked **before** any key derivation or upstream call, so a locked-out request costs Vaultwarden nothing. The page says only "invalid password or code" or "too many attempts"; the event says which limit applied (`details.scope`: `ip` or `global`). Tables are in memory, pruned, and capped.

The global limit means 10 bad guesses can block your own sign-in for 15 minutes; that is the price of protecting Vaultwarden's budget. Waiting it out, or restarting Ferrowarden, clears it. Failures caused by Vaultwarden itself (rate limited, unreachable) do not count.

---

## Sessions, CSRF and cookies

- Sessions live **in memory** (lost on restart; sign in again). The id is 32 random bytes from the OS RNG; only its **SHA-256** is stored, so a memory dump holds no usable cookie.
- Idle timeout `session_idle_minutes` (15), absolute limit `session_max_hours` (8), at most **8** concurrent sessions (the oldest is evicted). Signing in always issues a **new** id and ends the session the browser presented.
- Cookies: `__Host-fw_session`, `__Host-fw_pending`, `__Host-fw_login`: `HttpOnly; Secure; SameSite=Strict; Path=/`, no `Domain` (the `__Host-` prefix makes a browser refuse them otherwise, so a sibling subdomain cannot plant one). The session cookie has no `Max-Age`, so it dies with the browser.
- **Every POST** needs a CSRF token in a hidden `csrf` field, compared in constant time, **and** a same-origin proof: `Sec-Fetch-Site: same-origin`, or, when the browser sent no `Sec-Fetch-Site`, an `Origin` equal to the request's own origin. A POST with neither is refused. Signed-in pages use a per-session token; the sign-in forms use a pre-session token (double-submit: a random value in `__Host-fw_login` and in the form). A refusal is `403`, a `request_rejected` event, and nothing reaches Vaultwarden.
- Form bodies are parsed strictly: unknown or repeated fields, bad encodings and bodies over 8 KiB are `400`.
- Every response carries `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` (no scripts at all), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store` (the hashed stylesheet is cacheable for a day) and, on HTTPS, `Strict-Transport-Security`.

---

## What the UI does with your password

| Secret | Handling |
|---|---|
| Master password | Parsed straight into a `Zeroizing<String>`, moved into the key-derivation thread, wiped when that returns. Never logged, never in an event, never in a cookie, form field or URL. |
| Derived master key, login hash | `Zeroizing` buffers; the master key is wiped as soon as the hash exists. The hash is kept only inside a pending two-step login (wiped on removal) and is sent to Vaultwarden over HTTPS. |
| Vaultwarden tokens and vault keys | Never read: a successful response is dropped unread. |
| Vaultwarden error text | Never shown and never put in an event (a failed TOTP message contains the server time and IP). It is written to the server log at **debug** level only. |
| Session id, CSRF token | Random, OS RNG. Only the SHA-256 of the session id is stored. Never logged. The CSRF token is rendered into its own form, which is how CSRF protection works. |

The request body is read into a buffer Ferrowarden owns and wipes, but the HTTP stack's own read buffers (hyper, the TCP stack) are outside its control, as is any swap or core dump of the host. Run Ferrowarden with swap disabled or encrypted if that matters to you.

---

## What is logged

Every UI action is a [security event](events.md) with a request ID and the client IP:

| Event | Meaning |
|---|---|
| `ui_login` | Sign-in attempt. Outcome `success`, `failure`, or `unknown` for step one of two-step. Reasons: `invalid_credentials`, `two_factor_required`, `two_factor_failed`, `login_locked_out`, `upstream_rate_limited`, `upstream_error`, `insecure_transport`. `details.provider` for second-factor steps |
| `ui_two_factor_email_sent` | A code was requested (or the request failed) |
| `ui_logout` | Signed out |
| `ui_session_expired` | An expired session was detected |
| `request_rejected` | A UI POST refused for CSRF or origin (`details.error`: `csrf_check_failed`, `origin_check_failed`) |

Events never contain the password, the hash, a code, a token, a cookie or anything Vaultwarden said. The [SIEM examples](../examples/siem/README.md) have Wazuh rules and a LogQL query for them.

---

## Limits of phase 1

- Read-only. No key, policy or audit pages yet.
- Sessions do not survive a restart.
- No second-factor "remember this device" (Ferrowarden never sends `twoFactorRemember`).
- WebAuthn, Duo and recovery-code sign-in are not supported.
- The UI needs `bw serve` to be logged in: the account email comes from it.

See also [Security Model §16](security.md#16-the-admin-web-ui) and [Operations](operations.md).
