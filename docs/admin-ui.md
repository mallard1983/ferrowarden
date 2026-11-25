# Admin Web UI

Ferrowarden has an optional web UI for its operator. It covers sign-in, a status page, **agent key management** (list, create, edit policy with a dry-run, revoke) and an **audit view**. Everything the UI does to keys goes through the same code as the [admin API](api-reference.md), so both behave identically.

The UI is **off by default**. When you turn it on, it listens on its own port, separate from the agent and admin API.

---

## What you get

- **Sign in with your Vaultwarden master password**, including two-step login (authenticator app, email code or YubiKey OTP). Vaultwarden itself checks the password; Ferrowarden has no password of its own to guard.
- A **status page**: vault locked or unlocked, credential count, last sync, Ferrowarden version, TLS/HTTPS state, agent key count and how many keys have **no policy** (those keys are deny-all until a policy is set), events dropped, the signed-in account and when your session ends. A **Sign out** button.
- A **Notifications** section on the status page: which [push notifiers](notifications.md) are enabled (type and host only, never the URL or a token), which categories they cover, the counters (sent, failed, suppressed by the rate limits, dropped) and a **Send test notification** button that sends one test message to every sender and shows what each answered. It is a POST with the CSRF token and the same-origin check, needs no recent sign-in (it changes nothing), and accepts one test every 10 seconds.
- **Keys, policy editor and audit pages**, described under [Managing keys](#managing-keys) and [Audit view](#audit-view).
- No JavaScript, no external scripts, fonts or CDNs. Works at phone width and follows your system's light or dark setting. See [Appearance](#appearance).

The UI accepts the vault master password, so it is the most sensitive part of Ferrowarden. Read [What the UI does with your password](#what-the-ui-does-with-your-password) and the [threat model](security.md#16-the-admin-web-ui) before exposing it.

---

## Appearance

The UI follows the Ferrowarden brand kit: Paper and Deep Iron surfaces, Steel and Mist text, with copper kept for the mark, focus rings and small highlights. The **theme follows your system** (`prefers-color-scheme`); there is no toggle, because there is no JavaScript to remember one. The font is Inter, served from the UI's own origin together with the icons (`/ui/static/`, no session needed, cached for a day), so nothing is fetched from a third party and the browser never needs an outside connection to draw a page. Inter is under the SIL Open Font License (`src/ui/assets/fonts/OFL-Inter.txt`).

The layout is made for phones as well as desktops:

- The header shows the mark, the name and an "Admin" label; below about 720 px the navigation moves to its own row with 44 px tap targets, and a long account email is cut with an ellipsis instead of pushing the layout.
- The keys list becomes one card per key below about 720 px, and the audit list one card per event below about 1120 px (it has more columns). Wide screens keep a real table. Ids, request ids, URLs, patterns and placeholders wrap; they are never cut off.
- The audit filters, the key editor (the method checkboxes wrap in a grid, the action buttons wrap) and the Check policy results fit the screen without sideways scrolling.

The pages are served with the same strict content security policy as before, plus `font-src 'self'` for the font. Nothing inline is allowed: no `style=` attributes and no `<style>` blocks.

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

If a request is not secure, every UI page except the static files (stylesheet, font, icons) answers `400` with a plain page explaining how to fix it. **The sign-in form is never rendered.** The refusal is a `ui_login` event with reason `insecure_transport`, throttled to one per 30 seconds (with a `suppressed` count).

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
- Every response carries `Content-Security-Policy: default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` (no scripts at all, nothing inline), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store` (the static files, such as the hashed stylesheet, are cacheable for a day) and, on HTTPS, `Strict-Transport-Security`.

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

## Managing keys

All pages need a session. Every POST needs the per-session CSRF token and the same-origin proof, and its form is parsed strictly: a field that is not part of the form, or one given twice, is a `400`. The header navigation (Status, Keys, Audit, the signed-in account, Sign out) is on every signed-in page and marks the current page with `aria-current="page"`.

| Page | What it does |
|---|---|
| `/ui/keys` | Table of keys sorted by name: name, short id, created, methods, credential patterns (first three, with a count) and links to view/edit and revoke. A key with no policy (created with 0.1.0, `policy_set = false`) carries a **"No policy: deny-all"** badge. |
| `/ui/keys/new` | **Create** (needs a recent sign-in). Name (1 to 128), credential patterns (one per line, blank lines ignored, each trimmed) and one checkbox per method (`m_GET` to `m_OPTIONS`) plus **All methods** (`*`). Validation errors (the same messages as the API) appear next to the form with your input kept. The form is single use, see below. |
| `/ui/keys/new/draft/{id}`, `/ui/keys/{id}/draft/{draft}` | An **unsaved form restored after a sign-in**, see [Unsaved changes survive a sign-in](#unsaved-changes-survive-a-sign-in). |
| `/ui/keys/{id}` | The key and its saved policy, and the editor (below). |
| `/ui/keys/{id}/revoke` | **Revoke** (needs a recent sign-in): a confirmation page naming the key, then a POST. |

### The create form is single use

The create form carries a hidden `form_id`: 32 random bytes (base64url), issued when the form is shown, kept in your session (at most 8 outstanding; they end with the session) and used up by the POST that creates the key. If the same form is sent again, which is what reloading the token page and answering "resend" does, **no second key is created**. The answer is a page saying that the form was already submitted (or expired), that the token cannot be shown again and where to go next (`409`). A POST with a missing, unknown or foreign form id gets the same page. A submission that fails validation creates nothing and keeps its id, so you can fix the form and send it again.

### The token is shown once

A successful create renders the **token page directly in the response to the POST**, with the token in a read-only text field you can select and copy (there is no clipboard script). There is no redirect, so the token is in no URL, no history entry and no `Location` header; the response is `Cache-Control: no-store`. It is not stored: only its hash is kept, so after you leave the page the only remedy for a lost token is to revoke the key and create another. The token is never in an event, a log line, a later page or the audit view.

### The policy editor and Check policy

On `/ui/keys/{id}` the form is pre-filled with the saved policy and has three actions:

- **Check policy** (no recent sign-in needed): a dry run through the same preview as `POST /v1/admin/keys/{id}/preview`. It shows the saved and the draft policy, the credentials the draft **gains** and **loses** (highlighted), the full list of credentials the draft reaches with their ready-made `{{vault:...}}` placeholders and `bound_to` hosts (names only, never values), and the allowed methods. Nothing is saved, no value is read, nothing is sent. The form stays filled in so you can adjust and check again.
- **Check request** (also no recent sign-in): method, URL, headers (`Name: value` per line, at most 50, no repeated name in any letter case) and a body (sent as a raw string) are checked against the *draft* with the same logic as a real forward, minus the live connection. The page says Allowed or Denied with the status, the reason code and the message.
- **Save policy** (needs a recent sign-in): applies the draft with the shared patch. If the draft **gives the key more access** you first get a confirmation page with the differences and a **Confirm save** button (a POST carrying `confirm=1` and the same draft); a narrowing change saves directly and redirects to the key with a "Policy saved" notice. "More access" is judged conservatively and without the vault: a method the saved policy lacks, or a credential pattern the saved patterns do not cover (so `lab_a*` under `lab_*` is covered, `lab*` is not). That also catches a pattern that matches nothing yet but would match a credential added later.

A key with no policy (legacy) is explained on its page: it can do nothing until a policy with **both** the patterns and the methods is saved (an empty list means none).

## Recent sign-in for sensitive actions

Creating a key, revoking one and saving a policy change need a sign-in within the last **10 minutes** (the "sudo window"; not configurable). A session is created at sign-in and remembers when; activity keeps the session alive but never extends the window. Viewing, Check policy, Check request and the audit view do not need it.

It is enforced on **both the GET of the form and the POST**. If the sign-in is older, the browser is redirected to `/ui/login?m=sudo&next=<path>` with the message "Sign in again to continue". After a successful sign-in (password and second factor if required) a new session is created, as always, and the browser goes to `next`. A POST that arrives stale (for instance a save after a long pause) is not processed, but what you typed is kept, see below. Pages with sensitive actions show "Signed in N minutes ago" and whether the window is open.

### Unsaved changes survive a sign-in

When a **Save policy**, **Confirm save** or **Create key** arrives after the window ran out, Ferrowarden parks the draft instead of discarding it: for a save, the patterns, the methods and the request-check fields; for a create, the name, the patterns and the methods. It then redirects to `/ui/login?m=sudo&next=/ui/keys/{id}/draft/{draft}` (or `/ui/keys/new/draft/{draft}`). The `{draft}` part is a random 32-byte id, not your text, and the path passes the `next` rules below.

After you sign in (including the second factor) you land on that URL, which shows the editor **filled in with your changes but not saved**, with the notice "Your unsaved changes were restored. Review them and save again." Then the normal path applies: you save with a fresh sign-in, and a change that gives the key more access still asks for confirmation. **Nothing is ever saved automatically.**

The parked drafts live in memory only: at most 16, for 15 minutes, used up by the first visit, and **bound to your client IP**. A draft that is missing, expired, already restored, for another key or from another address is not an error: you get the normal editor (or a blank create form) with a notice that the unsaved changes could not be restored. They are lost on restart. The request-check fields are wiped from memory when the draft goes.

`next` is validated, on the way in and again before the redirect: it must start with `/ui/`, be at most 200 characters, and consist only of ASCII letters, digits and `/ _ - .`. That rules out schemes, hosts, `//`, backslashes, any percent-encoding (so `%2f%2f` cannot decode into something else), `.` and `..` segments, query strings, and the sign-in and static paths. Anything else becomes `/ui/`. The sign-in form carries it in a hidden field that is re-validated on submit; for a two-step login it is kept **server-side in the pending login**, and the second-factor form does not accept a `next` field at all.

## Audit view

`/ui/audit` lists the security events held in the in-memory ring buffer (the same data as `GET /v1/admin/audit`), newest first. Filters are GET parameters: `action` (a select of the known actions), `outcome` (`success`, `failure`, `unknown`), `key` (a key id or name, exact), `ip` (exact) and `limit` (25, 100 or 500; default 100). The query is parsed strictly: an unknown or repeated parameter, or a value that is not allowed, is a `400`. Columns: time, action, outcome (with the reason below it), key name and source IP, method and target host with the status, request id, and a `<details>` disclosure with the event as pretty-printed JSON. Everything is HTML-escaped (the JSON sits in a `<pre>`). Reading it emits an `audit_read` event. For history beyond the buffer use the [event sinks](events.md#sinks-and-configuration).

### Rendering safety

Every value comes through an auto-escaping template: key names, credential names, field names and placeholders (which can contain quotes, `<` and spaces), and event contents are never trusted. There is no JavaScript at all and the content security policy is unchanged.

## What is logged

Every UI action is a [security event](events.md) with a request ID and the client IP:

| Event | Meaning |
|---|---|
| `ui_login` | Sign-in attempt. Outcome `success`, `failure`, or `unknown` for step one of two-step. Reasons: `invalid_credentials`, `two_factor_required`, `two_factor_failed`, `login_locked_out`, `upstream_rate_limited`, `upstream_error`, `insecure_transport`. `details.provider` for second-factor steps |
| `ui_two_factor_email_sent` | A code was requested (or the request failed) |
| `notify_test` | The Send test notification button was used (`details.via` is `ui`; outcome `failure` if a sender did not accept it) |
| `ui_logout` | Signed out |
| `ui_session_expired` | An expired session was detected |
| `key_create`, `key_revoke`, `key_policy_change`, `policy_preview`, `key_list`, `audit_read` | The same events as the admin API, with `ferrowarden.details.via` set to `"ui"` (the API sets `"api"`), so a SIEM can tell them apart. Never a token |
| `request_rejected` | A UI POST refused for CSRF or origin (`details.error`: `csrf_check_failed`, `origin_check_failed`) |

Events never contain the password, the hash, a code, a token, a cookie or anything Vaultwarden said. The [SIEM examples](../examples/siem/README.md) have Wazuh rules and a LogQL query for them.

---

## Limits

- Screens are plain forms: no live updates, no bulk actions, no key renaming, no theme switch (the system setting decides).
- The audit view shows only what is in the ring buffer.
- Sessions do not survive a restart.
- No second-factor "remember this device" (Ferrowarden never sends `twoFactorRemember`).
- WebAuthn, Duo and recovery-code sign-in are not supported.
- The UI needs `bw serve` to be logged in: the account email comes from it.

See also [Security Model §16](security.md#16-the-admin-web-ui) and [Operations](operations.md).
