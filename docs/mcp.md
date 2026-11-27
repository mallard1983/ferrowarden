# MCP server (`ferrowarden-mcp`)

`ferrowarden-mcp` exposes Ferrowarden to agent harnesses that speak the [Model Context Protocol](https://modelcontextprotocol.io/). It gives the agent two typed tools, `list_credentials` and `http_request`, instead of free-form HTTP calls to the Ferrowarden API. It is the same API with the same rules, in a smaller surface that is easier for a model to use correctly.

It is a client-side bridge. It runs next to the agent, holds one agent key, and talks to a running Ferrowarden over HTTPS. It has no vault access, reads no vault state and does not start the proxy. The credential values stay where they were: in Vaultwarden and in Ferrowarden's memory during a request.

```
agent harness  <-- MCP over stdio -->  ferrowarden-mcp  <-- HTTPS + agent key -->  Ferrowarden  -->  target API
```

Transport is stdio only. Streamable HTTP is not implemented.

## Install

Pick one.

**Release archive.** Each release has archives for Linux (x86_64 and aarch64), macOS (Apple silicon) and Windows (x86_64). Each archive holds `ferrowarden`, `ferrowarden-mcp`, `LICENSE` and `README.md`. Check the download against `SHA256SUMS`, and optionally against its build provenance:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify ferrowarden-<version>-<target>.tar.gz --repo mallard1983/ferrowarden
```

The Linux binaries are built on the current Ubuntu runner image and need a glibc at least as new as that image's.

**From source.** With a Rust toolchain:

```sh
cargo install --locked --git https://github.com/mallard1983/ferrowarden --bin ferrowarden-mcp
```

The crate has two binaries, so `--bin ferrowarden-mcp` selects the one to install. `cargo install --path . --locked --bin ferrowarden-mcp` does the same from a checkout.

**Docker.** The Ferrowarden image does not contain `ferrowarden-mcp`. It runs on the agent's side, not next to Ferrowarden.

Run `ferrowarden-mcp --help` to see the options and variables, and `ferrowarden-mcp --version` for the version.

## Configuration

All settings are environment variables. A bad setting stops the program before it speaks MCP: the problem goes to stderr and the exit code is 2. The message names the variable and the rule, never the key or the URL path.

| Variable | Required | Meaning |
|---|---|---|
| `FERROWARDEN_URL` | yes | Base URL of Ferrowarden **including any `api_prefix`**, for example `https://ferro.example.com/k7f3q9`. Must be `https://`. `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`, or when `FERROWARDEN_MCP_ALLOW_HTTP=1`. No user name, password, query or fragment. |
| `FERROWARDEN_AGENT_KEY` | one of the two | The agent key. |
| `FERROWARDEN_AGENT_KEY_FILE` | one of the two | Path of a file that holds the agent key (surrounding whitespace is trimmed). Setting both variables is an error. Prefer this where the harness stores its configuration in a file you share or commit. |
| `FERROWARDEN_CA_FILE` | no | A PEM bundle of extra root certificates, added to the built-in roots. For a Ferrowarden behind a private CA (see [TLS](tls.md)). Certificate checks are never turned off. |
| `FERROWARDEN_MCP_TIMEOUT_SECS` | no | Timeout of one call to Ferrowarden, 1 to 600, default 400. Forwarded requests can be slow, and a request that needs [human approval](approvals.md) is held for up to `approval.wait_secs` (300 at most) first, so this covers the wait and the target's time as well. Keep it above `approval.wait_secs` plus `forward_timeout_secs`. |
| `FERROWARDEN_MCP_ALLOW_HTTP` | no | `1` allows `http://` to a host that is not loopback. For trusted internal networks only: the agent key and all traffic cross the network unencrypted, and a warning is logged at startup. |
| `FERROWARDEN_MCP_LOG` | no | Log level: `error`, `warn` (default), `info`, `debug`, `trace` or `off`. |

The standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`) are honoured by the HTTP client. Redirects from Ferrowarden are not followed.

## Tools

### `list_credentials`

No arguments. Calls `GET /v1/credentials?detail=true` and returns the credentials the agent key may use: for each one, ready-made placeholders (`{{vault:NAME}}` for the password, and `:username`, `:totp`, `:notes` and `:field:FIELD` where the item has them), the hosts it is bound to (`bound_to`), and the reason for anything that is unavailable. The result has structured content (`{"credentials": [...]}`) and a text rendering for harnesses that show only text. Credential values are not part of it.

### `http_request`

Calls `POST /v1/forward`. Arguments are the `request` of the [API](api-reference.md):

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `method` | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS` | yes | The HTTP method. |
| `url` | string | yes | The full `http` or `https` URL of the target. Placeholders are allowed in the path, query and user info, not in the scheme, host or port. |
| `headers` | object of strings | no | Headers for the target. Placeholders are allowed in values. |
| `body` | any JSON value | no | A string is sent as it is; any other value is sent as JSON. |
| `capture` | array of `{ from, as, ttl_secs? }` | no | Values of the response to keep inside Ferrowarden instead of returning them: a login token. `from` is `json:/pointer`, `header:Name` or `cookie:name`; `as` is the session name. Later calls write `{{session:NAME}}` where the token belongs. See [sessions.md](sessions.md). |

The input schemas are strict (`additionalProperties: false`) and a unit test checks them against `components.schemas.ProxyRequest` and `CaptureSpec` in [openapi.yaml](openapi.yaml), so the tool cannot drift from the API. The result has structured content (`status`, `headers`, `body`, `body_encoding`, and `captures` when the call had a `capture`, as in the API) and a text rendering: a status line, the response headers, then the body, then one line per capture (`NAME: captured (expires ...)`, or the status that says why not). A base64 body is summarised in the text as "binary response body, N bytes"; the structured content has the whole body. The text is cut at 100 KB and says so; the structured content is not cut.

The tool descriptions carry the rules an agent has to follow: placeholder syntax, that the listing gives ready-made placeholders, where placeholders may appear, that a credential goes only to its bound hosts, that responses have known credential values scrubbed, how to log in with `capture` and use `{{session:NAME}}`, and what a `403` and a `422` mean.

**Captured sessions through the bridge.** `capture` works as in the API: the token is kept inside Ferrowarden, so it is in neither the structured content nor the text of the result, and `{{session:NAME}}` in a later `http_request` carries it to the same origin only. The bridge has no tool to list or delete sessions (`GET /v1/sessions` and `DELETE /v1/sessions/{name}` are API-only in this release): a session ends at its expiry, or when the operator revokes the key or changes its policy.

### Errors

A target's own `404` or `500` is a normal result: Ferrowarden forwarded the request and the target answered, so the target's status is in the result. An answer from Ferrowarden itself that is not a success becomes a **tool error** (`isError: true`) with the HTTP status, Ferrowarden's message, the `X-Request-Id` and one line of guidance:

| Status | Guidance given to the agent |
|---|---|
| 400 | The request is malformed; fix it, do not resend it unchanged. |
| 401 | The agent key is missing, invalid or revoked; tell the user. |
| 403 | Not allowed for this key or target. Do not retry with other credentials, hosts or methods; tell the user. |
| 404 | A credential was not found in the vault; call `list_credentials`, tell the user if it is still missing. |
| 409 | A name matches more than one item or field; tell the user, do not guess. |
| 422 | A placeholder is malformed or unknown; call `list_credentials` and copy one. |
| 403 with `code` `approval_pending` | A human has to approve this credential. The text says to ask the human to approve it in the Ferrowarden admin UI (with the approval id), then **retry the same request unchanged**. `structuredContent` has `code` and `approval_id`. |
| 403 with `code` `approval_denied` | A human denied it. Stop and tell the user; do not retry. |
| 429 with `code` `approval_limit_reached` | The key has too many open or recent approval requests; do not retry now. |
| 429 | Wait `Retry-After` seconds. |
| 502 | Ferrowarden could not get an answer from the target; not a policy refusal. |
| 503 | The vault is locked; tell the user. |
| other, redirects | Unexpected; for a redirect, `FERROWARDEN_URL` may be wrong. Tell the user. |

If Ferrowarden cannot be reached at all (connection, TLS or timeout), the tool error says "Could not reach Ferrowarden" and the kind of failure, without the URL. A response that is not what Ferrowarden sends (a proxy's HTML page, for example) is reported as such and not echoed.

## Security notes

- **The agent key** is read once from the environment or the key file, held in memory that is zeroed on drop, and sent only in the `X-Agent-Key` header, marked sensitive. It is never logged and never placed in tool output or an error message. The HTTP client library keeps its own copy of the header value for the life of the process, which this program cannot zero. The key is in the environment of the process that starts `ferrowarden-mcp`, as for any program configured this way; use `FERROWARDEN_AGENT_KEY_FILE` with a file only the user can read where that matters.
- **The base URL path** may be a secret `api_prefix`. It is never echoed in tool output, error text or logs. Logs show the host only. If Ferrowarden's own error text were ever to contain the key or the path, both are replaced before the text reaches the agent.
- **HTTPS.** Certificates are always verified. A private CA is added with `FERROWARDEN_CA_FILE`, on top of the built-in roots. Plain `http://` is limited to loopback unless you set `FERROWARDEN_MCP_ALLOW_HTTP=1`.
- **stdout is the protocol channel.** Nothing but MCP messages is written to it once the server runs (`--help` and `--version` print and exit before that). Logs and startup errors go to stderr. The binary is built with clippy's `print_stdout` lint denied, and a test starts the real binary and checks that every stdout line is a JSON-RPC message.
- **Logs.** Plain text on stderr, level `warn` by default. At `info` there is one line per call: tool name, Ferrowarden's status, request id and duration. Request and response headers and bodies, URL paths and queries, the key and the base URL path are never logged. `FERROWARDEN_MCP_LOG` takes a level only, so the HTTP and TLS libraries cannot be switched to a verbose level that might show URLs.
- **No admin operations.** The program has two tools and uses only the agent endpoints (`GET /v1/credentials` and `POST /v1/forward`). It cannot create keys, read the audit log or change a policy.
- **No tool for creating or rotating credentials yet.** `POST /v1/credentials` and the rotation calls ([managed-credentials.md](managed-credentials.md)) are not exposed as a third tool in this release: a tool would need its own result rendering for the approval hold, the `409` and the `503` answers, which is more than the two tools' pattern shares. An agent that has the HTTP API (see [agent-skill.md](agent-skill.md)) can call it; the MCP bridge can still use a credential that was created this way, because it is listed by `list_credentials` like any other. The MCP listing does not show a pending rotation or its `next` placeholder.
- **Limits.** The bridge adds no new secret exposure, but it does not change what Ferrowarden can and cannot do: the [security model](security.md) lists the limits of scrubbing and host binding. A target that is allowed to receive a credential has it.

## Using it with an agent harness

In each example, replace the URL with your Ferrowarden address (with its `api_prefix`, if one is set) and the key file path with a file that holds the agent key. The command must be on the harness's `PATH`, or you can use its absolute path.

### Claude Code

Add it from the command line. Everything after `--` is the command to run:

```sh
claude mcp add ferrowarden \
  -e FERROWARDEN_URL=https://ferro.example.com/k7f3q9 \
  -e FERROWARDEN_AGENT_KEY_FILE=$HOME/.config/ferrowarden/agent-key \
  -- ferrowarden-mcp
```

`-s project` writes the entry to `.mcp.json` in the project, `-s user` makes it available in all projects, and the default is `local` (this project, only for you). Or write `.mcp.json` yourself:

```json
{
  "mcpServers": {
    "ferrowarden": {
      "command": "ferrowarden-mcp",
      "args": [],
      "env": {
        "FERROWARDEN_URL": "https://ferro.example.com/k7f3q9",
        "FERROWARDEN_AGENT_KEY_FILE": "${HOME}/.config/ferrowarden/agent-key"
      }
    }
  }
}
```

Do not put the key itself, or a secret `api_prefix`, in a `.mcp.json` that is committed. Use `${VAR}` references to your environment, as above, or the `local` or `user` scope.

How this was checked: the `claude mcp add` flags against `claude mcp add --help` of Claude Code 2.1.195, and the `.mcp.json` shape by having `claude mcp get` read it (it listed the server as a project server pending approval). The server was not started from Claude Code in that check; the tests in this repository drive the real binary over stdio instead.

### Claude Desktop

Edit `claude_desktop_config.json` (Settings, Developer, Edit Config; on macOS `~/Library/Application Support/Claude/`, on Windows `%APPDATA%\Claude\`) and restart Claude Desktop:

```json
{
  "mcpServers": {
    "ferrowarden": {
      "command": "/usr/local/bin/ferrowarden-mcp",
      "env": {
        "FERROWARDEN_URL": "https://ferro.example.com/k7f3q9",
        "FERROWARDEN_AGENT_KEY_FILE": "/Users/you/.config/ferrowarden/agent-key"
      }
    }
  }
}
```

Use the absolute path of the binary (on Windows, with doubled backslashes: `C:\\Tools\\ferrowarden-mcp.exe`) because Claude Desktop does not start it from your shell. Values are literal: Claude Desktop does not expand `${VAR}`. This snippet follows the format Anthropic documents for MCP servers in Claude Desktop; it was not run in Claude Desktop for this release.

### Other stdio MCP clients

Any client that starts an MCP server as a subprocess and talks to it on stdin and stdout should work with the same three pieces: a command, no arguments, and the environment variables above.

```json
{
  "command": "ferrowarden-mcp",
  "args": [],
  "env": {
    "FERROWARDEN_URL": "https://ferro.example.com/k7f3q9",
    "FERROWARDEN_AGENT_KEY_FILE": "/path/to/agent-key"
  }
}
```

Key names differ between clients (`command`/`args`/`env` is the common form). Only Claude Code was exercised for this document, and only the pieces named above; other harnesses are expected to work but are not verified.

## Tell the agent the rules

The tool descriptions already state them. If you also keep agent instructions, the [agent skill](agent-skill.md) has the same rules for raw HTTP; with MCP the tools replace the `GET /v1/credentials` and `POST /v1/forward` calls and the key is held by the bridge, so the agent never handles it.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| The harness shows the server as failed at startup | A configuration error. Run `ferrowarden-mcp` in a shell with the same environment and read stderr; exit code 2 means a setting was rejected. |
| "Could not reach Ferrowarden: the TLS handshake or certificate check failed" | A private CA: set `FERROWARDEN_CA_FILE`. |
| "Could not reach Ferrowarden: the connection failed" | Wrong host or port, or Ferrowarden is not running. |
| "the body was not ... FERROWARDEN_URL may point at the wrong address" | A missing or wrong `api_prefix`, or a reverse proxy in the way. |
| 401 on every call | The key is wrong, was revoked, or belongs to another Ferrowarden. |
| `list_credentials` is empty | The key's policy allows no credentials. Ask the operator ([operations](operations.md)). |
