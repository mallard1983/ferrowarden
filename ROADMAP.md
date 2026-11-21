# Roadmap

Ferrowarden's goal: an AI agent can do real infrastructure work — call APIs, deploy services, run commands on hosts — while **never holding a credential**. 0.1.0 covers HTTP APIs. The milestones below extend that to more credential types, human control over sensitive actions, the full credential lifecycle, and SSH.

Each item is a GitHub issue with the motivation, a design sketch, security considerations and acceptance criteria. Discussion and feedback are welcome on the issues — especially on anything labelled [`security`](https://github.com/mallard1983/ferrowarden/labels/security). Plans can change; the [milestones](https://github.com/mallard1983/ferrowarden/milestones) are the source of truth.

## v0.2.0 — Credential coverage and integrations

Make Ferrowarden a drop-in for more services and more agent harnesses.

| Issue | Summary |
|---|---|
| [#8](https://github.com/mallard1983/ferrowarden/issues/8) | **Field placeholders** — `{{vault:name:username}}`, custom fields, notes, TOTP |
| [#22](https://github.com/mallard1983/ferrowarden/issues/22) | **Security event log** — complete, structured events for Loki, Wazuh and other SIEMs |
| [#23](https://github.com/mallard1983/ferrowarden/issues/23) | **Strict JSON input** — reject unknown fields, `null` policy values and duplicate keys |
| [#9](https://github.com/mallard1983/ferrowarden/issues/9) | **Per-agent scoping** — limit a key to certain credentials and HTTP methods, with a policy preview |
| [#10](https://github.com/mallard1983/ferrowarden/issues/10) | **OpenAPI specification** for harnesses and automation tools such as n8n |
| [#11](https://github.com/mallard1983/ferrowarden/issues/11) | **MCP server** (`ferrowarden-mcp`) so any MCP-capable harness can use Ferrowarden |
| [#12](https://github.com/mallard1983/ferrowarden/issues/12) | **Push notifications** for blocked requests and security events (Gotify, webhooks) |
| [#13](https://github.com/mallard1983/ferrowarden/issues/13) | **Prometheus metrics** |

## v0.3.0 — Human in the loop and credential lifecycle

Keep humans in control of sensitive actions, and keep derived and newly created credentials away from the agent too.

| Issue | Summary |
|---|---|
| [#24](https://github.com/mallard1983/ferrowarden/issues/24) | **Admin web UI** — Vaultwarden sign-in, key and policy management, "check policy" |
| [#14](https://github.com/mallard1983/ferrowarden/issues/14) | **Human approval** for sensitive credentials, with time-boxed grants |
| [#15](https://github.com/mallard1983/ferrowarden/issues/15) | **Server-side session tokens** — capture login JWTs/tickets so the agent never sees them |
| [#16](https://github.com/mallard1983/ferrowarden/issues/16) | **Generate and store** new credentials without the agent seeing the value |

## v0.4.0 — Agent SSH client

Run commands and deploy files on hosts without the agent holding SSH keys or seeing the secrets it deploys. Design-first: see the threat model in [#20](https://github.com/mallard1983/ferrowarden/issues/20).

| Issue | Summary |
|---|---|
| [#20](https://github.com/mallard1983/ferrowarden/issues/20) | **Design and tracking** — threat model, architecture, open questions |
| [#17](https://github.com/mallard1983/ferrowarden/issues/17) | **`POST /v1/ssh/exec`** — operator-defined targets, pinned host keys, keys never leave Ferrowarden |
| [#18](https://github.com/mallard1983/ferrowarden/issues/18) | **`POST /v1/ssh/write-file`** — write `.env`/config files with substituted secrets over SFTP |
| [#19](https://github.com/mallard1983/ferrowarden/issues/19) | **Default-deny command policy** and protected paths |

## How the pieces fit

A typical "deploy a new service" task, once the roadmap lands, never exposes a secret to the agent:

1. **Generate** the service's admin password in the vault (#16), bound to the service's URL and SSH target.
2. **Write** the compose `.env` on the Docker host with the password substituted (#18); the command policy protects that file from being read back (#19).
3. **Start** the stack with an allowed `docker compose up -d` (#17).
4. **Configure** the service through its API with the password and, after login, a captured session token (#15).
5. **Ask a human** first if the target is sensitive (#14, in the web UI #24), and **alert** on anything blocked along the way (#12).
6. **Record** every step as a security event your SIEM can alert on (#22).
