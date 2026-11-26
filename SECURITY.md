# Security Policy

Ferrowarden is built to keep credential values out of AI agents' context, so security reports are very welcome. Ferrowarden is an independent project, not affiliated with Vaultwarden or Bitwarden; report vulnerabilities in those projects upstream.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. This creates a private advisory that only the maintainers can see.

Please include:

- What an attacker can achieve, and from which position (agent key holder, network observer, target service, someone who can reach the web vault, …)
- Steps to reproduce — a `POST /v1/forward` payload, configuration, or a failing test is ideal
- The version or commit you tested

This is a small, volunteer-maintained project. Expect an acknowledgement within a week; fixes are prioritised by severity. Once a fix is released, the advisory is published with credit to the reporter (unless you prefer otherwise).

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x (latest) | Yes |
| Older / unreleased snapshots | No — upgrade first |

## Scope

In scope — anything that breaks a guarantee in the [Security Model](docs/security.md), for example:

- An agent obtaining a credential **value** (in a response, header, error message, log line or audit entry), or sending a credential to a host not listed in its vault item's URIs
- Reaching the vault endpoint, cloud metadata or other blocked internal targets through `/v1/forward`
- Bypassing agent or admin key authentication, or the outbound target policy
- Credential values persisting in memory or on disk beyond what the security model describes
- Weaknesses in the shipped Docker Compose configuration (network exposure, secrets handling, internal TLS)

Out of scope:

- The [threat model's out-of-scope items](docs/security.md#out-of-scope): host compromise, Vaultwarden vulnerabilities (report those upstream), theft of an agent or admin key
- A target service that is *bound* to a credential transforming and returning it in a form the scrubber cannot recognise — binding a credential to a host means trusting that host with it
- Deployments that disable protections (`enforce_credential_hosts = false`, `allow_private_targets = true`, TLS disabled on a network hop)
- Denial of service through request volume beyond the documented rate limits

## Dependencies

`cargo audit` is run before releases. Known advisories and their assessment are listed in [docs/security.md](docs/security.md#dependency-security).
