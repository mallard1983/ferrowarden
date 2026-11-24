# Ferrowarden messaging and editorial voice

## Core message

**Project:** Ferrowarden  
**Tagline:** The credential boundary for AI agents  
**Category:** Open-source credential proxy for AI agents

### Approved positioning language

**One line:** Ferrowarden lets AI agents make API requests with named credentials without exposing credential values to the agent.

**Short paragraph:** Ferrowarden is a credential proxy that runs alongside Vaultwarden. Agents submit API requests with placeholders like `{{vault:name}}`; Ferrowarden resolves the secrets, forwards the request to the destination, and scrubs credential values from the response. The agent uses a scoped proxy token instead of direct vault access.

**More technical description:** Ferrowarden mediates outbound API calls from AI agents using credentials stored in Vaultwarden and resolved through a Bitwarden CLI vault API layer. It applies access controls to agent keys and destinations, replaces named placeholders during forwarding, and attempts to prevent credential values from leaking into agent-visible responses.

## The problem we are solving

Agents need to make authenticated calls. Directly injecting passwords or API tokens into model context makes them accessible to prompts, outputs, conversation histories, logs and error paths. Ferrowarden changes the integration pattern: agents reference credentials *by name* and ask the proxy to perform the API operation.

## Tone of voice

| Be | Do not be |
| --- | --- |
| Clear and practical | Hype-driven |
| Security-conscious | Absolute or overpromising |
| Precise about architecture | Vague about what handles a credential |
| Developer-friendly | Overly corporate |
| Transparent about limitations | Dismissive of threat models |
| Community-oriented | Presumptuous about affiliation |

Prefer short declarative sentences, examples with real syntax, and concise reasoning about trust boundaries. Avoid implying the agent has a direct connection to Vaultwarden.

## Messaging examples

### GitHub About description

> Open-source credential proxy for AI agents. Use named vault placeholders instead of exposing secrets to model context.

### README opening

> **The credential boundary for AI agents.** Ferrowarden is an open-source credential proxy that sits alongside Vaultwarden. AI agents send requests using `{{vault:name}}` placeholders; Ferrowarden resolves credentials and forwards requests, without returning the secret values to the agent by design.

### Website intro

> **Give agents access, not secrets.** Let an agent request an authenticated API call while Ferrowarden handles credential substitution and forwarding outside the agent's context.

### Release notes introduction

> This release improves the credential proxy's reliability and operator experience. Review the upgrade notes and security changes before deployment.

### CLI help description

> Ferrowarden — proxy authenticated API calls for agents using named vault credentials.

## Claims discipline

The repository README describes credential storage in Vaultwarden, `bw serve` as the vault API layer, proxy-scoped agent keys, outbound target checks, and response scrubbing. Marketing copy may explain those design choices, but it must not turn design intent into universal guarantees or invent independently verified security certifications.

Do **not** claim:

- All credentials can never leak under any conceivable failure or misconfiguration.
- All prompt-injection attempts are prevented.
- The service is zero-knowledge end-to-end: the proxy must use the decrypted credential to make the outbound call.
- Compliance certification, penetration testing or third-party audit unless documented.
- Official affiliation with Vaultwarden or Bitwarden.

When writing operational documentation, point readers to the current repository security model and security reporting policy rather than treating taglines as security assurances.

## Naming

Always style the name **Ferrowarden**, one word, capital F. The system, binaries and package identifiers may use lowercase `ferrowarden` where standard. Preserve `{{vault:name}}` syntax exactly in code examples. Use `Vaultwarden` for the upstream project and `Bitwarden CLI` or `bw serve` for that API layer. For first use in a general audience document, explain that Ferrowarden is a sidecar to Vaultwarden, not a fork or replacement vault.
