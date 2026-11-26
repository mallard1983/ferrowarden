# Contributing to Ferrowarden

Thanks for your interest in improving Ferrowarden! Bug reports, documentation fixes, tests and code are all welcome.

Ferrowarden is a security tool: its job is to keep credential values out of AI agents' context. That shapes how changes are reviewed, so please read the [Security Model](docs/security.md) before working on anything in the request path.

## Reporting security issues

**Do not open a public issue for a vulnerability.** Follow the [Security Policy](SECURITY.md) and report it privately through GitHub's **Report a vulnerability** button.

## Reporting bugs and suggesting features

Open an issue with:

- what you expected and what happened instead,
- how to reproduce it (configuration, the `/v1/forward` payload, logs — **with any credential values, admin keys and agent tokens removed**),
- your platform (Linux / Windows / macOS, Docker version) and the Ferrowarden version or commit.

For larger changes, open an issue to discuss the approach before writing code. Looking for something to work on? The [roadmap](ROADMAP.md) links issues with design notes and acceptance criteria.

## Development setup

Prerequisites: Rust (stable), Docker with Compose v2, `openssl` (ships with Git for Windows) and Python 3. On Windows use the MSVC Rust toolchain (`rustup default stable-x86_64-pc-windows-msvc`).

```sh
git clone https://github.com/mallard1983/ferrowarden.git
cd ferrowarden

# Build a throwaway test stack (Vaultwarden, Ferrowarden, mock API)
# with a test account and fake credentials; writes .env.test
./scripts/dev-setup.sh            # Linux/macOS
.\scripts\dev-setup.ps1           # Windows (PowerShell 7)
```

To start over: `docker compose -f docker-compose.test.yml down -v`, delete `secrets/bw_client_id`, `secrets/bw_client_secret` and `secrets/test_agent_key`, and run the setup script again.

## Checks — run these before opening a pull request

CI runs all of them on every push and pull request.

```sh
cargo fmt --check                            # formatting
cargo clippy --all-targets -- -D warnings    # lints, warnings are errors
cargo test --bins                            # unit tests

# Integration tests against the running test stack
set -a; . ./.env.test; set +a                # PowerShell: .\scripts\load-env.ps1
cargo test --test integration -- --test-threads=1
cargo test --test mcp -- --test-threads=1
```

## Guidelines for changes

**Security-sensitive changes** — anything touching substitution, scrubbing, the target policy, credential host binding, authentication, key storage, logging or error messages — must:

- keep every guarantee in [docs/security.md](docs/security.md), or update that document and explain why;
- come with tests that would fail if a credential value could be returned to the agent (see the leak-prevention tests at the end of `tests/integration.rs` and the mock API's `/echo` endpoints);
- never put credential values, admin keys or agent tokens into logs, audit entries, error messages or test output.

**Generally:**

- Keep pull requests focused: one change per PR, with a description of what and why.
- Add or update tests for behaviour changes. End-to-end behaviour goes in `tests/integration.rs`.
- **Unit tests live in their own files**, never inline in production code: `src/foo/bar.rs` declares `#[cfg(test)] mod tests;` and the tests go in `src/foo/bar/tests.rs` (`src/foo/mod.rs` → `src/foo/tests.rs`). Test fixtures, keys, passwords and vectors belong there or under a `testdata/` directory, so anyone can tell test code from production code by its file name. Only small `#[cfg(test)]` hooks that need private access (an accessor, a test clock) may stay next to the code they expose, and they must not hold fixtures or secret-looking values.
- Update the docs (`docs/`, `README.md`, `.env.example`, `ferrowarden.toml.example`, the agent skill under `.claude/skills/`) when behaviour or configuration changes.
- Add an entry under **[Unreleased]** in [CHANGELOG.md](CHANGELOG.md); call out anything that needs action when upgrading.
- New dependencies need a reason; prefer well-maintained crates and check them with `cargo audit`.
- Line endings are handled by `.gitattributes` (scripts that run in containers must stay LF).

## Branding

The [`branding/`](branding/README.md) kit is the source of truth for the Ferrowarden logo, colours, typography and voice (see [`branding/docs/VOICE_AND_MESSAGING.md`](branding/docs/VOICE_AND_MESSAGING.md) for the claims rules: no absolute security guarantees, no implied affiliation with Vaultwarden or Bitwarden). Use its assets as they are, regenerate exported files with the scripts in `branding/scripts/` (see [`branding/docs/MAINTAINING_ASSETS.md`](branding/docs/MAINTAINING_ASSETS.md)), and do not hand-edit exported PNG, SVG or favicon files.

## Licence and Contributor License Agreement

Ferrowarden is source-available under the [FSL-1.1-ALv2](LICENSE) licence (each release becomes Apache-2.0 two years after publication).

**Every contribution needs the [Contributor License Agreement](CLA.md).** It lets the maintainer distribute your contribution under the project licence and relicense or commercially license the project later; you keep the copyright in your work. To agree, add this line to the description of your first pull request:

> I have read the Ferrowarden CLA (CLA.md) and agree to its terms for this and all my future contributions to Ferrowarden.

Pull requests without it can't be merged. Contributions on behalf of a company need a separate agreement: open an issue first.
