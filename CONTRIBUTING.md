# Contributing to Ferrowarden

Thanks for your interest in improving Ferrowarden! Bug reports, documentation fixes, tests and code are all welcome.

Ferrowarden is a security tool: its whole job is to keep credential values away from AI agents. That shapes how changes are reviewed, so please read the [Security Model](docs/security.md) before working on anything in the request path.

## Reporting security issues

**Do not open a public issue for a vulnerability.** Follow the [Security Policy](SECURITY.md) and report it privately through GitHub's **Report a vulnerability** button.

## Reporting bugs and suggesting features

Open an issue with:

- what you expected and what happened instead,
- how to reproduce it (configuration, the `/v1/forward` payload, logs — **with any credential values, admin keys and agent tokens removed**),
- your platform (Linux / Windows / macOS, Docker version) and the Ferrowarden version or commit.

For larger changes, open an issue to discuss the approach before writing code.

## Development setup

Prerequisites: Rust (stable), Docker with Compose v2, `openssl` (ships with Git for Windows) and Python 3. On Windows use the MSVC Rust toolchain (`rustup default stable-x86_64-pc-windows-msvc`).

```sh
git clone https://github.com/mallard1983/ferrowarden.git
cd ferrowarden

# Build a throwaway test stack (Vaultwarden, bw serve, Ferrowarden, mock API)
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
```

## Guidelines for changes

**Security-sensitive changes** — anything touching substitution, scrubbing, the target policy, credential host binding, authentication, key storage, logging or error messages — must:

- keep every guarantee in [docs/security.md](docs/security.md), or update that document and explain why;
- come with tests that would fail if a credential value could reach the agent (see the leak-prevention tests at the end of `tests/integration.rs` and the mock API's `/echo` endpoints);
- never put credential values, admin keys or agent tokens into logs, audit entries, error messages or test output.

**Generally:**

- Keep pull requests focused: one change per PR, with a description of what and why.
- Add or update tests for behaviour changes. Unit tests live next to the code; end-to-end behaviour goes in `tests/integration.rs`.
- Update the docs (`docs/`, `README.md`, `.env.example`, `ferrowarden.toml.example`, the agent skill under `.claude/skills/`) when behaviour or configuration changes.
- Add an entry under **[Unreleased]** in [CHANGELOG.md](CHANGELOG.md); call out anything that needs action when upgrading.
- New dependencies need a reason; prefer well-maintained crates and check them with `cargo audit`.
- Line endings are handled by `.gitattributes` (scripts that run in containers must stay LF).

## Licence

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE).
