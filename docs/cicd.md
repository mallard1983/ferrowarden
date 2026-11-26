# CI/CD Pipeline

> **Status:** the **GitHub Actions** workflow (`.github/workflows/test.yml`) runs on every push to [github.com/mallard1983/ferrowarden](https://github.com/mallard1983/ferrowarden/actions) — formatting, clippy, unit tests and the full Docker integration suite. The **GitLab CI** file is still an untested draft; known unknowns are called out inline.

---

## What the Pipeline Needs to Do

```
push → build → unit tests → integration tests → (optional) build Docker image
```

The unit tests (run with `cargo test --bins`) need only a Rust toolchain. CI also runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`. The unit job also lints `docs/openapi.yaml` with Redocly CLI (`npx --yes @redocly/cli@2.83.0 lint docs/openapi.yaml`, rules in `redocly.yaml`); run the same command locally after editing the spec.

The integration tests (`tests/integration.rs`) require the full Docker Compose stack — Vaultwarden, ferrowarden and mock-api — all healthy and communicating. This makes integration tests significantly harder to run in CI than unit tests, and the two are separated below so unit tests can pass without a Docker environment.

---

## Option A: GitLab CI

Place `.gitlab-ci.yml` at the repo root. A draft is provided at `.gitlab-ci.yml` in this repository.

### Runner Requirements

The unit test job requires only a standard GitLab runner with Docker executor.

The integration test job requires Docker-in-Docker (dind). The runner must have:
- Docker executor with privileged mode enabled, **or**
- A runner configured with the Docker socket mounted (`/var/run/docker.sock`)

For a self-hosted GitLab in a homelab, the easiest path is a runner registered with `--docker-privileged` and the dind service. See the [GitLab DinD docs](https://docs.gitlab.com/ee/ci/docker/using_docker_build.html).

### Secrets

The integration tests need an admin key and agent key at runtime. These are generated during stack setup (the pipeline runs `dev-setup.sh`), so they do not need to be pre-seeded as CI secrets. The admin key ends up in `secrets/ferrowarden_admin_key` after setup.

> **Unknown:** Whether GitLab's dind environment has network access between the CI container and the Docker Compose services on the same bridge network. If the `until curl` health checks in `dev-setup.sh` time out, the services may be on an isolated network. Setting `FERROWARDEN_URL` to the container's service name instead of `localhost` may be needed.

### Draft Pipeline

See [`.gitlab-ci.yml`](../.gitlab-ci.yml).

---

## Option B: GitHub Actions

`.github/workflows/test.yml` is in use and passing. Its actions are pinned to commit SHAs and the token is read-only (`permissions: contents: read`).

### Services vs Docker Compose

GitHub Actions supports `services:` for simple containers but not Docker Compose stacks. The integration test workflow uses `docker compose` directly (the runner has Docker available).

> **Unknown:** Whether `docker compose` is available on GitHub-hosted runners by default. As of mid-2024 it is available on `ubuntu-latest`, but this may change. If not available, `pip install docker-compose` or `apt-get install docker-compose-plugin` may be needed.

### Secrets

GitHub Actions secrets are set in the repository settings. The admin key does not need to be pre-configured — `dev-setup.sh` generates it. No secrets are required in the CI environment for the tests to run.

### Pipeline

See [`.github/workflows/test.yml`](../.github/workflows/test.yml).

---

## Release Workflow

`.github/workflows/release.yml` builds the release binaries. It is separate from the test workflow and never publishes anything.

- **Trigger.** A push of a tag `v*` (the tag must equal `v` plus the `Cargo.toml` version), or a manual run. A manual run is a dry run: it builds, packages and keeps the archives as workflow artifacts for 14 days, and cannot upload, because the upload jobs run only for a tag push.
- **Build.** `cargo build --release --locked` for `ferrowarden` and `ferrowarden-mcp` on GitHub-hosted runners: `x86_64-unknown-linux-gnu` (ubuntu-latest), `aarch64-unknown-linux-gnu` (ubuntu-24.04-arm), `aarch64-apple-darwin` (macos-latest) and `x86_64-pc-windows-msvc` (windows-latest). Each binary is started once with `--version` as a smoke test. No build cache is used.
- **Packages.** `ferrowarden-<version>-<target>.tar.gz` (`.zip` on Windows) with both binaries, `LICENSE` and `README.md`, plus one `SHA256SUMS`.
- **Upload.** On a tag push, the `release` job attaches the archives and `SHA256SUMS` to the GitHub release for the tag with `gh release upload`. If the release does not exist it is created as a **draft**; if it exists and is already published, the job fails. Publishing is a manual step after you have checked the draft and written the notes.
- **Provenance.** The `attest` job signs a build provenance attestation for each archive (`gh attestation verify <file> --repo mallard1983/ferrowarden`).
- **Permissions.** The workflow default is `contents: read`. Only `release` has `contents: write` (it checks out no code), and only `attest` has `id-token: write` and `attestations: write`. Every action is pinned to a commit SHA, with the version in a comment; Dependabot keeps them current.
- **Docker.** The Docker image holds `ferrowarden` only and is built with `--bin ferrowarden`. `ferrowarden-mcp` runs on the agent's side ([docs/mcp.md](mcp.md)).

To cut a release: update the version in `Cargo.toml` and the changelog, merge, tag `vX.Y.Z` on the merge commit, push the tag, wait for the workflow, check the draft release and publish it.

## The Test Stack in CI

The test stack runs one Ferrowarden against one Vaultwarden account (see [native-vault.md](native-vault.md)): `ferrowarden` with the native backend, on port 3000 (admin UI 3001, metrics 9095). The integration job runs, in this order:

1. the whole integration suite (`.env.test`). It includes the seed-data checks that replaced the old backend equivalence suite: the listing, and every offered placeholder, are compared with what `tests/seed/*.json` define ([native-vault.md](native-vault.md#how-formats-are-verified));
2. the MCP tests;
3. the secret gate, which scans the logs, the event file and a metrics scrape of the instance, and two checks of the container itself (below).

The Bitwarden CLI is no longer part of CI: nothing in the stack runs it, so there is no CLI version to pair with a Vaultwarden release. The images of the one-shot setup and seed containers (`docker/setup.Dockerfile`) are a Node runtime for scripts that use Node's built-in `crypto` and HTTP client.

### Vaultwarden versions in CI

The native backend implements the Bitwarden protocol itself, so the Vaultwarden release matters. The integration job runs twice, in parallel, each run with a stack of its own (`strategy.matrix.include` in `.github/workflows/test.yml`; the matrix sets `VAULTWARDEN_VERSION` and `TEST_KDF` for `docker-compose.test.yml` and `scripts/dev-setup.sh`):

| Check name | Vaultwarden | Test accounts' KDF |
|---|---|---|
| `Integration tests` | 1.37.5 (current) | PBKDF2-SHA256, 600 000 iterations |
| `Integration tests (Vaultwarden 1.36.0, Argon2id)` | 1.36.0 (previous minor) | Argon2id, 64 MiB, 3 iterations, parallelism 4 |

Both run every step: the integration suite, the MCP suite and the secret gate. `Integration tests` is the required status check on `main`; the job keeps that name (the matrix entry's `name`), and the second one has a name of its own. They fail independently (`fail-fast: false`).

Run the second configuration locally the same way CI does:

```sh
docker compose -f docker-compose.test.yml down -v     # a fresh stack: the account's KDF is chosen at registration
VAULTWARDEN_VERSION=1.36.0 TEST_KDF=argon2id ./scripts/dev-setup.sh
```

Account setup, the seeders and the API key script (`docker/bw-register.js`, `bw-apikey.js`, `bw-seed.js`, `bw-seed-hidden.js`) read the account's KDF from the server's prelogin and use Node's built-in `crypto` for PBKDF2 and Argon2id (`crypto.argon2Sync`, Node 24.7 or later; the image is `node:26-slim`), so the Argon2id account is exercised end to end: registration, API-key login, the native backend's unlock and the admin UI sign-in.

When a Vaultwarden release comes out, move the pair forward: the new release becomes the first row, the old one the second, and recapture the [web-vault fixture](native-vault.md#how-formats-are-verified) from the new release.

## Secret Gate

After the integration tests, the GitHub workflow runs `scripts/check-no-secrets.sh` while the stack is still up. It collects every secret the test stack knows about (passwords, notes, custom field values and TOTP seeds from `tests/seed/credentials.json`, the password, username and note of the hidden-password item in `tests/seed/hidden.json`, the agent and admin keys from `.env.test`, the vault master password, the metrics token, and any agent token the integration tests created through the UI, which they write to `target/integration-secrets.txt`), and every session token the mock API's login services issued during the run (the gate reads them from the mock's `/__issued__` endpoint, raw and URL-encoded, for [captured sessions](sessions.md)), then greps the `ferrowarden` container logs, the security event file and a scrape of Ferrowarden's Prometheus `/metrics` (fetched with the metrics token from the published port 9095) for each of them (fixed-string) and fails if any appears. The test stack enables the file sink at `/data/events/events.jsonl` inside the container (on the `ferrowarden-keys` volume, because the root filesystem is read-only); the script copies it out with `docker compose cp`, so no host directory is mounted and host UIDs do not matter. Secret values are never printed, only the name of the leaked item. It needs `python3` (preinstalled on `ubuntu-latest`). To see it fail, pass an extra file containing a seeded password: `bash scripts/check-no-secrets.sh some-file`.

The integration job runs against the hardened `docker-compose.test.yml` (read-only root filesystem, no capabilities, `no-new-privileges`, the `scratch` image), so the suites prove the stack works that way. Two further steps check the container itself. The first finds the container's PID on the host (`docker inspect -f '{{.State.Pid}}'`), reads `/proc/<pid>/environ` with `sudo`, and fails if it contains the admin key, the Vaultwarden API key or the master password (compared with `grep -qF -f`, never printed) or a `FERROWARDEN_ADMIN_KEY=` variable; it also checks that the file path variables are present, so it cannot pass by reading the wrong process. The second fails if `/bin/sh` exists in the image, if the binary does not start (it is static, so no loader or libc is needed), or if the image holds anything beyond the binary, `/etc/passwd`, `/etc/group` and `/data`. `test_container_is_healthy_and_hardened` in the integration suite checks that Docker reports the container `healthy` through `ferrowarden healthcheck`, that the hardening flags are set, and that the admin key value is not in the container's configuration; it skips when docker is not available to the test. Reading another process's environment needs the host's `/proc`, so the first step runs on the Linux runner only.

---

## Separating Unit and Integration Tests

The integration tests are gated behind the `FERROWARDEN_INTEGRATION` environment variable. Without it, `cargo test` skips them entirely and only runs unit tests.

```sh
# Unit tests only (no Docker required):
cargo test --bins   # binary crate: --lib would fail with "no library targets"

# Unit + all non-integration tests:
cargo test

# Full suite including integration tests:
FERROWARDEN_INTEGRATION=1 cargo test --test integration -- --test-threads=1
```

A pipeline that only wants fast feedback on every push can skip integration tests and run them only on merge requests or on a schedule.

---

## Caching

Cargo compiles all dependencies before the application. Without caching, every pipeline run recompiles everything from scratch (~3–5 minutes on a small runner). Cache the Cargo registry and target directory:

**GitLab:**
```yaml
cache:
  key: "$CI_COMMIT_REF_SLUG"
  paths:
    - .cargo/registry/
    - .cargo/git/
    - target/
```

**GitHub Actions:**
```yaml
- uses: actions/cache@v4
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
      target/
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
```

---

## Known Issues and Gotchas

**`--test-threads=1` is required for integration tests.**
The 11 integration tests share mock-api state and must run serially. Without this flag, two tests that modify the mock state will race.

**Ferrowarden needs a moment to log in and sync at startup.**
The dev-setup script waits for `GET /v1/admin/status` before it creates the test agent key. In CI the Docker network round-trip may be slower. If tests fail with "vault locked" or connection refused on the first few runs, increase the wait time in `scripts/dev-setup.sh`.

**Cargo build toolchain on Windows runners.**
If running on a Windows GitHub Actions runner, use the MSVC toolchain:
```yaml
- run: rustup default stable-x86_64-pc-windows-msvc
```
The GNU toolchain requires MinGW and will fail to build `ring`.

**Docker volume ownership.**
The first run creates named volumes. If a previous run left behind a root-owned volume (from a failed setup), the next run's `ferrowarden` container will fail to write to it. Add `docker compose down -v` at the start of the integration test job to ensure a clean state.
