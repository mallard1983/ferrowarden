# CI/CD Pipeline

> **Status:** the **GitHub Actions** workflow (`.github/workflows/test.yml`) runs on every push to [github.com/mallard1983/ferrowarden](https://github.com/mallard1983/ferrowarden/actions) — formatting, clippy, unit tests and the full Docker integration suite. The **GitLab CI** file is still an untested draft; known unknowns are called out inline.

---

## What the Pipeline Needs to Do

```
push → build → unit tests → integration tests → (optional) build Docker image
```

The unit tests (run with `cargo test --bins`) need only a Rust toolchain. CI also runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`.

The integration tests (`tests/integration.rs`) require the full Docker Compose stack — Vaultwarden, bw-serve, ferrowarden, and mock-api — all healthy and communicating. This makes integration tests significantly harder to run in CI than unit tests, and the two are separated below so unit tests can pass without a Docker environment.

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

## Secret Gate

After the integration tests, the GitHub workflow runs `scripts/check-no-secrets.sh` while the stack is still up. It collects every secret the test stack knows about (passwords, notes, custom field values and TOTP seeds from `tests/seed/credentials.json`, the agent and admin keys from `.env.test`, the vault master password, and any agent token the integration tests created through the UI, which they write to `target/integration-secrets.txt`), then greps the `ferrowarden` container logs and the security event file for each of them (fixed-string) and fails if any appears. The test stack enables the file sink at `/tmp/ferrowarden-events/events.jsonl` inside the container; the script copies it out with `docker compose cp`, so no host directory is mounted and host UIDs do not matter. Secret values are never printed, only the name of the leaked item. It needs `python3` (preinstalled on `ubuntu-latest`). To see it fail, pass an extra file containing a seeded password: `bash scripts/check-no-secrets.sh some-file`.

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

**bw-serve takes ~15 seconds to initialize.**
The dev-setup script has a sleep and health-check loop. In CI the Docker network round-trip may be slower. If tests fail with "vault locked" or connection refused on the first few runs, increase the wait time in `scripts/dev-setup.sh`.

**bw-cli version is pinned (currently 2026.11.0).**
It requires HTTPS to Vaultwarden (provided by the `internal-certs` service) and checks the `Host` header on `bw serve`. Bump it deliberately and re-run the integration tests: the `bw serve` API is part of ferrowarden's contract.

**Cargo build toolchain on Windows runners.**
If running on a Windows GitHub Actions runner, use the MSVC toolchain:
```yaml
- run: rustup default stable-x86_64-pc-windows-msvc
```
The GNU toolchain requires MinGW and will fail to build `ring`.

**Docker volume ownership.**
The first run creates named volumes. If a previous run left behind a root-owned volume (from a failed setup), the next run's `bw-serve` or `ferrowarden` container will fail to write to it. Add `docker compose down -v` at the start of the integration test job to ensure a clean state.
