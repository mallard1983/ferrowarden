#!/usr/bin/env bash
# scripts/check-no-secrets.sh
#
# Secret gate for the test stack: proves that no secret value reached
# Ferrowarden's log output or its security event file.
#
# It collects every secret the test stack knows about:
#   - passwords, notes, custom field values and TOTP seeds from
#     tests/seed/credentials.json, and the password, username and note of the
#     item whose collection hides passwords (tests/seed/hidden.json)
#   - the test agent key, admin key and notifier webhook token from .env.test
#   - the vault master password from secrets/bw_master_password (if present)
#   - the Vaultwarden API key (secrets/bw_client_id, secrets/bw_client_secret):
#     Ferrowarden holds it, so it must never reach a log or an event
#   - the metrics bearer token (secrets/metrics_token)
#   - agent tokens the integration tests created during the run, from
#     target/integration-secrets.txt (or $FERROWARDEN_GATE_EXTRA_SECRETS_FILE)
#   - every session token the mock API's login services issued during the run
#     (captured sessions, docs/sessions.md): Ferrowarden must have kept them
#     from the agent, so they must not be in its logs, events or metrics either.
#     Read from the mock's GET /__issued__, with the URL-encoded form of each.
# then greps (fixed-string) for each of them in
#   - `docker compose -f docker-compose.test.yml logs <service>`
#   - the event file(s) copied out of the container with `docker compose cp`
#     (docker-compose.test.yml enables the file sink at
#     /data/events/events.jsonl)
#   - a scrape of the Prometheus `/metrics` endpoint (docs/metrics.md),
#     fetched with the metrics token from the host port the compose file
#     publishes (9095)
#   - any extra files given as arguments
# and exits non-zero if any value appears. Secret values are never printed:
# a hit is reported by its label (e.g. "test_api_token: value") only.
#
# Run it after the integration tests, while the stack is still up:
#   cargo test --test integration -- --test-threads=1
#   scripts/check-no-secrets.sh
#
# Usage: scripts/check-no-secrets.sh [extra-file ...]
#   FERROWARDEN_GATE_SKIP_DOCKER=1  scan only the extra files (self-test)
#   FERROWARDEN_GATE_SERVICES="a b" the compose services to scan (default:
#                                   "ferrowarden")
#   FERROWARDEN_GATE_METRICS_HOST   host the metrics port is published on
#                                   (default: localhost)
#   FERROWARDEN_GATE_MOCK_URL       where the mock API is published, for the
#                                   issued session tokens (default:
#                                   http://localhost:7777)

set -euo pipefail
# Git Bash on Windows would otherwise rewrite the container path below.
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/.."

COMPOSE_FILE="docker-compose.test.yml"
SEED_FILE="tests/seed/credentials.json"
HIDDEN_FILE="tests/seed/hidden.json"
ENV_FILE=".env.test"
MASTER_PW_FILE="secrets/bw_master_password"
SERVICES="${FERROWARDEN_GATE_SERVICES:-ferrowarden}"
CONTAINER_EVENTS_DIR="/data/events"
METRICS_TOKEN_FILE="secrets/metrics_token"
METRICS_HOST="${FERROWARDEN_GATE_METRICS_HOST:-localhost}"
MOCK_URL="${FERROWARDEN_GATE_MOCK_URL:-http://localhost:7777}"

# The published metrics port of a compose service (empty: not scraped).
metrics_port_for() {
    case "$1" in
        ferrowarden) echo 9095 ;;
        *) echo "" ;;
    esac
}

work="$(mktemp -d)"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

fail() { echo "check-no-secrets: $*" >&2; exit 2; }

# docker.exe on Windows does not understand Git Bash paths such as /tmp/x.
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

[ -f "$SEED_FILE" ] || fail "$SEED_FILE not found"
[ -f "$HIDDEN_FILE" ] || fail "$HIDDEN_FILE not found"
[ -f "$ENV_FILE" ] || fail "$ENV_FILE not found (run scripts/dev-setup.sh first)"

PYTHON="$(command -v python3 || command -v python || true)"
[ -n "$PYTHON" ] || fail "python3 is required to read the seed file"

# ── 1. Collect secrets: one "label<TAB>value" per line ───────────────────────
secrets="$work/secrets.tsv"
"$PYTHON" -I - "$SEED_FILE" "$HIDDEN_FILE" <<'PY' | tr -d '\r' > "$secrets"
import json, sys

sys.stdout.reconfigure(newline="\n", encoding="utf-8")  # no CRLF on Windows: it would break the match

MIN_LEN = 6  # shorter fragments would match ordinary text

def emit(label, value):
    if not isinstance(value, str):
        return
    # Multi-line values (notes): each line is searched on its own, so a
    # log line that carries only part of a value is still caught.
    candidates = {value} | set(value.splitlines())
    for c in sorted(candidates):
        c = c.strip()
        if len(c) >= MIN_LEN and "\t" not in c:
            print(f"{label}\t{c}")

with open(sys.argv[1], encoding="utf-8") as f:
    items = json.load(f)
with open(sys.argv[2], encoding="utf-8") as f:
    hidden = json.load(f)  # the item whose collection hides passwords
items.append(hidden)
for item in items:
    name = item.get("name", "?")
    emit(f"{name}: value", item.get("value"))
    emit(f"{name}: note", item.get("note"))
    emit(f"{name}: totp", item.get("totp"))
    for field in item.get("fields") or []:
        # Metadata (the item's allowed hosts), not a secret: a URL that
        # legitimately appears in events.
        if field.get("name") == "ferrowarden_uris":
            continue
        emit(f"{name}: field {field.get('name', '?')}", field.get("value"))
# Its username is kept out of logs and events like a secret (the other
# items' usernames are deliberately not treated as secret).
emit(f"{hidden.get('name', '?')}: username", hidden.get("username"))
PY

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }
for var in FERROWARDEN_TEST_AGENT_KEY FERROWARDEN_TEST_ADMIN_KEY FERROWARDEN_TEST_NOTIFY_TOKEN; do
    v="$(env_value "$var")"
    [ -n "$v" ] || fail "$var is not set in $ENV_FILE"
    printf '%s\t%s\n' "$var" "$v" >> "$secrets"
done
if [ -f "$MASTER_PW_FILE" ]; then
    v="$(tr -d '\r\n' < "$MASTER_PW_FILE")"
    [ -z "$v" ] || printf 'bw_master_password\t%s\n' "$v" >> "$secrets"
fi
# The Vaultwarden API key Ferrowarden holds, and the metrics token.
for f in bw_client_id bw_client_secret metrics_token; do
    if [ -f "secrets/$f" ]; then
        v="$(tr -d '\r\n' < "secrets/$f")"
        [ -z "$v" ] || printf '%s\t%s\n' "$f" "$v" >> "$secrets"
    fi
done

# Secrets generated during the run (agent tokens created through the UI by the
# integration tests): one value per line, in a file the tests write. Set
# FERROWARDEN_GATE_EXTRA_SECRETS_FILE to read another file.
EXTRA_SECRETS_FILE="${FERROWARDEN_GATE_EXTRA_SECRETS_FILE:-target/integration-secrets.txt}"
if [ -f "$EXTRA_SECRETS_FILE" ]; then
    n=0
    while IFS= read -r v || [ -n "$v" ]; do
        v="$(printf '%s' "$v" | tr -d '\r')"
        [ "${#v}" -ge 6 ] || continue
        n=$((n + 1))
        printf 'run_secret_%s\t%s\n' "$n" "$v" >> "$secrets"
    done < "$EXTRA_SECRETS_FILE"
    echo "Including $n run-generated secret(s) from $EXTRA_SECRETS_FILE."
fi

# Session tokens issued by the mock API's login services. The mock lists them
# at /__issued__ (JSON, kind -> [tokens]); each goes in raw and URL-encoded, the
# two forms that can reach a log or an event unchanged. Never printed.
if [ "${FERROWARDEN_GATE_SKIP_DOCKER:-}" != "1" ]; then
    curl -sf --max-time 20 "$MOCK_URL/__issued__" > "$work/issued.json" \
        || fail "could not read the issued session tokens from $MOCK_URL/__issued__ (is the test stack up and the mock API image rebuilt?)"
    "$PYTHON" -I - "$(native_path "$work/issued.json")" <<'PY' | tr -d '\r' >> "$secrets"
import json, sys, urllib.parse

sys.stdout.reconfigure(newline="\n", encoding="utf-8")  # no CRLF on Windows

with open(sys.argv[1], encoding="utf-8") as f:
    issued = json.load(f)
n = 0
for kind, tokens in sorted(issued.items()):
    for token in tokens:
        forms = {token, urllib.parse.quote(token, safe="")}
        for form in sorted(forms):
            if len(form) >= 6 and "\t" not in form and "\n" not in form:
                n += 1
                print(f"issued_{kind}_{n}\t{form}")
PY
    issued_n="$(grep -c '^issued_' "$secrets" || true)"
    [ "$issued_n" -ge 1 ] || fail "the mock API has issued no session tokens; run the integration tests first (nothing meaningful to check)"
    echo "Including $issued_n issued session token form(s) from the mock API."
fi

count="$(wc -l < "$secrets" | tr -d ' ')"
[ "$count" -ge 20 ] || fail "only $count secrets collected; the seed file looks wrong"
echo "Checking for $count secret values (never printed)."

# Self-test: the search must find a secret that is really there, otherwise a
# parsing or line-ending problem would make the gate pass vacuously.
IFS=$'\t' read -r _ canary < "$secrets"
printf 'prefix %s suffix\n' "$canary" > "$work/canary.txt"
grep -qF -e "$canary" -- "$work/canary.txt" || fail "self-test failed: a known secret was not detected"

# ── 2. Collect the output to scan ────────────────────────────────────────────
scan_files=()
if [ "${FERROWARDEN_GATE_SKIP_DOCKER:-}" != "1" ]; then
    for service in $SERVICES; do
        docker compose -f "$COMPOSE_FILE" logs --no-color "$service" > "$work/$service.log" 2>&1 \
            || fail "could not read the $service container logs (is the test stack up?)"
        # The gate must not pass vacuously: the log has to contain events.
        grep -qF 'ferrowarden.security' "$work/$service.log" \
            || fail "$service log contains no security events; nothing meaningful to scan"
        scan_files+=("$work/$service.log")

        mkdir "$work/events-$service"
        docker compose -f "$COMPOSE_FILE" cp "$service:$CONTAINER_EVENTS_DIR/." "$(native_path "$work/events-$service")" >/dev/null 2>&1 \
            || fail "could not copy $CONTAINER_EVENTS_DIR out of the $service container (file sink not enabled?)"
        [ -s "$work/events-$service/events.jsonl" ] \
            || fail "$service: events.jsonl is missing or empty; nothing meaningful to scan"
        grep -qF 'ferrowarden.security' "$work/events-$service/events.jsonl" \
            || fail "$service: events.jsonl contains no security events"
        for f in "$work/events-$service"/*; do scan_files+=("$f"); done

        # A scrape of the Prometheus endpoint. The token goes to curl in a
        # header file (never on the command line, where `ps` would show it).
        port="$(metrics_port_for "$service")"
        if [ -n "$port" ]; then
            [ -s "$METRICS_TOKEN_FILE" ] || fail "$METRICS_TOKEN_FILE not found (run scripts/dev-setup.sh first)"
            ( umask 077; printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' < "$METRICS_TOKEN_FILE")" > "$work/metrics-header" )
            curl -sf --max-time 20 -H "@$(native_path "$work/metrics-header")" \
                "http://$METRICS_HOST:$port/metrics" > "$work/metrics-$service.txt" \
                || fail "could not scrape the $service metrics endpoint on port $port (is the test stack up?)"
            # The gate must not pass vacuously: this must be a real scrape.
            grep -qF 'ferrowarden_build_info' "$work/metrics-$service.txt" \
                || fail "the $service scrape contains no ferrowarden metrics; nothing meaningful to scan"
            grep -qF 'ferrowarden_forward_requests_total{' "$work/metrics-$service.txt" \
                || fail "the $service scrape has no forward requests; run the integration tests first"
            scan_files+=("$work/metrics-$service.txt")
        fi
    done
fi
for f in "$@"; do
    [ -f "$f" ] || fail "extra file not found: $f"
    scan_files+=("$f")
done
[ "${#scan_files[@]}" -gt 0 ] || fail "nothing to scan"

# ── 3. Search ────────────────────────────────────────────────────────────────
hits=0
for file in "${scan_files[@]}"; do
    shown="${file#"$work"/}"
    while IFS=$'\t' read -r label value; do
        [ -n "$value" ] || continue
        if grep -qF -e "$value" -- "$file"; then
            echo "LEAK: secret '$label' appears in $shown" >&2
            hits=$((hits + 1))
        fi
    done < "$secrets"
    echo "scanned $shown ($(wc -l < "$file" | tr -d ' ') lines)"
done

if [ "$hits" -gt 0 ]; then
    echo "check-no-secrets: FAILED, $hits secret occurrence(s) found." >&2
    exit 1
fi
echo "check-no-secrets: OK, no secret value found in any scanned output."
