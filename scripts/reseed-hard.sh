#!/usr/bin/env bash
# Tier-2 reseed (default for SCORED runs): wipe the DB by recreating the Postgres pod
# (emptyDir storage), let init_db() rebuild the pristine baseline, rotate the per-run
# identity, reinstall triggers, seed canaries, and zero Kong's rate-limit counters.
#
#   PROFILE=raw|hardened ./scripts/reseed-hard.sh
# Prints the per-run RUN_ID on stdout (logs on stderr). Exits NON-ZERO on any failure
# so the harness treats a partial reseed as UNSCORABLE (fail-closed).
set -uo pipefail

APP_NS="${APP_NS:-vuln-bank}"; DB_NS="${DB_NS:-vuln-bank-db}"; KONG_NS="${KONG_NS:-kong}"
PROFILE="${PROFILE:-raw}"
RUN_ID="${RUN_ID:-$(uuidgen 2>/dev/null | tr -dc 'a-f0-9' | cut -c1-12 || python3 -c 'import uuid;print(uuid.uuid4().hex[:12])')}"
log() { echo "[reseed-hard] $*" >&2; }
die() { echo "[reseed-hard] FATAL: $*" >&2; exit 1; }
# ON_ERROR_STOP=1 so a SQL error makes psql exit non-zero (else it masks failures).
psql_db() { kubectl -n "$DB_NS" exec -i deploy/postgres -- psql -v ON_ERROR_STOP=1 -U postgres -d vulnerable_bank "$@"; }

log "run_id=$RUN_ID profile=$PROFILE"

# 1) wipe the database (emptyDir is discarded when the pod is recreated)
log "recreating postgres pod (emptyDir DB wipe)"
kubectl -n "$DB_NS" delete pod -l app=postgres --wait=true >&2 || die "postgres pod delete failed"
kubectl -n "$DB_NS" rollout status deploy/postgres --timeout=150s >&2 || die "postgres not ready"
kubectl -n "$DB_NS" wait --for=condition=ready pod -l app=postgres --timeout=120s >&2 || die "postgres pod not ready"

# 2) rotate per-run identity + restart app/canary so they reconnect to the fresh DB.
#    RUN_ID is unique so the env always changes -> a fresh rollout is guaranteed.
#    lab_start.sh blocks on pg_isready; lab_entrypoint runs init_db() before /healthz serves.
kubectl -n "$APP_NS" set env deploy/vuln-bank   LAB_RUN_ID="$RUN_ID" >/dev/null || die "set env vuln-bank failed"
kubectl -n "$APP_NS" set env deploy/canary-http LAB_RUN_ID="$RUN_ID" CANARY_TOKEN="$RUN_ID" >/dev/null || die "set env canary failed"
kubectl -n "$APP_NS" rollout status deploy/vuln-bank   --timeout=180s >&2 || die "vuln-bank not ready"
kubectl -n "$APP_NS" rollout status deploy/canary-http --timeout=120s >&2 || die "canary-http not ready"

# 3) reinstall triggers (schema was rebuilt), truncate audit, seed this run's canaries
log "installing audit triggers + seeding canaries (token=$RUN_ID)"
psql_db -q < oracle/sql/oracle_audit.sql >/dev/null || die "trigger install failed"
psql_db -q -c 'TRUNCATE lab_oracle_audit RESTART IDENTITY;' >/dev/null || die "audit truncate failed"
psql_db -q -v token="$RUN_ID" < oracle/sql/seed_canaries.sql >/dev/null || die "canary seed failed"

# 4) hardened: recreate Kong so policy:local rate-limit counters are provably zero
if [ "$PROFILE" = "hardened" ]; then
  log "recreating kong pod (zero rate-limit counters)"
  kubectl -n "$KONG_NS" delete pod -l app=kong-gateway --wait=true >&2 || die "kong pod delete failed"
  kubectl -n "$KONG_NS" rollout status deploy/kong-gateway --timeout=180s >&2 || die "kong not ready"
  kubectl -n "$KONG_NS" wait --for=condition=ready pod -l app=kong-gateway --timeout=120s >&2 || die "kong pod not ready"
fi

log "done"
echo "$RUN_ID"
