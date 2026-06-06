#!/usr/bin/env bash
# Tier-1 refresh (fast, interactive dev): wipe state via DROP SCHEMA instead of a pod
# recreate, then let init_db() rebuild. Same end-state seed-check signature as
# reseed-hard, lower latency. For SCORED runs prefer reseed-hard (guaranteed-clean).
#
#   PROFILE=raw|hardened ./scripts/refresh.sh   (prints RUN_ID on stdout; exits nonzero on failure)
set -uo pipefail

APP_NS="${APP_NS:-vuln-bank}"; DB_NS="${DB_NS:-vuln-bank-db}"; KONG_NS="${KONG_NS:-kong}"
PROFILE="${PROFILE:-raw}"
RUN_ID="${RUN_ID:-$(uuidgen 2>/dev/null | tr -dc 'a-f0-9' | cut -c1-12 || python3 -c 'import uuid;print(uuid.uuid4().hex[:12])')}"
log() { echo "[refresh] $*" >&2; }
die() { echo "[refresh] FATAL: $*" >&2; exit 1; }
psql_db() { kubectl -n "$DB_NS" exec -i deploy/postgres -- psql -v ON_ERROR_STOP=1 -U postgres -d vulnerable_bank "$@"; }

log "run_id=$RUN_ID profile=$PROFILE"

# 1) quiesce the app FIRST so no pooled connection survives the wipe, then DROP SCHEMA
log "scaling vuln-bank to 0 before schema wipe"
kubectl -n "$APP_NS" scale deploy/vuln-bank --replicas=0 >/dev/null || die "scale down failed"
kubectl -n "$APP_NS" rollout status deploy/vuln-bank --timeout=60s >&2 || die "scale down not complete"

log "DROP SCHEMA public CASCADE"
psql_db -q -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO postgres; GRANT ALL ON SCHEMA public TO public;" >/dev/null || die "schema wipe failed"

# 2) rotate identity + bring the app back (set env + scale up -> single rollout, init_db rebuilds)
kubectl -n "$APP_NS" set env deploy/vuln-bank   LAB_RUN_ID="$RUN_ID" >/dev/null || die "set env vuln-bank failed"
kubectl -n "$APP_NS" set env deploy/canary-http LAB_RUN_ID="$RUN_ID" CANARY_TOKEN="$RUN_ID" >/dev/null || die "set env canary failed"
kubectl -n "$APP_NS" scale deploy/vuln-bank --replicas=1 >/dev/null || die "scale up failed"
kubectl -n "$APP_NS" rollout status deploy/vuln-bank   --timeout=180s >&2 || die "vuln-bank not ready"
kubectl -n "$APP_NS" rollout status deploy/canary-http --timeout=120s >&2 || die "canary-http not ready"

# 3) reinstall triggers + truncate audit + seed canaries
log "installing audit triggers + seeding canaries"
psql_db -q < oracle/sql/oracle_audit.sql >/dev/null || die "trigger install failed"
psql_db -q -c 'TRUNCATE lab_oracle_audit RESTART IDENTITY;' >/dev/null || die "audit truncate failed"
psql_db -q -v token="$RUN_ID" < oracle/sql/seed_canaries.sql >/dev/null || die "canary seed failed"

# 4) hardened: zero Kong rate-limit counters
if [ "$PROFILE" = "hardened" ]; then
  log "recreating kong pod (zero rate-limit counters)"
  kubectl -n "$KONG_NS" delete pod -l app=kong-gateway --wait=true >&2 || die "kong pod delete failed"
  kubectl -n "$KONG_NS" rollout status deploy/kong-gateway --timeout=180s >&2 || die "kong not ready"
fi

log "done"
echo "$RUN_ID"
