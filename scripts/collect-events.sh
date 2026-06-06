#!/usr/bin/env bash
# Collect server-side PROOF events for a scored run into one JSONL stream:
#   * observer middleware  (app pod stdout: LAB_EVENT ...)
#   * canary-http          (canary pod stdout: LAB_EVENT CANARY_HIT ...)
#   * DB triggers          (lab_oracle_audit rows -> DB_* events)
#   * Kong file-log        (kong-gateway stdout -> KONG_BLOCKED via logparse)
#   * Postgres statements  (postgres stdout    -> DB_SQLI_EXEC via logparse)
# Feed the result to the scorer:  python3 -m oracle.scorer.cli score --events <out>
#
#   scripts/collect-events.sh [out.jsonl]
# This is the MVP "ingester" (kubectl logs + psql). The scale version ships events to
# oracle-postgres in-cluster; the JSONL snapshot is what makes per-run scoring deterministic.
set -euo pipefail

OUT="${1:-${OUT:-events.jsonl}}"
APP_NS="${APP_NS:-vuln-bank}"
DB_NS="${DB_NS:-vuln-bank-db}"
KONG_NS="${KONG_NS:-kong}"
RUN_ID="${RUN_ID:-}"      # stamp DB-trigger rows with this run id (they carry none natively)

# repo root (so `python3 -m oracle.scorer.logparse` resolves regardless of cwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PY="${PYTHON:-python3}"

: > "$OUT"

collect_log() {  # ns deploy
  kubectl -n "$1" logs "deploy/$2" --tail=-1 2>/dev/null | sed -n 's/^LAB_EVENT //p' >> "$OUT" || true
}

# Pull a deploy's raw stdout through logparse (--kong/--pg) -> proof events, run_id-stamped.
# Skips gracefully if the namespace/deploy is absent (e.g. raw profile has no Kong).
logparse_deploy() {  # ns deploy mode(--kong|--pg)
  local ns="$1" deploy="$2" mode="$3"
  kubectl get ns "$ns" >/dev/null 2>&1 || return 0
  kubectl -n "$ns" logs "deploy/$deploy" --tail=-1 2>/dev/null \
    | ( cd "$REPO_ROOT" && "$PY" -m oracle.scorer.logparse "$mode" ${RUN_ID:+--run-id "$RUN_ID"} ) \
    >> "$OUT" 2>/dev/null || true
}

collect_log "$APP_NS"  vuln-bank
collect_log "$APP_NS"  canary-http

# Gateway + DB logs -> KONG_BLOCKED / DB_SQLI_EXEC proof events (signals.py consumes them).
logparse_deploy "$KONG_NS" kong-gateway --kong
logparse_deploy "$DB_NS"   postgres     --pg

# DB-trigger audit rows -> DB_* events (one JSON object per line). The audit table has
# no native run_id, so STAMP the active run id here (truncated fresh each reseed anyway).
kubectl -n "$DB_NS" exec -i deploy/postgres -- \
  psql -v ON_ERROR_STOP=1 -v rid="${RUN_ID:-dev}" -U postgres -d vulnerable_bank -tA -c \
  "SELECT jsonb_build_object('type', event_type, 'run_id', :'rid') || coalesce(detail,'{}'::jsonb)
     FROM lab_oracle_audit ORDER BY id;" 2>/dev/null | sed -n 's/^{.*}$/&/p' >> "$OUT" || true

echo "collected $(grep -c '^{' "$OUT" 2>/dev/null || echo 0) proof events -> $OUT" >&2
