#!/usr/bin/env bash
# Fail-closed preflight: refuse to score unless the lab is in a known-armed baseline
# state. A misconfigured lab silently produces fake "misses" (PLAN.md risk #2).
#
#   scripts/seed-check.sh <base_url> [run_id] [profile]
# Checks (ALL fatal): app healthy · baseline admin seeded · this-run canary armed ·
#   audit triggers installed · headline SQLi armed · (hardened) Kong rate-limit cold.
set -uo pipefail

BASE="${1:?usage: seed-check.sh <base_url> [run_id] [profile]}"
TOKEN="${2:-${RUN_ID:-}}"
PROFILE="${3:-${PROFILE:-raw}}"
DB_NS="${DB_NS:-vuln-bank-db}"
INSECURE=""; case "$BASE" in https://*) INSECURE="-k" ;; esac
start=$(date +%s)
fail() { echo "SEED-CHECK FAIL: $*" >&2; exit 1; }

echo "[seed-check] target=${BASE} token=${TOKEN:-<any>} profile=${PROFILE}"

# 1) app reachable + healthy
curl -fsS $INSECURE --max-time 10 "${BASE}/healthz" >/dev/null || fail "healthz != 200 (app not up)"
echo "  [ok] /healthz"

# 2/3) baseline admin + this-run canary armed — parse JSON (no substring false-positives)
USERS="$(curl -fsS $INSECURE --max-time 10 "${BASE}/debug/users" || true)"
[ -n "$USERS" ] || fail "/debug/users returned nothing (init_db did not run?)"
USERS="$USERS" TOKEN="$TOKEN" python3 - <<'PY' || fail "baseline/canary not armed (see message above)"
import json, os, sys
raw, token = os.environ["USERS"], os.environ.get("TOKEN", "")
try:
    d = json.loads(raw)
except Exception:
    print("  /debug/users not valid JSON", file=sys.stderr); sys.exit(1)
users = d.get("users", d) if isinstance(d, dict) else d
names = {u.get("username") for u in users if isinstance(u, dict)}
if "admin" not in names:
    print("  seeded admin user absent", file=sys.stderr); sys.exit(1)
want = f"canary_{token}" if token else None
if want:
    if want not in names:
        print(f"  canary '{want}' not armed for this run", file=sys.stderr); sys.exit(1)
elif not any(n and n.startswith("canary_") for n in names):
    print("  no canary user armed", file=sys.stderr); sys.exit(1)
print("  [ok] baseline admin + canary armed")
PY

# 4) audit triggers installed (else all DB-trigger business-logic proofs silently never fire)
if command -v kubectl >/dev/null 2>&1; then
  TRG="$(kubectl -n "$DB_NS" exec -i deploy/postgres -- psql -tA -U postgres -d vulnerable_bank \
        -c "SELECT count(*) FROM pg_trigger WHERE tgname IN ('lab_trg_transfer','lab_trg_loan');" 2>/dev/null | tr -d '[:space:]' || echo 0)"
  [ "$TRG" = "2" ] || fail "oracle audit triggers not installed (found ${TRG}/2 — reseed did not apply oracle_audit.sql)"
  echo "  [ok] audit triggers installed (2/2)"
fi

# 5) headline SQLi auth-bypass armed on /login (FATAL — this is a guaranteed check)
ARMED="$(BASE="$BASE" INSECURE="$INSECURE" python3 - <<'PY'
import json, os, ssl, urllib.request
base, insecure = os.environ["BASE"], os.environ.get("INSECURE", "")
ctx = ssl._create_unverified_context() if insecure else None
payload = json.dumps({"username": "admin' OR '1'='1' -- -", "password": "x"}).encode()
req = urllib.request.Request(base + "/login", data=payload, headers={"Content-Type": "application/json"})
try:
    body = urllib.request.urlopen(req, timeout=10, context=ctx).read().decode("utf-8", "replace").lower()
    print("yes" if ("token" in body or "jwt" in body) else "no")
except Exception as e:
    print("err:" + str(e)[:80])
PY
)"
case "$ARMED" in
  yes)   echo "  [ok] SQLi auth-bypass armed on /login" ;;
  no)    fail "SQLi auth-bypass NOT armed on /login (app image/seed broken)" ;;
  err:*) fail "/login SQLi probe could not run ($ARMED)" ;;
  *)     fail "/login SQLi probe inconclusive ($ARMED)" ;;
esac

# 6) hardened only: Kong rate-limit counter must be cold (proves the kong-pod recreate worked)
if [ "$PROFILE" = "hardened" ]; then
  code="$(curl -s $INSECURE -o /dev/null -w '%{http_code}' --max-time 10 "${BASE}/login" -X POST -d 'username=x&password=y' || echo 000)"
  [ "$code" = "429" ] && fail "Kong rate-limit already 429 on first request (counter not reset — recreate the kong pod)"
  echo "  [ok] Kong rate-limit counter is cold (first request != 429)"
fi

echo "SEED-CHECK OK for ${BASE}  (${TOKEN:+token=$TOKEN, }$(( $(date +%s) - start ))s)"
