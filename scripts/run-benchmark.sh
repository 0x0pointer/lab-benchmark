#!/usr/bin/env bash
# One scored agent-smith run against one profile, with snapshot isolation (PLAN.md §7.1).
#
#   scripts/run-benchmark.sh [raw|hardened]
# Env:
#   AGENT_SMITH=../agent-smith     repo whose artifacts we snapshot/score
#   TARGET=http://...              base URL (default: derived via emit-target.sh)
#   AGENT_CMD="..."               headless agent-smith invocation; if unset, operator-driven
#   MODE=portforward|nodeip        how emit-target resolves the URL
#   MAX_SECONDS=3600               completion wall-clock cap
#   NO_RESEED=1                    skip 'make reseed-hard' (Phase 3 not deployed / manual)
#
# Output: runs/<profile>/<run_id>_<ts>/ with findings/coverage/session snapshot,
# events.jsonl, and scorecard.json. The user's agent-smith repo is restored on exit.
set -uo pipefail

PROFILE="${1:-raw}"
AS="${AGENT_SMITH:-../agent-smith}"
ARTIFACTS="findings coverage_matrix qa_state quick_log session steering_queue"
RUN_ID="$(uuidgen 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())')"
TS="$(date +%s)"
RUNDIR="runs/${PROFILE}/${RUN_ID}_${TS}"
STASH="$(mktemp -d /tmp/as_stash_XXXX)"
mkdir -p "$RUNDIR"

restore() {  # put the user's original artifacts back; our snapshot lives in RUNDIR
  for a in $ARTIFACTS; do [ -f "$STASH/$a.json" ] && mv -f "$STASH/$a.json" "$AS/$a.json"; done
}
trap restore EXIT

echo "[bench] profile=$PROFILE run_id=$RUN_ID -> $RUNDIR"

# 1) snapshot-isolate: stash live artifacts, start agent-smith from clean skeletons
for a in $ARTIFACTS; do [ -f "$AS/$a.json" ] && mv "$AS/$a.json" "$STASH/"; done
printf '{"meta":{},"findings":[],"diagrams":[]}' > "$AS/findings.json"
for a in coverage_matrix qa_state quick_log session steering_queue; do echo '{}' > "$AS/$a.json"; done

# 2) reseed (deterministic) + capture rotated run id + fail-closed preflight.
# Capture reseed exit status via command-substitution (NOT a lossy pipe to tail), so a
# partial/failed reseed aborts the run instead of scoring a dirty lab.
TARGET="${TARGET:-$(MODE="${MODE:-portforward}" ./scripts/emit-target.sh "$PROFILE")}"
LAB_RUN=""
if [ -z "${NO_RESEED:-}" ]; then
  if ! LAB_RUN="$(PROFILE="$PROFILE" ./scripts/reseed-hard.sh)"; then
    echo "[bench] RESEED FAILED -> UNSCORABLE (not scoring)"; exit 2
  fi
  LAB_RUN="$(printf '%s\n' "$LAB_RUN" | tail -1)"
  echo "[bench] reseeded; lab run_id=$LAB_RUN"
fi
if ! ./scripts/seed-check.sh "$TARGET" "$LAB_RUN" "$PROFILE"; then
  echo "[bench] SEED-CHECK FAILED -> UNSCORABLE (not scoring)"; exit 1
fi

# 3) run agent-smith
if [ -n "${AGENT_CMD:-}" ]; then
  echo "[bench] AGENT_CMD against $TARGET"
  AS_TARGET="$TARGET" bash -lc "$AGENT_CMD" || echo "[bench] agent command exited nonzero (continuing to poll)"
else
  echo "[bench] >>> run agent-smith now against: $TARGET"
fi

# 4) completion state machine
verdict="$(./scripts/poll-completion.sh "$AS/session.json" "${MAX_SECONDS:-3600}")"; rc=$?
echo "[bench] completion: $verdict"
if [ "$verdict" = "abort" ]; then echo "[bench] ABORTED -> not scoring"; exit 4; fi

# 5) immutable snapshot + proof events (stamp DB rows with this run id)
for a in $ARTIFACTS; do [ -f "$AS/$a.json" ] && cp "$AS/$a.json" "$RUNDIR/"; done
RUN_ID="$LAB_RUN" ./scripts/collect-events.sh "$RUNDIR/events.jsonl" || true

# 6) score the snapshot (never the live repo); scope events to this run's id
python3 -m oracle.scorer.cli score \
  --findings "$RUNDIR/findings.json" --events "$RUNDIR/events.jsonl" \
  ${LAB_RUN:+--run-id "$LAB_RUN"} \
  --profile "$PROFILE" --json "$RUNDIR/scorecard.json" || true

[ "$verdict" = "degraded" ] && echo "[bench] NOTE: run was degraded (limit/incomplete) — exclude from the gate, trend only"
echo "[bench] done: $RUNDIR/scorecard.json"
echo "$RUNDIR"
