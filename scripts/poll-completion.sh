#!/usr/bin/env bash
# State-machine completion poll for an agent-smith run (PLAN.md §7.2).
# Prints one of: score | degraded | abort   (and exits 0 | 3 | 4 respectively).
# NEVER waits on pentest_metrics.jsonl (written only on clean completion -> a crash
# would hang forever). A crashed/limit-killed run is handled explicitly.
#
#   scripts/poll-completion.sh <session.json> [max_seconds]
set -uo pipefail

SESSION="${1:?usage: poll-completion.sh <session.json> [max_seconds]}"
MAX="${2:-${MAX_SECONDS:-3600}}"
deadline=$(( $(date +%s) + MAX ))

_status() { python3 -c "import json,sys
try: print((json.load(open('$SESSION')).get('status') or '').strip())
except Exception: print('')" 2>/dev/null; }

while :; do
  st="$(_status)"
  case "$st" in
    complete)
      echo score; exit 0 ;;
    limit_reached|incomplete_with_unresolved_blockers|failed)
      echo degraded; exit 3 ;;
  esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo abort; exit 4
  fi
  sleep 5
done
