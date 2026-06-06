#!/usr/bin/env bash
# Delete the lab cluster + firewall so DigitalOcean STOPS billing. Safe to run anytime;
# your code and results stay on your laptop. The container image stays in the registry
# (cheap), so the next `make wake` is quick. Uses doctl (works regardless of token scope).
set -uo pipefail
CLUSTER="${CLUSTER:-vulnbank-lab}"
FW_NAME="${FW_NAME:-vulnbank-lab-lock}"

echo "[kill] deleting cluster '$CLUSTER' (+ its load-balancers/volumes) — this STOPS billing"
doctl kubernetes cluster delete "$CLUSTER" --dangerous --force 2>/dev/null \
  && echo "[kill] cluster deleted" || echo "[kill] no cluster named '$CLUSTER' (already gone)"

FW_ID="$(doctl compute firewall list --format ID,Name --no-header 2>/dev/null | awk -v n="$FW_NAME" '$2==n{print $1}')"
if [ -n "${FW_ID:-}" ]; then
  doctl compute firewall delete "$FW_ID" --force 2>/dev/null && echo "[kill] firewall '$FW_NAME' deleted"
fi

echo "[kill] verifying nothing lab-related remains (should be empty):"
doctl kubernetes cluster list  --format Name --no-header 2>/dev/null | grep -i vulnbank && echo "  !! cluster still present" || echo "  no lab cluster"
doctl compute load-balancer list --format Name --no-header 2>/dev/null | grep -i vulnbank && echo "  !! LB still present"    || echo "  no lab load-balancer"
doctl compute volume        list --format Name --no-header 2>/dev/null | grep -i vulnbank && echo "  !! volume still present" || echo "  no lab volume"
echo "[kill] done. Compute billing has stopped. (Registry image kept — revoke the DO token when the project ends.)"
