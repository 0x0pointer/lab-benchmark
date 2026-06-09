#!/usr/bin/env bash
# Delete the lab cluster + firewall so DigitalOcean STOPS billing. Safe to run anytime;
# your code and results stay on your laptop. Uses doctl.
#
# FAILS LOUDLY if the teardown does not actually take (e.g. a DO token without delete
# scope) — it never reports a false "already gone", and it WAITS for the node droplets
# to terminate (that is the moment compute billing stops), then verifies. Exit non-zero
# if anything billable still remains.
set -uo pipefail
CLUSTER="${CLUSTER:-vulnbank-lab}"
FW_NAME="${FW_NAME:-vulnbank-lab-lock}"
NAME_MATCH="${NAME_MATCH:-vulnbank}"   # substring identifying lab droplets/clusters/LBs
rc=0

command -v doctl >/dev/null 2>&1 || { echo "[kill] doctl not found — run 'make install'"; exit 1; }
doctl account get >/dev/null 2>&1   || { echo "[kill] doctl not authenticated — run: doctl auth init"; exit 1; }

# 1) delete the cluster (+ associated LBs/volumes). Errors are SHOWN, not swallowed.
if doctl kubernetes cluster get "$CLUSTER" >/dev/null 2>&1; then
  echo "[kill] deleting cluster '$CLUSTER' (+ its load-balancers/volumes)…"
  if ! doctl kubernetes cluster delete "$CLUSTER" --dangerous --force; then
    echo "[kill] ERROR: cluster delete FAILED — your DO token may lack delete scope." >&2
    echo "       Delete it manually: https://cloud.digitalocean.com/kubernetes/clusters" >&2
    rc=1
  fi
else
  echo "[kill] no cluster named '$CLUSTER' (already gone)"
fi

# 2) lab firewall (the k8s-managed firewalls auto-remove with the cluster)
FW_ID="$(doctl compute firewall list --format ID,Name --no-header 2>/dev/null | awk -v n="$FW_NAME" '$2==n{print $1}')"
if [ -n "${FW_ID:-}" ]; then
  doctl compute firewall delete "$FW_ID" --force && echo "[kill] firewall '$FW_NAME' deleted" \
    || { echo "[kill] firewall delete failed" >&2; rc=1; }
fi

# 3) WAIT for node droplets to actually terminate — billing stops when they're gone (~1-2 min)
echo "[kill] waiting for node droplets to terminate (compute billing stops then)…"
for _ in $(seq 1 36); do
  n="$(doctl compute droplet list --format Name --no-header 2>/dev/null | grep -ci "$NAME_MATCH" || true)"
  [ "$n" = "0" ] && break
  printf '.'; sleep 5
done; echo

# 4) verify — report and exit non-zero if anything billable remains
cl="$(doctl kubernetes cluster list   --format Name --no-header 2>/dev/null | grep -ci "$NAME_MATCH" || true)"
dr="$(doctl compute droplet list      --format Name --no-header 2>/dev/null | grep -ci "$NAME_MATCH" || true)"
lb="$(doctl compute load-balancer list --format Name --no-header 2>/dev/null | grep -ci "$NAME_MATCH" || true)"
vo="$(doctl compute volume list       --format Name --no-header 2>/dev/null | grep -ci "$NAME_MATCH" || true)"
echo "[kill] remaining lab-tagged: clusters=$cl droplets=$dr load-balancers=$lb volumes=$vo"
if [ "$cl$dr$lb$vo" != "0000" ] || [ "$rc" != "0" ]; then
  echo "[kill] !! NOT fully torn down (see above) — compute may still bill. Re-run or use the console." >&2
  exit 1
fi

echo "[kill] DONE — compute billing stopped."
echo "[kill] note: your container REGISTRY is separate and is NOT deleted (it may be shared by"
echo "       other projects). Free leftover VPC '${CLUSTER}-vpc' can be removed in the console."
