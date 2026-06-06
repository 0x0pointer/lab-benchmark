#!/usr/bin/env bash
# Turn the lab ON: create the DOKS cluster (if missing), wire kubeconfig + registry pull
# secret + the IP-allowlist firewall, deploy the raw profile. Idempotent — safe to re-run.
# Uses doctl (works even with a narrowly-scoped DO token). Pair with scripts/kill.sh.
#
#   make wake            # then: make reseed-hard && make urls
set -uo pipefail
CLUSTER="${CLUSTER:-vulnbank-lab}"
REGION="${REGION:-ams3}"
TAG="${TAG:-vulnbank-lab}"
FW_NAME="${FW_NAME:-vulnbank-lab-lock}"
ALLOW_CIDR="${ALLOW_CIDR:-$(grep -oE '[0-9.]+/[0-9]+' terraform/envs/doks.tfvars 2>/dev/null | head -1)}"
ALLOW_CIDR="${ALLOW_CIDR:-YOUR_IP/32}"
log() { echo "[wake] $*"; }

command -v doctl >/dev/null || { echo "doctl missing — run 'make install'"; exit 1; }
doctl account get >/dev/null 2>&1 || { echo "doctl not authenticated — run: doctl auth init -t \"\$(grep ^DO_TOKEN= .env | cut -d= -f2-)\""; exit 1; }

if doctl kubernetes cluster get "$CLUSTER" >/dev/null 2>&1; then
  log "cluster '$CLUSTER' already exists"
else
  VER="$(doctl kubernetes options versions -o json 2>/dev/null | python3 -c "import sys,json;print(next(v['slug'] for v in json.load(sys.stdin) if v['slug'].startswith('1.34')))")"
  log "creating cluster '$CLUSTER' ($VER), 2 nodes — this takes ~6-10 min..."
  doctl kubernetes cluster create "$CLUSTER" --region "$REGION" --version "$VER" \
    --node-pool "name=pool;size=s-2vcpu-4gb;count=2;tag=${TAG}" --tag "$TAG" --wait \
    || { echo "[wake] cluster create failed"; exit 1; }
fi

log "kubeconfig + registry pull-secret"
doctl kubernetes cluster kubeconfig save "$CLUSTER" >/dev/null
doctl kubernetes cluster registry add "$CLUSTER" >/dev/null 2>&1 || true

if ! doctl compute firewall list --format Name --no-header 2>/dev/null | grep -qx "$FW_NAME"; then
  log "firewall '$FW_NAME' — NodePorts allowed ONLY from ${ALLOW_CIDR}"
  doctl compute firewall create --name "$FW_NAME" --tag-names "$TAG" \
    --inbound-rules "protocol:tcp,ports:30000-32767,address:${ALLOW_CIDR}" \
    --outbound-rules "protocol:tcp,ports:1-65535,address:0.0.0.0/0,address:::/0 protocol:udp,ports:1-65535,address:0.0.0.0/0,address:::/0 protocol:icmp,address:0.0.0.0/0,address:::/0" >/dev/null \
    || echo "[wake] firewall create failed (add your IP manually)"
fi

log "deploying raw profile"
kubectl apply -k k8s/overlays/raw >/dev/null
kubectl -n vuln-bank-db rollout status deploy/postgres   --timeout=150s
kubectl -n vuln-bank    rollout status deploy/vuln-bank  --timeout=180s
NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}')"
log "UP. raw URL: http://${NODE_IP}:30081"
log "next: make reseed-hard PROFILE=raw   (then point agent-smith at the URL)"
log "WHEN DONE: make kill   (stops billing)"
