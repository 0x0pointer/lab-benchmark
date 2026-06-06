#!/usr/bin/env bash
# Print the base URL agent-smith should target for a given profile.
#
#   scripts/emit-target.sh raw                 # MODE=nodeip (default): http://<nodeIP>:30081
#   MODE=portforward scripts/emit-target.sh raw
#
# SAFE DEFAULT is portforward (zero public exposure, authenticated via kubeconfig).
# nodeip requires the node's public IP:NodePort to be reachable from your allowlist
# (verify empirically — see PLAN.md §8.2).
set -euo pipefail

PROFILE="${1:-raw}"
MODE="${MODE:-nodeip}"

case "$PROFILE" in
  raw)      NS=vuln-bank; SVC=vuln-bank-raw; SVC_PORT=5000 ;;
  hardened) NS=kong;      SVC=kong-gateway-proxy; SVC_PORT=443 ;;   # Phase 2
  *) echo "unknown profile: $PROFILE (use raw|hardened)" >&2; exit 1 ;;
esac

if [ "$MODE" = "portforward" ]; then
  LOCAL="${LOCAL_PORT:-8088}"
  echo "http://127.0.0.1:${LOCAL}"
  echo "[emit-target] start the tunnel in another shell:" >&2
  echo "    kubectl -n ${NS} port-forward svc/${SVC} ${LOCAL}:${SVC_PORT}" >&2
  exit 0
fi

# nodeip mode
NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}')"
NP="$(kubectl -n "${NS}" get svc "${SVC}" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)"
if [ -z "${NODE_IP}" ] || [ -z "${NP}" ]; then
  echo "[emit-target] could not resolve node IP / NodePort (is the cluster up and svc ${SVC} present?)" >&2
  exit 1
fi
SCHEME="http"; [ "$PROFILE" = "hardened" ] && SCHEME="https"
echo "${SCHEME}://${NODE_IP}:${NP}"
