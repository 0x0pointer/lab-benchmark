#!/usr/bin/env bash
# Build the VulnBank LAB image and push it to DigitalOcean Container Registry (DOCR),
# pinned by immutable digest. Replaces the blog's `ctr import` / imagePullPolicy:Never,
# which does not work on DOKS managed nodes (PLAN.md §8.6).
#
# Requirements: docker (daemon running), doctl (authenticated), git.
# Usage:
#   DOCR_NAME=vulnbank-lab ./image/build-push.sh
#   VB_COMMIT=<sha> DOCR_NAME=vulnbank-lab ./image/build-push.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# Load secrets from the repo .env when run directly (the Makefile already does this).
if [ -f "$REPO_ROOT/.env" ]; then
  set -a; . "$REPO_ROOT/.env"; set +a
  export DIGITALOCEAN_ACCESS_TOKEN="${DIGITALOCEAN_ACCESS_TOKEN:-${DO_TOKEN:-}}"
fi

DOCR_NAME="${DOCR_NAME:-smithbench}"
VB_REPO="${VB_REPO:-https://github.com/Commando-X/vuln-bank.git}"
VB_COMMIT="${VB_COMMIT:-}"          # pin a commit for reproducibility; empty = current main
IMAGE_TAG="${IMAGE_TAG:-seed-v1}"
WORKDIR="${WORKDIR:-/tmp/vuln-bank-build}"

REGISTRY="registry.digitalocean.com/${DOCR_NAME}"
# DOKS nodes are linux/amd64 — cross-build for that arch (the host may be arm64/Apple Silicon).
PLATFORM="${PLATFORM:-linux/amd64}"
BASE_IMAGE="${REGISTRY}/vuln-bank:base-amd64"
LAB_IMAGE="${REGISTRY}/vuln-bank:${IMAGE_TAG}"

echo "==> [1/6] fetch VulnBank source"
if [ ! -d "$WORKDIR/.git" ]; then
  git clone "$VB_REPO" "$WORKDIR"
fi
git -C "$WORKDIR" fetch --all --quiet
if [ -n "$VB_COMMIT" ]; then
  git -C "$WORKDIR" checkout --quiet "$VB_COMMIT"
fi
RESOLVED_COMMIT="$(git -C "$WORKDIR" rev-parse HEAD)"
echo "    VulnBank @ ${RESOLVED_COMMIT}"

echo "==> [2/6] docr login"
doctl registry login

echo "==> [3/6] cross-build pristine upstream base ($PLATFORM) -> registry"
docker buildx build --platform "$PLATFORM" -t "$BASE_IMAGE" --push "$WORKDIR"

echo "==> [4/6] cross-build lab image (base + observer) -> registry"
docker buildx build --platform "$PLATFORM" --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
  -t "$LAB_IMAGE" --push -f "$HERE/Dockerfile.lab" "$HERE"

echo "==> [5/6] resolve immutable digest (amd64 manifest)"
DIGEST="$(docker buildx imagetools inspect "$LAB_IMAGE" --format '{{ range .Manifest.Manifests }}{{ if eq .Platform.architecture "amd64" }}{{ .Digest }}{{ end }}{{ end }}' 2>/dev/null || true)"
[ -z "$DIGEST" ] && DIGEST="$(doctl registry repository list-tags vuln-bank --format Tag,ManifestDigest --no-header 2>/dev/null | awk -v t="$IMAGE_TAG" '$1==t{print $2}')"
[ -n "$DIGEST" ] && DIGEST="${LAB_IMAGE%%:*}@${DIGEST}"
echo "    digest: ${DIGEST:-<unresolved — set manually in versions.txt>}"

echo "==> [6/6] garbage-collect old untagged manifests (stay under DOCR cap)"
doctl registry garbage-collection start --include-untagged-manifests --force "$DOCR_NAME" || \
  echo "    (gc skipped — run manually if registry nears its size cap)"

# Record provenance for reproducibility / baseline re-bless.
{
  echo "vulnbank.commit = ${RESOLVED_COMMIT}"
  echo "vulnbank.image  = ${DIGEST:-${LAB_IMAGE}}"
} >> "$REPO_ROOT/versions.txt"
echo
echo "DONE. Pin this in k8s/overlays/*/kustomization.yaml images[]:"
echo "    name:  ${REGISTRY}/vuln-bank"
echo "    digest: ${DIGEST#*@}"
