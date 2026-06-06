#!/usr/bin/env bash
# Bootstrap / preflight for the lab-benchmark deploy toolchain.
# Checks every tool the deploy needs, installs the missing ones, starts the Docker
# daemon, installs python deps, and validates the repo. Idempotent + re-runnable.
#
#   scripts/install.sh            # check + install missing + start docker
#   scripts/install.sh check      # report only, change nothing
#   DOCKER_WAIT=60 scripts/install.sh
#
# macOS uses Homebrew; Linux prints apt/manual hints (no sudo is run automatically).
set -uo pipefail

MODE="${1:-install}"
DOCKER_WAIT="${DOCKER_WAIT:-120}"
OS="$(uname -s)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

ok()   { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33m[!!]\033[0m   %s\n' "$*"; }
err()  { printf '  \033[31m[xx]\033[0m   %s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }
MISSING=(); STARTED=(); OPT_MISSING=()

# Install terraform from HashiCorp's precompiled binary (no compiler/Xcode needed —
# the brew formula builds from source on bleeding-edge macOS, which fails here).
install_terraform_binary() {
  local ver="${TERRAFORM_VERSION:-1.9.8}" arch oss dest tmp
  case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
  case "$OS" in Darwin) oss=darwin ;; Linux) oss=linux ;; *) oss=darwin ;; esac
  for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do [ -d "$d" ] && [ -w "$d" ] && dest="$d" && break; done
  [ -z "${dest:-}" ] && { mkdir -p "$HOME/.local/bin"; dest="$HOME/.local/bin"; }
  tmp="$(mktemp -d)"
  local url="https://releases.hashicorp.com/terraform/${ver}/terraform_${ver}_${oss}_${arch}.zip"
  curl -fsSL "$url" -o "$tmp/tf.zip" && unzip -o -q "$tmp/tf.zip" -d "$tmp" \
    && mv -f "$tmp/terraform" "$dest/terraform" && chmod +x "$dest/terraform" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  ok "terraform ${ver} installed -> $dest/terraform"
  case ":$PATH:" in *":$dest:"*) ;; *) warn "add to PATH: export PATH=\"$dest:\$PATH\"" ;; esac
  return 0
}

brew_present() { have brew; }
install_hint() { # tool  brew-formula  [tap]
  local tool="$1" formula="$2" tap="${3:-}"
  if [ "$MODE" = check ]; then MISSING+=("$tool"); err "$tool missing (run without 'check' to install)"; return 1; fi
  if [ "$OS" = Darwin ] && brew_present; then
    local target="$formula"
    if [ -n "$tap" ]; then brew tap "$tap" >/dev/null 2>&1 || true; target="$tap/$formula"; fi
    warn "$tool missing — brew install $target"
    if brew install "$target" >/dev/null 2>&1; then ok "$tool installed"; STARTED+=("$tool"); return 0
    else err "$tool brew install failed — try: brew install $target"; MISSING+=("$tool"); return 1; fi
  fi
  err "$tool missing — install it (Linux: apt/pkg manager; macOS: install Homebrew first)"; MISSING+=("$tool"); return 1
}

# ---------------------------------------------------------------- core tools
hdr "core tools"
if have python3; then ok "python3 $(python3 -V 2>&1 | awk '{print $2}')"; else err "python3 missing (required)"; MISSING+=(python3); fi
have brew && ok "homebrew $(brew --version 2>/dev/null | head -1 | awk '{print $2}')" || { [ "$OS" = Darwin ] && warn "homebrew not found — needed to auto-install tools on macOS"; }

for t in doctl kubectl; do
  if have "$t"; then ok "$t present"; else install_hint "$t" "$t"; fi
done

# terraform: OPTIONAL — only the IaC `make up` path needs it; doctl path (DEPLOY.md §2B) skips it.
if have terraform; then ok "terraform $(terraform version 2>/dev/null | head -1 | awk '{print $2}')"
elif [ "$MODE" = check ]; then warn "terraform missing (optional — doctl path works without it)"; OPT_MISSING+=(terraform)
else
  warn "terraform missing — trying brew, then precompiled binary"
  if [ "$OS" = Darwin ] && brew_present && brew tap hashicorp/tap >/dev/null 2>&1 && brew install hashicorp/tap/terraform >/dev/null 2>&1; then
    ok "terraform installed (brew)"; STARTED+=(terraform)
  elif install_terraform_binary; then
    STARTED+=(terraform)
  else
    warn "terraform auto-install failed (OPTIONAL — use the doctl deploy path, DEPLOY.md §2B)"; OPT_MISSING+=(terraform)
  fi
fi

# ---------------------------------------------------------------- python deps
hdr "python deps"
if have python3; then
  if python3 -c "import yaml" >/dev/null 2>&1; then ok "PyYAML present"
  elif [ "$MODE" = check ]; then err "PyYAML missing"
  else
    warn "installing python deps (PyYAML)"
    python3 -m pip install -r requirements.txt >/dev/null 2>&1 && ok "python deps installed" \
      || python3 -m pip install --user -r requirements.txt >/dev/null 2>&1 && ok "python deps installed (--user)" \
      || err "pip install failed — run: python3 -m pip install -r requirements.txt"
  fi
fi

# ---------------------------------------------------------------- docker daemon
hdr "docker"
if ! have docker; then
  if [ "$OS" = Darwin ] && brew_present && [ "$MODE" != check ]; then
    warn "docker missing — brew install --cask docker (Docker Desktop)"
    brew install --cask docker >/dev/null 2>&1 && ok "Docker Desktop installed" || { err "install Docker Desktop from docker.com"; MISSING+=(docker); }
  else err "docker missing — install Docker Desktop from docker.com"; MISSING+=(docker); fi
elif docker info >/dev/null 2>&1; then
  ok "docker daemon up"
else
  if [ "$MODE" = check ]; then err "docker daemon DOWN (run without 'check' to start it)"
  else
    warn "docker daemon down — starting Docker Desktop"
    [ "$OS" = Darwin ] && open -a Docker >/dev/null 2>&1 || true
    printf "  waiting for docker daemon (up to %ss) " "$DOCKER_WAIT"
    waited=0
    while ! docker info >/dev/null 2>&1; do
      [ "$waited" -ge "$DOCKER_WAIT" ] && { echo; err "docker daemon did not come up in ${DOCKER_WAIT}s"; MISSING+=(docker-daemon); break; }
      printf '.'; sleep 3; waited=$((waited+3))
    done
    docker info >/dev/null 2>&1 && { echo; ok "docker daemon up"; STARTED+=(docker); }
  fi
fi

# ---------------------------------------------------------------- secrets + auth
hdr "secrets + auth"
[ -f .env ] || { cp .env.example .env 2>/dev/null && warn "created .env from template — fill DO_TOKEN"; }
if grep -q '^DO_TOKEN=.\+' .env 2>/dev/null; then ok ".env DO_TOKEN is set"; else warn ".env DO_TOKEN is EMPTY — set it before deploying"; fi
if have doctl && doctl account get >/dev/null 2>&1; then ok "doctl authenticated ($(doctl account get --format Email --no-header 2>/dev/null))"
else warn "doctl not authenticated — run: doctl auth init -t \"\$(grep ^DO_TOKEN= .env | cut -d= -f2-)\""; fi

# ---------------------------------------------------------------- repo sanity
hdr "repo sanity"
if have python3 && python3 -c "import yaml" >/dev/null 2>&1; then
  python3 -m oracle.scorer.cli validate >/dev/null 2>&1 && ok "ground_truth.yaml valid" || err "ground_truth.yaml validation failed"
  python3 -m unittest discover -s oracle/scorer/tests -p 'test_*.py' >/dev/null 2>&1 && ok "oracle tests pass" || err "oracle tests FAILED"
fi
for b in kubectl; do have "$b" && kubectl kustomize k8s/overlays/raw >/dev/null 2>&1 && ok "k8s overlays build" && break; done

# ---------------------------------------------------------------- summary
hdr "summary"
[ "${#STARTED[@]}" -gt 0 ] && echo "  installed/started: ${STARTED[*]}"
[ "${#OPT_MISSING[@]}" -gt 0 ] && echo "  optional missing : ${OPT_MISSING[*]} (deploy still works via the doctl path)"
if [ "${#MISSING[@]}" -eq 0 ]; then
  echo "  toolchain READY."
  echo "  next: docs/DEPLOY.md  ->  make image && (make up | doctl path) && make deploy-raw"
  exit 0
else
  echo "  NOT READY — unresolved (required): ${MISSING[*]}"
  echo "  re-run after addressing the [xx] items above."
  exit 1
fi
