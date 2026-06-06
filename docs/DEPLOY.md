# Deploy runbook (DigitalOcean)

> ⚠️ This stands up an **intentionally-vulnerable** bank. Keep it reachable **only from
> your IP** (firewall) or, safer, **never publicly** (port-forward). Tear it down when done.

## 0. Unblock prerequisites (one-time)

Run the bootstrap — it checks every tool, installs the missing ones (doctl, kubectl,
terraform), starts the Docker daemon, installs python deps, and validates the repo:

```bash
make install        # or: make preflight  (check only, no changes)
```

Then make sure `.env` has a valid `DO_TOKEN` and doctl is authed with it:
```bash
doctl auth init -t "$(grep ^DO_TOKEN= .env | cut -d= -f2-)" && doctl account get
```
(Terraform installs from HashiCorp's precompiled binary if the Homebrew formula can't
build — the IaC path is optional anyway; §2B deploys with just doctl.)

## 1. Build & push the lab image
```bash
DOCR_NAME=smithbench make image     # builds VulnBank+observer, pushes, prints @sha256 digest
```
Pin that digest in `k8s/overlays/raw/kustomization.yaml` and `…/hardened/kustomization.yaml`
(`images[].digest`, drop `newTag`).

## 2A. Provision via Terraform (preferred — firewall + teardown engineered)
```bash
make up                              # reads .env DO_TOKEN; creates VPC + DOKS + DOCR + firewall
make kubeconfig && make docr-attach
```

## 2B. Provision via doctl (no Terraform installed)
```bash
doctl kubernetes cluster create vulnbank-lab \
  --region ams3 --version latest --node-pool "name=p;size=s-2vcpu-4gb;count=2" --tag vulnbank-lab
doctl registry create smithbench --subscription-tier basic   # if not already created
doctl kubernetes cluster registry add vulnbank-lab
# SAFETY: lock the worker NodePorts to YOUR IP only (never 0.0.0.0/0)
doctl compute firewall create --name vulnbank-lab-lock --tag-names vulnbank-lab \
  --inbound-rules "protocol:tcp,ports:30000-32767,address:YOUR_IP/32" \
  --outbound-rules "protocol:tcp,ports:all,address:0.0.0.0/0 protocol:udp,ports:all,address:0.0.0.0/0"
```
> Note: DO firewalls are allow/union-only — they cannot *remove* DOKS's default NodePort
> opening. The **safe default is to NOT expose NodePorts publicly at all** and reach the lab
> via `kubectl port-forward` (MODE=portforward), which needs no firewall and no public IP.

## 3. Deploy a profile
```bash
make deploy-raw                                  # raw profile
# or both: hardened needs cert-manager first
make cert-manager-install && make deploy-hardened
```

## 4. Reseed → preflight → run → score
```bash
make reseed-hard PROFILE=raw                     # deterministic clean state + per-run canary
MODE=portforward make urls                       # prints http://127.0.0.1:8088  (start the tunnel it shows)
make apply-triggers                              # DB audit triggers (business-logic proofs)
make seed-check URL=http://127.0.0.1:8088        # FAIL-CLOSED preflight

# point agent-smith at the URL (capped run), then:
make bench PROFILE=raw                           # snapshot-isolated scored run -> runs/raw/<id>/scorecard.json
```

## 5. Baseline & regression (after a few runs)
```bash
for i in 1 2 3; do make bench PROFILE=raw; done
make aggregate PROFILE=raw
make baseline-save AS_COMMIT=$(git -C ../agent-smith rev-parse --short HEAD)
# later, after changing agent-smith:
make regress                                     # exit 2 if a must-find vuln regressed
```

## 6. Teardown to $0
```bash
make down && make verify-zero                    # Terraform path
# doctl path:
doctl kubernetes cluster delete vulnbank-lab
doctl compute firewall delete <id>
doctl kubernetes cluster list; doctl compute load-balancer list   # confirm empty
```
Then **revoke the lab DO token** when the campaign is over.
