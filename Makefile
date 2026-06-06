# VulnBank detection-benchmark — Makefile
# Phase 0 targets are local-only (no infra). Infra targets (up/down/refresh/bench)
# are stubs filled in Phase 1-5 (see PLAN.md).

PYTHON ?= python3
GROUND_TRUTH ?= ground_truth.yaml
# default: score agent-smith's live findings.json (override with FINDINGS=...)
FINDINGS ?= ../agent-smith/findings.json
PROFILE ?= raw

TF_DIR ?= terraform
TFVARS ?= envs/doks.tfvars
PROFILE_NS_raw = vuln-bank

# Load secrets from .env (gitignored) and export to child processes (terraform/doctl/docker).
# One DO_TOKEN is mapped to the two names the tools expect.
-include .env
export DO_TOKEN DEEPSEEK_API_KEY ANTHROPIC_API_KEY SPACES_ACCESS_KEY_ID SPACES_SECRET_ACCESS_KEY
export TF_VAR_do_token := $(DO_TOKEN)
export DIGITALOCEAN_ACCESS_TOKEN := $(DO_TOKEN)

CERT_MANAGER_VERSION ?= v1.14.5

.PHONY: help install preflight wake kill validate score score-fixture test baseline clean \
        image up down kubeconfig docr-attach deploy-raw deploy-hardened cert-manager-install \
        urls urls-hardened seed-check apply-triggers collect-events score-events verify-zero \
        refresh reseed-hard bench aggregate baseline-save regress

help:
	@echo "Setup:"
	@echo "  make install          - check + install toolchain (doctl/kubectl/terraform), start Docker"
	@echo "  make preflight        - check toolchain only (no changes)"
	@echo ""
	@echo "Simplest cloud lifecycle (beginner):"
	@echo "  make wake             - turn the lab ON in DO (create cluster + deploy raw)"
	@echo "  make kill             - turn it OFF + delete everything (STOPS billing)"
	@echo ""
	@echo "Phase 0 (local, no infra):"
	@echo "  make validate         - validate ground_truth.yaml"
	@echo "  make score            - score FINDINGS=$(FINDINGS) on PROFILE=$(PROFILE)"
	@echo "  make score-fixture    - score the frozen sample findings (calibration)"
	@echo "  make test             - run the oracle test suite"
	@echo "  make baseline         - write out/scorecard.json from the fixture"
	@echo ""
	@echo ""
	@echo "Image + infra (Phase 1-2):"
	@echo "  make image            - build VulnBank lab image + push to DOCR (needs docker+doctl)"
	@echo "  make up               - terraform apply (DOKS + DOCR + firewall)"
	@echo "  make kubeconfig       - doctl: save kubeconfig for the cluster"
	@echo "  make docr-attach      - doctl: inject DOCR pull secret into the cluster"
	@echo "  make deploy-raw       - kubectl apply -k k8s/overlays/raw"
	@echo "  make cert-manager-install - install cert-manager (prereq for hardened)"
	@echo "  make deploy-hardened  - kubectl apply -k k8s/overlays/hardened (Kong+TLS+netpol)"
	@echo "  make urls             - print the raw-profile target URL"
	@echo "  make urls-hardened    - print the hardened-profile (Kong) target URL"
	@echo "  make seed-check URL=… - fail-closed preflight against a base URL"
	@echo ""
	@echo "Oracle exploit-axis (Phase 4):"
	@echo "  make apply-triggers   - install DB audit triggers (proves-exploit for business-logic)"
	@echo "  make collect-events   - gather observer/canary/DB proof events -> events.jsonl"
	@echo "  make score-events     - score findings.json + events.jsonl (reported×exploited)"
	@echo ""
	@echo "  make down             - terraform destroy"
	@echo "  make verify-zero      - assert no lab-tagged DO resources remain"
	@echo ""
	@echo ""
	@echo "Benchmark + regression gate (Phase 5):"
	@echo "  make bench PROFILE=raw - one scored run (snapshot-isolate -> run -> collect -> score)"
	@echo "  make aggregate         - combine runs/<profile>/*/scorecard.json -> out/aggregate.json"
	@echo "  make baseline-save     - freeze the aggregate as the regression baseline"
	@echo "  make regress           - compare aggregate vs baseline (exit 2 on regression)"
	@echo "  (Phase 3 stubs: refresh reseed-hard)"

install:
	./scripts/install.sh

preflight:
	./scripts/install.sh check

wake:
	./scripts/wake.sh

kill:
	./scripts/kill.sh

validate:
	$(PYTHON) -m oracle.scorer.cli validate --ground-truth $(GROUND_TRUTH)

score:
	$(PYTHON) -m oracle.scorer.cli score --findings $(FINDINGS) --ground-truth $(GROUND_TRUTH) \
		--profile $(PROFILE) --explain

score-fixture:
	$(PYTHON) -m oracle.scorer.cli score --findings oracle/scorer/fixtures/findings_sample.json \
		--ground-truth $(GROUND_TRUTH) --profile $(PROFILE)

test:
	$(PYTHON) -m unittest discover -s oracle/scorer/tests -p "test_*.py" -v

baseline:
	@mkdir -p out
	@# '-' / '|| true': baseline writes artifacts regardless of the must-find gate exit code
	-$(PYTHON) -m oracle.scorer.cli score --findings oracle/scorer/fixtures/findings_sample.json \
		--profile raw --json out/scorecard.raw.json >/dev/null
	-$(PYTHON) -m oracle.scorer.cli score --findings oracle/scorer/fixtures/findings_sample.json \
		--profile hardened --json out/scorecard.hardened.json >/dev/null
	@echo "Wrote out/scorecard.raw.json and out/scorecard.hardened.json"

clean:
	rm -rf out runs **/__pycache__ .pytest_cache

# --- image pipeline (Phase 1) ---
image:
	DOCR_NAME=$${DOCR_NAME:-smithbench} ./image/build-push.sh

# --- infra (Phase 2) ---
up:
	cd $(TF_DIR) && terraform init -input=false && terraform apply -var-file=$(TFVARS)

down:
	cd $(TF_DIR) && terraform destroy -var-file=$(TFVARS)
	@$(MAKE) verify-zero || true

kubeconfig:
	doctl kubernetes cluster kubeconfig save $${CLUSTER:-vulnbank-lab}

docr-attach:
	doctl kubernetes cluster registry add $${CLUSTER:-vulnbank-lab}

deploy-raw:
	kubectl apply -k k8s/overlays/raw
	kubectl -n vuln-bank rollout status deploy/vuln-bank --timeout=180s

cert-manager-install:
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
	kubectl -n cert-manager rollout status deploy/cert-manager --timeout=180s
	kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=180s

deploy-hardened:
	@kubectl get crd certificates.cert-manager.io >/dev/null 2>&1 || \
		{ echo "cert-manager not installed — run 'make cert-manager-install' first"; exit 1; }
	kubectl apply -k k8s/overlays/hardened
	kubectl -n kong rollout status deploy/kong-gateway --timeout=240s
	kubectl -n vuln-bank rollout status deploy/vuln-bank --timeout=180s

urls:
	@MODE=$${MODE:-nodeip} ./scripts/emit-target.sh raw

urls-hardened:
	@MODE=$${MODE:-nodeip} ./scripts/emit-target.sh hardened

apply-triggers:
	kubectl -n vuln-bank-db exec -i deploy/postgres -- \
		psql -U postgres -d vulnerable_bank < oracle/sql/oracle_audit.sql

collect-events:
	@./scripts/collect-events.sh $${OUT:-events.jsonl}

score-events:
	$(PYTHON) -m oracle.scorer.cli score --findings $(FINDINGS) \
		--events $${EVENTS:-events.jsonl} --profile $(PROFILE)

seed-check:
	@./scripts/seed-check.sh $${URL:?set URL=http://<host>:<port>}

verify-zero:
	@echo "Lab-tagged DO resources still present (should be empty):"
	@doctl compute droplet  list --tag-name vulnbank-lab --format ID,Name        --no-header || true
	@doctl compute load-balancer list --format ID,Name 2>/dev/null | grep -i vulnbank || true
	@doctl kubernetes cluster list --format ID,Name --no-header 2>/dev/null | grep -i vulnbank || true
	@doctl compute firewall list --format ID,Name --no-header 2>/dev/null | grep -i vulnbank || true
	@echo "(if any rows above name a lab resource, teardown is incomplete)"

# --- deterministic refresh (Phase 3) ---
refresh:
	@PROFILE=$${PROFILE:-raw} ./scripts/refresh.sh
reseed-hard:
	@PROFILE=$${PROFILE:-raw} ./scripts/reseed-hard.sh

# --- benchmark + regression gate (Phase 5) ---
bench:
	./scripts/run-benchmark.sh $${PROFILE:-raw}

aggregate:
	$(PYTHON) -m oracle.scorer.cli aggregate $${SCORECARDS:-runs/$${PROFILE:-raw}/*/scorecard.json} \
		--out $${AGG:-out/aggregate.json}

baseline-save:
	@mkdir -p oracle/scorer/baselines
	$(PYTHON) -m oracle.scorer.cli baseline-save --aggregate $${AGG:-out/aggregate.json} \
		--out $${BASELINE:-oracle/scorer/baselines/current.json} --agent-smith-commit $${AS_COMMIT:-unknown}

regress:
	$(PYTHON) -m oracle.scorer.cli regress --aggregate $${AGG:-out/aggregate.json} \
		--baseline $${BASELINE:-oracle/scorer/baselines/current.json}
