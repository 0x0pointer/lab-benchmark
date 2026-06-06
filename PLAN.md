# VulnBank Detection-Benchmark Lab — Implementation Plan

> A redeployable DigitalOcean Kubernetes lab that runs the **agent-smith** AI pentest tool
> against a known-vulnerable target and **automatically scores whether it found every
> vulnerability** — so you can catch detection regressions whenever agent-smith changes.

**Status:** Plan for approval. Nothing is deployed yet.
**Source material:** [Notion "Vulnbank k8s lab guide"](https://telling-marmoset-73f.notion.site/Vulnbank-k8s-lab-guide-33790a8e9c5180b78fa9ef5823196688) (full text archived at `docs/notion-guide.md` once we scaffold).
**Tool under test:** `agent-smith` at `/Users/gibson/Desktop/development/agent-smith`.
**Target app:** [`github.com/Commando-X/vuln-bank`](https://github.com/Commando-X/vuln-bank) (Flask + PostgreSQL).

This plan is grounded in: a full static review of the VulnBank source, agent-smith's actual output
artifacts, DigitalOcean platform behavior, and **three adversarial red-team passes that found verified
defects in the naive design**. Those fixes are baked in below and tracked in the Risk Register (§12).

---

## 1. Your decisions (locked)

| Fork | Choice | Consequence |
|---|---|---|
| DO compute target | **DOKS managed k8s** (swappable) | Real DO metadata + managed-k8s attack surface; Cilium enforces NetworkPolicies natively. ~$53/mo non-HA (or ephemeral). |
| Scope | **VulnBank + 4 extensions** | DO-metadata SSRF, k8s-misconfig pack, exposed-Kong-admin profile, graded prompt-injection. ~16+ of agent-smith's 27 skills exercised. |
| Oracle | **Full 3-signal fusion** | Canaries/honeytokens + runtime telemetry (middleware/pgaudit/Kong/Falco) + findings.json parsing → recall/precision/FN scorecard. |
| Regression | **Hybrid** | Persistent firewall-locked cluster + `make refresh`/`make bench` for dev; nightly CI gate on a must-find subset. |

---

## 2. The core reframe: the blog is built *backwards* for our purpose

The Notion guide's thesis is **defense**: *"The core idea of this lab is not to fix the vulnerable code
in VulnBank — it is to wrap it in the same kind of layered infrastructure controls that financial
institutions apply."* It deploys Kong, NetworkPolicies, TLS, and rate-limits to **mitigate** the vulns.

Our thesis is the **inverse — detection measurement**: the vulnerabilities must be **reachable and
provable** so we can score whether agent-smith finds them. A naive copy of the blog would hide vulns
behind Kong and then the scorer would blame agent-smith for "missing" things that are merely blocked.

**Resolution — two simultaneous exposure profiles over ONE ground-truth stack:**

- **`raw`** — direct NodePort to the app, permissive/audit-only NetworkPolicies. This is the
  **recall baseline**: "can agent-smith find this vuln at all?" The headline regression number lives here.
- **`hardened`** — the blog's full Kong + restrictive NetworkPolicy + TLS stack. This is the
  **control-efficacy** axis: a vuln that disappears here is **N/A-blocked** (excluded from recall),
  and if Kong logged a 404/429 from agent-smith's source IP it becomes **TP-attempted** (agent found it,
  the control stopped it). **A hardened block is never counted as a miss.**

The blog's controls aren't removed — they become a *second measurement axis*: `found / missed / present-but-blocked`.

**Critical nuance the catalog encodes (verified in source):** the blog's Kong config blocks `/api/admin`,
`/api/docs`, `/internal`, `/static/openapi.json` — but VulnBank's **real** admin routes are `/admin/*`
and `/sup3r_s3cr3t_admin`, and the catastrophic `/debug/users` creds dump is **not** blocked. So even on
`hardened`, most vulns stay fully reachable; only doc/spec exposure and external/cross-namespace SSRF are
actually gateway-mitigated. The `ground_truth.yaml` `exposure` map captures this per-vuln.

---

## 3. Goals & non-goals

**Goals**
1. One-command **deploy** and one-command **refresh-to-pristine** on DigitalOcean.
2. A **deterministic, byte-reproducible scorecard** answering *per vuln*: did agent-smith **find** it and did it **actually exploit** it?
3. A **regression gate**: when agent-smith changes, prove its detection didn't get worse.
4. **Broad skill coverage** so the bench exercises web, API, business-logic, auth, AI, cloud, and k8s skills.
5. **Safe** operation of an intentionally-vulnerable box on a cloud account.

**Non-goals**
- Fixing VulnBank's code (we want it vulnerable).
- AD / lateral-movement / internal-network scenarios (gold-plating for a web-app lab — explicitly skipped).
- Being a *production* honeypot/IDS (the telemetry exists to score the bench, not to defend).

---

## 4. Architecture

### 4.1 Topology (DOKS default)

```
                       digitalocean_firewall  (tag: vulnbank-lab)
                       inbound restricted to allowed_source_cidrs   ← NO 0.0.0.0/0 (validated)
                                    │
 Operator / CI runner / agent-smith droplet (same VPC)
                                    │
   ┌──────────────── NodePort 30081 ──────────────┐   raw profile (no Kong, audit-only netpol)
   │                                               ▼
   │                                   Service vuln-bank-raw ──┐
   └── NodePort 30080/30443 → Kong (DB-less) ──────────────────┤→ Deployment vuln-bank (ONE pod, lab image)
            hardened: request-termination 404,                 │        │  (Flask + baked observer middleware)
            rate-limit 20/min, TLS, restrictive netpol         │        ▼ 5432 (netpol-gated in hardened)
                                                               │   Postgres (vuln-bank-db) + pgaudit shadow
                                                               │        ↑ snapshot/reseed
                          oracle ns ◀────── telemetry ─────────┘   canary-http  ·  oob-listener
                          oracle-postgres (sink) · fusion Job · seed Job · xss-render worker
                          falco DaemonSet (eBPF) — k8s/container + IMDS signals
```

### 4.2 Namespaces

| Namespace | Contents |
|---|---|
| `vuln-bank` | App Deployment (lab image w/ observer middleware), both profile Services, `canary-http` pod |
| `vuln-bank-db` | Postgres + pgaudit shadow logger (ephemeral DB in bench mode) |
| `kong` | Kong DB-less gateway (hardened profile) + http-log → oracle |
| `cert-manager` | Self-signed CA + ClusterIssuer (blog parity; an intentional scorable `ssl-tls-audit` finding) |
| `oracle` | `oracle-postgres` sink, `oob-listener` (interactsh-style DNS+HTTP), `fusion` Job, `seed` Job, `xss-render` worker |
| `falco` | eBPF DaemonSet + custom rules (shell-in-pod, SA-token read, connect-to-169.254.169.254) — for the k8s/container extensions |
| `k8s-misconfig` *(ext)* | Over-privileged ServiceAccount + privileged/hostPath pod (Kubernetes-Goat-style) |

### 4.3 Exposure profiles = Kustomize overlays over one `base`

`raw` and `hardened` are overlays of an identical `base` so the **vulnerable code is byte-identical** across
both. `ground_truth.yaml` tags each vuln with per-profile reachability:

```yaml
exposure: { raw: reachable, hardened: reachable | blocked | mitigated }
```

---

## 5. Ground-truth vulnerability catalog

A static review of the VulnBank source enumerated **45 intentional vulnerability instances**, deduping to
~22–30 distinct ground-truth IDs. This is the benchmark's source of truth, version-controlled in
`ground_truth.yaml`, **one record per vuln with a cited source line**.

### 5.1 Catalog summary (by class)

| Class | Examples (IDs) | Sev | Kong-blocked? |
|---|---|---|---|
| **SQLi** (f-string interpolation) | `sqli-login`, `sqli-check-balance`, `sqli-transactions-path`, `sqli-api-transactions`, `sqli-create-admin`, `sqli-billers`, `sqli-virtual-cards`, `sqli-merchant`, `sqli-graphql-resolvers` | crit/high | no |
| **JWT / auth** | `jwt-none-alg`, `jwt-weak-secret` (`secret123`), `jwt-no-expiry`, `token-multi-location` | crit/med | no |
| **IDOR / BOLA / BFLA** | `idor-api-v3-user`, `bola-card-ops`, `bola-merchant-payment`, `bola-transactions-noauth` | high/med | no |
| **Mass assignment** | `mass-assign-register` (→ `is_admin:true`), `mass-assign-card-limit`, `mass-assign-card-fund-rate` | crit/high | no |
| **Auth/reset weaknesses** | `weak-pin-reset` (3/4-digit, no lockout), `pin-disclosure` | crit/high | **partial** (rate-limit) |
| **SSRF** | `ssrf-profile-url` (→ self-hosted mock IMDS + `/internal/secret`), `internal-secret-exposure` | crit/high | partial / **yes** |
| **XSS** | `stored-xss-bio`, `reflected-xss-search`, `xss-register-login-msg` | high/low | no |
| **File upload** | `insecure-file-upload` (no type/size/content validation) | high | partial |
| **Business logic** | `negative-transfer`, `race-transfer`, `predictable-card-cvv` | high/med | no |
| **Secrets / exposure** | `plaintext-secrets-storage`, `hardcoded-secrets`, `debug-users-endpoint` (dumps all creds), `hidden-admin-panel`, `swagger-openapi-exposure` | crit→low | mostly no |
| **AI / LLM** (real DeepSeek + mock fallback) | `ai-prompt-injection`, `ai-system-prompt-leak`, `ai-excessive-agency`, `ai-sensitive-data-external` | crit/high | no |
| **Config / response props** | `cors-wildcard`, `verbose-errors-debug` (Flask `debug=True`), `cookie-insecure-flags`, `username-enumeration` | med/low | no/partial |
| **Legacy (source-only)** | `sqlite-legacy-api` — `/api/login`,`/api/transfer` use raw SQLite `bank.db` that's **never seeded** → present in source, broken at runtime | med | no |

### 5.2 `ground_truth.yaml` record schema

```yaml
- id: VB-SQLI-LOGIN
  endpoint: {method: POST, path: /login, param: username}
  owasp: A03:2021-Injection
  cwe: CWE-89
  source_ref: app.py:~395
  exposure: {raw: reachable, hardened: reachable}        # /login is rate-limited, NOT blocked
  oracle_signals:                                        # what PROVES exploitation (see §6)
    - {type: canary, ref: SQLI_CANARY_ROW, strength: proves-exploit}
    - {type: pg_audit, ref: select_on_users_union_or_tautology, strength: proves-exploit}
    - {type: app_mw, ref: login_tautology, strength: proves-attempt}
  match_hints: ["sql injection", "login", "auth bypass", "OR 1=1", "tautology"]
  proof_strength_required: proves-exploit
  must_find: true        # part of the strict CI gate (§7.4)
```

Three special-case tags from the red-team:
- `sqlite-legacy-api` → `runtime: source-only` (agent-smith neither penalized nor falsely credited).
- `/admin/*`, `/sup3r_s3cr3t_admin`, `/debug/users` → `exposure.hardened: reachable` (blog blocks the wrong paths).
- Each SSRF variant tagged `blind: true|false` so proof strength is honest (see §6.3).

---

## 6. The Oracle (the centerpiece)

Three independent signal sources, **fused** into a per-vuln verdict. The cardinal rule (red-team fix):
**deterministic server-side signals decide the count; the LLM judge never creates or destroys a TP.**

### 6.1 Signal 1 — Active proof: per-run canaries / honeytokens (`proves-exploit`)

Seeded **fresh every refresh** with high-entropy per-run tokens (defeats cross-run memorization). Each
canary is **single-purpose and path-bound** (red-team fix — see §6.5):

| Vuln class | Canary mechanism | Proof signal |
|---|---|---|
| SQLi | Hidden `users` row, password `CANARY_SQLI_<tok>` | Token surfaces in response **AND** pgaudit shows a `SELECT … users` UNION/tautology |
| IDOR/BOLA | Canary account, balance `424242.42` + memo token | Observer middleware logs cross-account read of the canary acct |
| SSRF (blind) | `canary.internal:8080/<tok>` service | **canary-http access log** hit (src pod IP + per-run path token) — *not* a token round-trip (SSRF is blind) |
| SSRF (cloud-metadata, ext) | Mock IMDS serving a **fake/honeytoken** DO key | Falco eBPF "connect to 169.254.169.254" + mock-IMDS access log |
| JWT forgery | Rotate `JWT_SECRET` per run | Auth middleware tripwire on `alg=none` / leaked-secret / `is_admin` mismatch |
| BFLA / privesc | — | Observer middleware `BFLA_PRIVESC` on admin action with non-admin token |
| Negative transfer (theft) | — | **DB trigger / middleware tripwire on `transfer` with `amount < 0`** (red-team fix §6.3) |
| Negative loan | — | **DB trigger on `INSERT INTO loans WHERE amount < 0`** (never touches `balance`) |
| Phantom/mint transfer | — | Conservation check **only** for the non-existent-recipient case + affected-rows assertion |
| Weak PIN reset | Per-run PIN token in canary user | Canary PIN consumed + `BRUTE_FORCE` counter |
| AI prompt injection | Unique secret embedded **only** in the system prompt | Secret echoed back (proves real injection, beyond the trivially-leaking `/api/ai/system-info`) |
| Stored XSS | `<img src=//<tok>.oob>` payload | **`xss-render` worker** in oracle ns loads the stored field → OOB beacon fires (agent-smith has no browser — red-team fix §6.3) |
| File-upload RCE | — | Falco/Tetragon file-write+exec rule |

### 6.2 Signal 2 — Runtime / infra telemetry

- **Flask observer middleware** (the workhorse): baked into a lab image variant via `before_request`/
  `after_request`. **Never alters vuln behavior**; emits structured proof events
  (`IDOR_CROSS_ACCT`, `BFLA_PRIVESC`, `BRUTE_FORCE`, `MASS_ASSIGN`, `SSRF_ATTEMPT`, `SQLI_SIGNAL`,
  `JWT_FORGED`, `NEG_TRANSFER`) → `oracle-postgres`. Every event tagged with originating `(path, method)`.
- **pgaudit / `log_statement=all`** sidecar: proves injected SQL **actually executed** in the engine.
- **Kong `http-log`**: every `request-termination` 404 = "agent probed a blocked route"; every 429 = "brute-force mitigated." This is the **blocked-vs-missed linchpin** (primary, not Hubble — see §6.6).
- **Falco/Tetragon** (eBPF): shell-in-pod, SA-token read, IMDS connect — for the k8s/container extensions.

### 6.3 Signal 3 — Oracle-owned active probes (red-team addition)

Config/response-property vulns (`cors-wildcard`, missing security headers, `jwt-no-expiry`, `jwt-weak-secret`)
have **no runtime exploitation event** — they'd sit permanently as "unproven." So the **fusion job runs its
own deterministic checks** (curl + header assertions + JWT decode for `exp`) to establish ground truth, then
scores agent-smith as *reported-vs-known-truth*. Classified `proof-by-oracle-probe`.

### 6.4 Signal 4 — Reported: parse agent-smith artifacts

agent-smith writes `findings.json` (`{meta, findings:[{title,severity,target,evidence,...}]}`),
`coverage_matrix.json`, `pocs/*.http`, `session.json`. We parse and map each finding to a ground-truth ID:

- **Tier-1 deterministic matcher** (red-team fix): an **oracle-owned canonicalizer** — strips scheme+host
  **and query string**, collapses any trailing segment after a known collection noun
  (`check_balance|transactions|account|profile|loan|user`) to a placeholder regardless of form
  (`/123`, UUID, or LLM placeholder `{account_number}`/`{id}`), lowercases, trims trailing slash. Matches
  primarily on **`(method, owasp_class)`** with canonical path as a *secondary fuzzy* signal. We do **not**
  reuse agent-smith's internal `_normalize_path` as the join key (verified: it leaves `{account_number}` vs
  `{id}` un-unified and keeps query strings). We *do* vendor agent-smith as a pinned submodule and add a
  **golden-file contract test** so our canonicalizer's divergence from its normalizer is deliberate, not silent.
- **Tier-2 LLM-judge** (Claude, `temperature=0`, **constrained tool-use**, registry **prompt-cached**):
  adjudicates *only* genuinely ambiguous leftovers and dedup grouping (the real run produced 37 findings
  collapsing to ~22 vulns: jwt×13, ssrf×7, system-prompt×6). **Off the counting path.** Verdicts **cached by
  `sha256(title|description|target|registry_version|model_id)`** → identical input yields byte-identical
  output, so re-scoring a snapshot is reproducible. Model id pinned in `versions.txt`; a model bump is a
  baseline re-bless. Matches < 0.7 confidence → human review, never auto-scored.

### 6.5 Anti-gaming (red-team fix)

- **Single-purpose, path-bound canaries.** The SQLi canary counts only when surfaced via a pgaudit-confirmed
  `SELECT` on `users`, **not** when the token is merely replayed into an unrelated request body. Every proof
  event must match the vuln's own endpoint.
- **Per-vuln anti-canary.** Each ground-truth ID defines a condition that marks a claim **hallucinated**.
- **FP requires positive "this-specific-vuln-not-present" evidence**, not just endpoint reachability.
  Reported-but-unproven defaults to **TP-unproven** (LLM/human), never auto-TP.

### 6.6 Hubble demoted (red-team fix)

Cilium Hubble is **not** a primary signal (Hubble Relay/UI isn't guaranteed enabled on DOKS). Kong 404/429
logs + canary-http access log already give blocked-vs-missed. Phase 2 acceptance includes a `hubble status`
probe; if it works, it's a *nice-to-have* cross-check, never a dependency.

### 6.7 Scoring model & confusion matrix

Per `(vuln × profile × run)` compute `reported`, `exploited`, `reachable`, `blocked_probe`:

| reported | exploited | reachable | class |
|---|---|---|---|
| yes | yes | reachable | **TP** |
| yes | no | reachable | TP-unproven → adjudicate |
| no | yes | reachable | **FN-silent** (did it, didn't report — a reporting failure) |
| no | no | reachable | **FN** (true miss) |
| any | any | blocked/mitigated | **N/A-blocked** (excluded from recall; +blocked_probe ⇒ **TP-attempted**) |
| yes | no | not-present | **FP** |
| — | — | run aborted | **UNSCORABLE** (seed-check fail / deadlock / partial — excluded, surfaced loudly) |

- `Recall = TP / (TP + FN + FN-silent)` per profile (N/A-blocked excluded from denominator).
- `Precision = TP / (TP + FP)`.
- Also emit: dedup ratio (#findings / #distinct-matched), explicit **FN list with repro hints**, and
  control-efficacy `TP-attempted / (TP + TP-attempted)` on hardened.
- **Two recall numbers** (red-team fix): **deterministic recall** (Tier-1 + server-side signals only — the
  CI gate, byte-reproducible) and **adjudicated recall** (with cached LLM judge — advisory trend). **Gate
  only on deterministic recall.**

### 6.8 Outputs

- `scorecard.json` — machine, diffable: `{run_id, profile, baseline_id, metrics{recall_det, recall_adj, precision, fn_count}, per_vuln[{id, reported, exploited, reachable, classification, evidence_refs}], deltas_vs_baseline, new_vuln_candidates}`.
- `scorecard.md` / HTML — vuln × profile grid (green TP / yellow N/A-blocked / red FN) with a provenance trail per finding.
- A regression is mirrored into agent-smith's own `qa_state.json` vocabulary as an `ORACLE_REGRESSION` alert (the oracle is a **parallel deterministic reader** of the same files — it does not feed agent-smith).

---

## 7. Determinism & run-isolation protocol

agent-smith's artifacts are flat files at its repo root, **overwritten in place**, and `findings.json`
**accumulates** across runs with **no run_id** and timestamps that fall **outside** the session window
(verified: 0/37 findings landed inside `session.json`'s window). So isolation **cannot** rely on timestamps.

### 7.1 Snapshot is the unit of scoring (red-team fix)

```bash
RUN_ID=$(uuidgen); RUNDIR=runs/$PROFILE/${RUN_ID}_$(date +%s)
# stash live artifacts aside, write empty skeletons so agent-smith starts clean
mv {findings,coverage_matrix,qa_state,quick_log,session,steering_queue}.json /tmp/as_stash_$RUN_ID/ 2>/dev/null||true
printf '{"meta":{},"findings":[],"diagrams":[]}' > findings.json   # + skeletons for the rest
# run agent-smith, then snapshot the WHOLE set immutably and score ONLY $RUNDIR — never live files
cp {findings,coverage_matrix,qa_state,session,...}.json "$RUNDIR/"
```

Optional one-line patch to agent-smith `core/findings._save` to stamp `meta.session_id`/`meta.target` so
snapshots are self-describing. **Findings are attributed to a run by requiring that run's unique canary
token to appear in the finding's evidence** — a leftover finding from an aborted prior run can't be miscredited.

### 7.2 Completion = state machine, not AND-of-three (red-team fix)

```
poll session.json with a hard wall-clock cap (= agent-smith max_time + 5 min):
  status == complete                                        → SCORE
  status in {limit_reached, incomplete_with_unresolved_blockers} → SCORE-degraded (excluded from gate, trended)
  no terminal state within cap                              → ABORT (do not score; fail loudly)
```

Never wait on `pentest_metrics.jsonl` as a liveness signal — it's written exactly once at `complete` and is
absent on a crash (a crashed agent leaves `status:running` forever, which is the current live state).

### 7.3 Refresh actually resets the state that biases scores (red-team fix)

- **Scored runs default to ephemeral-namespace-per-run or PVC-delete (Tier-2)** — not in-place Tier-1.
- **Recreate the Kong pod every reset** so `policy:local` rate-limit counters are provably zero
  (a warm limiter mislabels a fresh brute-force as `mitigated`). `seed-check` fires one request and asserts no 429.
- **Reset `oob-listener` / `canary-http` stores** so accumulated hits don't pre-classify the next run.
- **Seed per-run canary entropy into Postgres rows** (resettable in <20s, no pod restart) rather than env-var
  Secrets that force a 30–60s rolling restart. Rotate `JWT_SECRET` (needs restart) only when it's under test.
- `startupProbe` instead of the blog's 30s `initialDelaySeconds` liveness probe → ~10s readiness.
- **`seed-check.sh` is fail-closed**: asserts every canary armed + reachable per profile, baseline rows
  present, rate-limit counters zero, listeners empty — and **prints measured refresh wall-clock**. The
  acceptance criterion is an **identical seed-check signature**, *not* "byte-identical DB" (impossible —
  VulnBank uses `random.randint` for PINs/accounts).

### 7.4 N-run scoring with two gates (red-team fix)

- **Strict gate** — the `must_find` subset (deterministically-canaried, high-signal: SQLi-login,
  IDOR-balance, mass-assign `is_admin`, `/debug/users` creds dump): **TP in every one of N runs (hit-rate 100%)**.
  Any single miss = regression.
- **Trend set** — flaky-by-nature (blind/timing): rolling-window hit-rate with **hysteresis** (alert only on
  a sustained drop, e.g. 3 consecutive nights below baseline CI), never on one flaky night.
- Baselines stored as **per-vuln hit-rate distributions with confidence intervals**, captured at N≥10.
- Run agent-smith with **explicit caps** (`max_time_minutes`, `max_cost_usd`) — `depth=thorough` is uncapped.

### 7.5 Oracle self-test (meta-determinism, red-team fix)

A fixture test runs `score.py` **twice over the same frozen snapshot** (the existing 37-finding
`findings.json` + a canned `oracle-pg` dump) and asserts **byte-identical `scorecard.json`** (modulo
run_id/timestamp). If the scorer isn't idempotent over fixed input, no downstream signal is trustworthy.

---

## 8. Redeploy, refresh, teardown & cost

### 8.1 Three refresh tiers

| Tier | Command | Time | Use |
|---|---|---|---|
| 1 | `make refresh` | ~10–20s (DB reseed + canary rows + listener reset + Kong pod recreate) | interactive dev |
| 2 | `make reseed-hard` | ~30–60s (delete Postgres PVC / recreate; **default for scored runs**) | scored runs |
| 3 | `make up` / `make down` | 4–8 min DOKS (full `terraform apply/destroy`) | infra change / fresh cluster |

### 8.2 Safety: the box must NOT be world-readable (red-team CRITICAL fix)

DOKS auto-opens NodePorts `30000-32767` to **0.0.0.0/0** via a whitelist-only managed firewall you can't
DENY into and whose edits the reconciler reverts. We add a **separate tag-targeted firewall** (not watched by
the reconciler):

```hcl
variable "allowed_source_cidrs" {
  type = list(string)            # operator IP + CI/agent-smith droplet egress IP
  # NO default — must be set explicitly
  validation {
    condition     = !contains(var.allowed_source_cidrs, "0.0.0.0/0")
    error_message = "Refusing to expose an intentionally-vulnerable bank to the whole internet."
  }
}
resource "digitalocean_kubernetes_cluster" "lab" {
  ha = false                                  # never silently pay +$40/mo HA
  destroy_all_associated_resources = true     # kill orphaned LBs/volumes on destroy
  node_pool { tags = ["vulnbank-lab"] }
}
resource "digitalocean_firewall" "lab_lock" {
  tags = ["vulnbank-lab"]
  inbound_rule { protocol="tcp"; port_range="30000-32767"; source_addresses=var.allowed_source_cidrs }
}
```

Plus: a **TTL kill-switch** (cron/`at` destroying any lab older than N hours), a **dedicated DO project +
scoped PAT** to bound blast radius, **remote encrypted Terraform state** (DO Spaces + SOPS/age — state holds
the DO token + kubeconfig in plaintext), and — critically — the Phase-6 DO-metadata canary is a
**fake/honeytoken or scoped read-only instantly-revocable** token, **never a live account key**.

### 8.3 Teardown engineered to $0 (red-team fix)

`destroy_all_associated_resources=true` + pre-destroy `kubectl delete -k overlays/hardened` (lets the CCM
clean LB-backed Services) + `make verify-zero` (a CI gate asserting `doctl` shows no lab-tagged
LB/volume/firewall/cluster) + an out-of-band reaper cron for anything older than 2h.

### 8.4 Honest cost table (red-team correction)

| Path | Compute | Registry | Total standing | Notes |
|---|---|---|---|---|
| **DOKS (chosen, non-HA)** | 2× $24 nodes = $48 | DOCR Basic $5 (image > 500 MiB Starter cap) | **~$53/mo** | No LoadBalancer (NodePort only) → avoid +$12 each. `doctl registry garbage-collection` in `build-push.sh` so the never-delete digest strategy stays under cap. |
| DOKS ephemeral | ~$0.07/30-min run | $5 | per-run | Use only when scoring the cloud/k8s surface. |
| droplet+k3s (fallback) | $24 | $0 (`ctr import`) | $24/mo | Half cost; less cloud surface; Cilium mandatory. |

Hybrid CI uses a **persistent firewall-locked cluster + `make refresh`** as the per-run reset — the cluster
is recreated only weekly or on infra-code change (avoids slow/flaky DOKS provision and destroy-leak in the hot path).

### 8.5 DNS / TLS (red-team fix)

Automated path targets the **raw node IP:NodePort** (deterministic, no third-party dep) — **not** `nip.io`
(no SLA, resolver blocklisting). The `kong-proxy` cert SANs are **templated from a Terraform output**
(actual node IP at deploy time), not the blog's hardcoded `127.0.0.1` SAN that breaks on every recreate.

### 8.6 Image pipeline

`doctl registry create vulnbank-lab`; build lab image (VulnBank + observer middleware), push to DOCR with an
**immutable digest-pinned tag** (`vuln-bank:seed-v1@sha256:…`, never `latest`), `imagePullPolicy:IfNotPresent`.
`doctl kubernetes cluster registry add` injects the pull secret. Rebuild only on an intentional vuln-set bump.

---

## 9. Scope extensions (the 4, coverage-per-effort)

| # | Extension | Unlocks skill | Effort | Oracle proof |
|---|---|---|---|---|
| 1 | **DO-metadata SSRF** — SSRF pivot to `169.254.169.254/metadata/v1` with a planted **honeytoken** | `/cloud-security` | ~0 (free on DOKS) | Falco eBPF IMDS-connect + mock-IMDS access log |
| 2 | **k8s-misconfig pack** — over-privileged ServiceAccount + privileged/hostPath pod + read-only kubelet | `/container-k8s-security` | medium | Falco/Tetragon shell-in-pod + SA-token read |
| 3 | **`kong-admin-exposed` profile** — Kong admin API on a NodePort | `/api-security` | ~0 | Kong admin access log |
| 4 | **Graded multi-turn prompt-injection** target (gated jailbreak, not the trivially-leaking system prompt) | `/ai-redteam` discriminates skill | low | AI-canary secret echo only on a real multi-turn jailbreak |

Skipped as gold-plating: AD / lateral-movement / network-assess.

---

## 10. Repo layout

```
lab-benchmark/
  Makefile                  # up / down / refresh / reseed-hard / bench / score / urls / verify-zero
  ground_truth.yaml         # ~22+ vulns × endpoint × class × per-profile exposure × oracle_signals
  versions.txt              # pinned image digest · agent-smith commit · LLM-judge model id · baseline id
  docs/notion-guide.md      # archived source guide
  terraform/
    modules/{doks,droplet-k3s,droplet-kind,docr}/
    envs/{doks.tfvars,ephemeral.tfvars,...}        # allowed_source_cidrs REQUIRED, no default
  image/
    Dockerfile.lab          # VulnBank base + baked observer middleware (non-behavior-altering)
    middleware/observer.py  # before/after_request → stdout proof events
    build-push.sh           # build, push DOCR, GC old digests, write digest to versions.txt
  k8s/                      # kustomize
    base/{namespaces,postgres,vuln-bank,canary-http}/
    overlays/{raw,hardened,kong-admin-exposed}/
    components/{kong-dbless,cert-manager,networkpolicies,pgaudit,falco,k8s-misconfig}/
  oracle/
    ns/                     # oracle-postgres · oob-listener · canary-http · xss-render worker
    scorer/                 # registry.py · parse_artifacts.py · canonicalize.py · match_tier1.py
                            # match_tier2_llm.py (cached) · signals.py · fuse.py · score.py · emit.py
    sql/                    # oracle-postgres schema + DB triggers (neg-transfer/neg-loan)
    jobs/{seed-job,fusion-job}.yaml
    baselines/              # per-agent-smith-version hit-rate distributions
    tests/                  # canonicalizer golden-file test · oracle idempotency self-test
  scripts/
    refresh.sh · reseed-hard.sh · seed-check.sh (fail-closed)
    emit-target.sh · run-benchmark.sh · poll-completion.sh (state machine)
  runs/                     # gitignored per-run snapshots runs/<profile>/<session_id>_<ts>/
  .github/workflows/nightly-regression.yml
```

---

## 11. Phased implementation plan

Each phase has a concrete acceptance check (corrected per the red-team).

### Phase 0 — Ground truth + repo skeleton (no infra)
Build `ground_truth.yaml` (~22+ deduped vulns, each with normalized endpoint, per-profile `exposure`,
`oracle_signals`, `match_hints`, cited source line). Scaffold the repo. Write the oracle canonicalizer +
the golden-file contract test against agent-smith's vendored normalizer.
**Accept:** `registry --validate` passes; canonicalizer unit tests pass; replaying the *existing* 37-finding
`findings.json` through the parser maps to ground-truth IDs and dedups to ~22.

### Phase 1 — Local deploy + image pipeline
Build the lab image (+ observer middleware), push to DOCR with a captured digest. Stand up `base` +
`overlays/raw` locally. Confirm `init_db()` seeds, and `/login` SQLi, `/debug/users`, `/internal/secret`
(loopback) behave per catalog.
**Accept:** `kubectl apply -k overlays/raw` brings the app up; manual SQLi on `/login` returns an admin JWT;
`/debug/users` returns `admin/admin123`; image is digest-pinned.

### Phase 2 — Both profiles + DOKS infra (Terraform)
`terraform/modules/doks` (+ DOCR binding, **mandatory `allowed_source_cidrs` firewall**, `ha=false`,
`destroy_all_associated_resources=true`), `overlays/hardened` (Kong + cert-manager + restrictive netpol +
TLS, cert SANs from TF output). Wire `make up/down`, `emit-target.sh` (node-IP URLs). Probe `hubble status`.
**Accept:** both profile URLs resolve **only from `allowed_source_cidrs`**; `curl raw/internal/secret` leaks,
`curl hardened/internal/secret` → Kong 404; rate-limit 429 fires on hardened; `make verify-zero` after
`make down` shows zero lab-tagged resources.

### Phase 3 — Deterministic refresh + fail-closed preflight
`refresh.sh` (Tier-1), `reseed-hard.sh` (Tier-2, default for scored), `seed-check.sh` (fail-closed: canaries
armed+reachable, baseline rows, **Kong counters zero**, listeners empty, prints wall-clock). Ephemeral DB;
per-run canary tokens into Postgres rows.
**Accept:** `make reseed-hard` returns to **identical seed-check signature**; running twice yields identical
signature; `seed-check` exits non-zero if a canary is removed or a Kong counter is warm.

### Phase 4 — Oracle: signals + parsing + scoring
Stand up `oracle` ns (oracle-postgres, canary-http, oob-listener, **xss-render worker**). Wire observer
middleware, pgaudit, Kong http-log, **DB triggers** (neg-transfer/neg-loan), Falco. Build the scorer:
Tier-1 matcher, oracle active-probes (CORS/headers/JWT-exp), signal joins, fusion confusion model, two
recall numbers, `scorecard.json/.md`. Add the cached Tier-2 LLM-judge. Add the **idempotency self-test**.
**Accept:** replay the 37-finding artifacts → scorer dedups to ~22 IDs, computes deterministic + adjudicated
recall/precision/FN, flags `new_vuln_candidates`; canary round-trips classify SQLi/SSRF/IDOR as
proves-exploit TPs; scorer is byte-idempotent over the frozen snapshot.

### Phase 5 — End-to-end harness + hybrid regression gate
`run-benchmark.sh` (snapshot+clear → reseed → run per profile → **state-machine poll** → snapshot to
`runs/` → score), baseline storage (N≥10 hit-rate distributions), strict + trend gates. Persistent
firewall-locked cluster; `nightly-regression.yml` asserts must-find subset at 100% hit-rate + no reachable
vuln flips TP→FN, surfacing failures as `ORACLE_REGRESSION`.
**Accept:** one `make bench` does a full clean run against both profiles → profile-aware scorecard with
deltas vs baseline; CI fails on an injected regression (a must-find vuln removed from reachability) and
passes clean; an aborted/partial run is marked UNSCORABLE, not a regression.

### Phase 6 — Scope extensions
Add the 4 extensions (§9) in ROI order, each with `ground_truth.yaml` entries + canaries + a Falco/probe proof.
**Accept:** each addition raises distinct-skills-exercised and produces a scorable TP/FN cell; new
injection types appear in agent-smith's `coverage_matrix.json`.

---

## 12. Risk register (red-team findings → mitigations)

| # | Risk | Sev | Mitigation (where in plan) |
|---|---|---|---|
| 1 | **Internet-exposed vuln bank** — DOKS NodePort opens to 0.0.0.0/0 | **Critical** | Tag-targeted firewall, `allowed_source_cidrs` no-default + validation, TTL kill-switch (§8.2) |
| 2 | **Live cloud creds as canary** — Phase-6 DO token exfiltratable | **Critical** | Honeytoken / scoped read-only revocable only; dedicated project + scoped PAT (§8.2, §9) |
| 3 | **Balance-conservation detector is mathematically wrong** — blind to neg-transfer theft & neg-loan | High | Per-vuln DB triggers on `amount<0`; conservation only for non-existent-recipient mint (§6.1) |
| 4 | **Path-match key fails on real data** — `{account_number}` vs `{id}`, query strings survive | High | Oracle-owned canonicalizer; match on `(method, class)`; vendored normalizer + golden test (§6.4) |
| 5 | **SSRF is blind** — body not echoed, token round-trip impossible | High | canary-http access log as primary proof; `blind` tag per variant (§6.1) |
| 6 | **Run isolation broken** — no run_id, timestamps outside session window | High | Snapshot-as-unit-of-scoring; canary-token-in-evidence attribution; optional meta stamp (§7.1) |
| 7 | **Completion poll deadlocks** on crash/limit/incomplete | High | State-machine poll + hard wall-clock timeout → ABORT (§7.2) |
| 8 | **LLM judge moves the headline number** | High | Deterministic signals authoritative; judge off counting path; cached + pinned; two recall numbers (§6.4, §6.7) |
| 9 | **Refresh leaks state** — warm Kong counters, accumulated listener hits | High | Recreate Kong pod + reset listeners + seed-check asserts counter=0 (§7.3) |
| 10 | **Unobservable config vulns** (CORS/headers/JWT-exp) | Med | Oracle-owned active probes (§6.3) |
| 11 | **Stored-XSS never fires** — agent-smith has no browser | Med | `xss-render` worker in oracle ns; else downgrade to reported-only (§6.1) |
| 12 | **Teardown leaks $$** — orphaned LBs/volumes | High | `destroy_all_associated_resources`; pre-destroy delete; `make verify-zero`; reaper (§8.3) |
| 13 | **Hubble assumed available** on DOKS | Med | Demoted to optional; Kong+canary logs primary; `hubble status` probe (§6.6) |
| 14 | **nip.io flakiness + cert SAN drift** on recreate | Med | Node-IP target; cert SANs from TF output (§8.5) |
| 15 | **Uncapped agent-smith** (depth=thorough) scans whole node, trips DO abuse | Med | Cap `max_time`/`max_cost`; target specific NodePort URL; run agent-smith from same-VPC droplet (§7.4, §8.2) |
| 16 | **N-run gate noise** — flaky vulns spam false regressions | Med | Strict (must-find 100%) vs trend (hysteresis) gates; baselines as distributions (§7.4) |
| 17 | **Canary cross-contamination** within a run | Med | Single-purpose, path-bound canaries; anti-canary; FP needs positive evidence (§6.5) |
| 18 | **Legacy SQLite routes** present-but-broken at runtime | Low | Tagged `runtime: source-only` (§5.2) |
| 19 | **DOCR 500 MiB cap** blown by never-delete digests | Low | DOCR Basic budgeted; GC in `build-push.sh` (§8.4) |
| 20 | **Secrets in TF state** (DO token, kubeconfig, DB pw) | Med | Remote encrypted state (DO Spaces + SOPS/age); dedicated scoped PAT (§8.2) |

---

## 13. What I need from you before Phase 1

1. **DO access** — a `doctl`/Terraform DO API token scoped to a **dedicated DO project** for the lab, and
   your **source CIDR(s)** for `allowed_source_cidrs` (your workstation egress IP + where agent-smith runs).
2. **agent-smith run convention** — confirm the invocation we'll standardize for scored runs
   (e.g. `session(action=start, depth=…, max_time_minutes, max_cost_usd)` against the raw/hardened NodePort URL),
   and whether you're OK with a **one-line patch** to `core/findings._save` to stamp `meta.session_id` (makes
   snapshots self-describing; optional — the canary-token attribution works without it).
3. **Anthropic key** for the Tier-2 LLM-judge matcher (off the counting path; cached).

---

## 14. Suggested first step

**Phase 0 is pure local work with zero infra and zero cost** — it produces `ground_truth.yaml` and the
scorer skeleton, and immediately *proves value* by replaying your existing 37-finding `findings.json`
through the parser to show the dedup-to-~22 and a first recall/FN read. I recommend starting there while you
provision the DO project + token in parallel.

> *Re-using the blog's own framing:* "The vulnerability in the code hasn't changed. The control around it
> has." Our addition: **and now we can prove, every time agent-smith changes, whether it still sees through
> the control to the vulnerability beneath.**
