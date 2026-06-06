"""Ingest server-side PROOF events and map them to ground-truth vuln ids.

Sources (all reduced to one event stream):
  * observer middleware  -> ``LAB_EVENT {json}`` lines on the app pod's stdout
  * canary-http          -> ``LAB_EVENT {"type":"CANARY_HIT",...}`` lines
  * Postgres DB triggers -> rows exported as ``{"type":"DB_NEG_TRANSFER_ROW",...}``
  * Kong file-log        -> request lines (404 on a blocked route / 429 rate-limit)

Each event becomes one or more Signal(gt_id, strength). Strength tiers:
  * proves-exploit  — the vuln was demonstrably exploited (canary reached, creds
                      endpoint hit, cross-account read, persisted bad row, ...)
  * proves-attempt  — the attack was attempted/observed but success not yet confirmed
                      at this layer (request-level payload; upgrade via DB/canary/pgaudit)

This module is PURE + deterministic: same events in -> same signals out.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field

_STRENGTH_RANK = {"proves-attempt": 1, "proves-exploit": 2}

# path prefix -> SQLi ground-truth id (for SQLI_SIGNAL / pgaudit events)
_SQLI_PATH = {
    "/login": "VB-SQLI-LOGIN",
    "/check_balance": "VB-SQLI-CHECK-BALANCE",
    "/transactions": "VB-SQLI-TRANSACTIONS-PATH",
    "/api/transactions": "VB-SQLI-API-TRANSACTIONS",
    "/admin/create_admin": "VB-SQLI-CREATE-ADMIN",
    "/api/billers": "VB-SQLI-BILLERS",
    "/api/virtual-cards": "VB-SQLI-VIRTUAL-CARDS",
    "/api/v1/merchants": "VB-SQLI-MERCHANT",
    "/api/v1/payments": "VB-SQLI-MERCHANT",
    "/graphql": "VB-SQLI-GRAPHQL",
}


@dataclass
class Signal:
    gt_id: str
    strength: str
    event_type: str
    evidence: dict = field(default_factory=dict)


def _sqli_id_for(path: str) -> str | None:
    p = (path or "").lower()
    # longest prefix wins (so /api/transactions beats /transactions)
    best = None
    for prefix, vid in _SQLI_PATH.items():
        if p == prefix or p.startswith(prefix + "/") or p.startswith(prefix + "?") or p.startswith(prefix):
            if best is None or len(prefix) > best[0]:
                best = (len(prefix), vid)
    return best[1] if best else None


def classify_event(ev: dict) -> list[Signal]:
    t = ev.get("type", "")
    path = (ev.get("path") or "").lower()
    out: list[Signal] = []

    def add(gt_id, strength):
        if gt_id:
            out.append(Signal(gt_id, strength, t, {k: ev.get(k) for k in ("src", "path", "target", "actor", "reason") if ev.get(k) is not None}))

    if t == "CANARY_HIT":
        # the app's server-side fetch reached the internal canary -> SSRF fired (blind-proof)
        add("VB-SSRF-PROFILE-URL", "proves-exploit")
    elif t == "SSRF_ATTEMPT":
        tc = ev.get("target_class")
        if tc == "metadata":
            add("VB-SSRF-CLOUD-METADATA", "proves-attempt")
        elif tc == "internal":
            add("VB-SSRF-PROFILE-URL", "proves-attempt")
            add("VB-SSRF-INTERNAL-SECRET", "proves-attempt")
        else:
            add("VB-SSRF-PROFILE-URL", "proves-attempt")
    elif t in ("DB_NEG_TRANSFER_ROW",):
        add("VB-BL-NEG-TRANSFER", "proves-exploit")
    elif t in ("DB_ZERO_TRANSFER_ROW",):
        add("VB-BL-ZERO-TRANSFER", "proves-exploit")
    elif t in ("DB_NEG_LOAN_ROW",):
        add("VB-BL-NEG-LOAN", "proves-exploit")
    elif t == "NEG_TRANSFER":
        add("VB-BL-NEG-TRANSFER", "proves-attempt")
    elif t == "ZERO_TRANSFER":
        add("VB-BL-ZERO-TRANSFER", "proves-attempt")
    elif t == "NEG_LOAN":
        add("VB-BL-NEG-LOAN", "proves-attempt")
    elif t == "MASS_ASSIGN":
        add("VB-MASSASSIGN-REGISTER", "proves-attempt")
    elif t == "JWT_FORGED":
        add("VB-JWT-NONE-ALG", "proves-attempt")   # upgrade to exploit if the request returned 2xx
    elif t == "JWT_NO_EXP_USED":
        add("VB-JWT-NO-EXPIRY", "proves-attempt")
    elif t == "DEBUG_USERS_ACCESS":
        add("VB-DEBUG-USERS", "proves-exploit")    # endpoint dumps all creds; access == disclosure
    elif t == "ADMIN_ACCESS":
        if "create_admin" in path:
            add("VB-SQLI-CREATE-ADMIN", "proves-attempt")
        elif "sup3r_s3cr3t" in path:
            add("VB-HIDDEN-ADMIN", "proves-exploit")
        else:
            add("VB-HIDDEN-ADMIN", "proves-attempt")
    elif t == "AI_INJECTION_ATTEMPT":
        add("VB-AI-PROMPT-INJECTION", "proves-attempt")
        if ev.get("rate_bypass"):
            add("VB-AI-RATE-LIMIT-BYPASS", "proves-attempt")
    elif t == "AI_CANARY_ECHO":
        add("VB-AI-PROMPT-INJECTION", "proves-exploit")
    elif t == "SQLI_SIGNAL":
        add(_sqli_id_for(path), "proves-attempt")
    elif t == "DB_SQLI_EXEC":          # pgaudit: injected UNION/tautology executed
        add(_sqli_id_for(path), "proves-exploit")
    elif t == "BRUTE_FORCE":
        add("VB-NO-LOCKOUT-LOGIN", "proves-attempt")
    elif t == "BRUTE_FORCE_PIN":
        add("VB-WEAK-PIN-RESET", "proves-attempt")
    elif t == "ACCOUNT_ACCESS":
        authed = ev.get("authenticated")
        target = str(ev.get("target", ""))
        own = ev.get("actor_account")
        cross = authed and own is not None and target and str(own) != target
        if "/api/v3/user/" in path:
            add("VB-IDOR-API-V3-USER", "proves-exploit" if cross else "proves-attempt")
        elif not authed:
            add("VB-BOLA-TXN-NOAUTH", "proves-exploit")   # account-scoped GET without a token
        elif cross:
            add("VB-BOLA-TXN-NOAUTH", "proves-exploit")
    elif t == "KONG_BLOCKED":          # Kong 404 on a request-termination route
        add(ev.get("gt_id"), "proves-attempt")
    return out


def load_events(path: str) -> list[dict]:
    """Read a proof-event stream: JSONL (optionally 'LAB_EVENT '-prefixed) or a JSON array."""
    events: list[dict] = []
    with open(path) as fh:
        content = fh.read().strip()
    if content.startswith("["):
        return [e for e in json.loads(content) if isinstance(e, dict)]
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("LAB_EVENT "):
            line = line[len("LAB_EVENT "):]
        if not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def collect_signals(events: list[dict], run_id: str | None = None) -> dict[str, dict]:
    """Reduce events to {gt_id: {strength, count, event_types, evidence[]}}, best strength wins.

    If run_id is given, only events tagged with that run_id are counted (per-run isolation)."""
    agg: dict[str, dict] = defaultdict(lambda: {"strength": None, "count": 0, "event_types": set(), "evidence": []})
    for ev in events:
        if run_id is not None and ev.get("run_id") not in (run_id, None):
            continue
        for sig in classify_event(ev):
            a = agg[sig.gt_id]
            a["count"] += 1
            a["event_types"].add(sig.event_type)
            if len(a["evidence"]) < 5:
                a["evidence"].append({"type": sig.event_type, **sig.evidence})
            if a["strength"] is None or _STRENGTH_RANK[sig.strength] > _STRENGTH_RANK[a["strength"]]:
                a["strength"] = sig.strength
    # freeze sets to sorted lists for determinism
    return {k: {**v, "event_types": sorted(v["event_types"])} for k, v in sorted(agg.items())}
