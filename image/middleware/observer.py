"""Lab observer middleware — the oracle's highest-value runtime signal source.

Baked into the LAB image variant only (never upstream VulnBank). It registers
Flask before/after_request hooks that INSPECT traffic and emit structured proof
events to stdout as ``LAB_EVENT {json}`` lines. A Phase-4 ingester ships these to
oracle-postgres; the scorer joins them against ground_truth.yaml.

HARD INVARIANT: this middleware is READ-ONLY and MUST NOT change app behavior.
  * before_request returns None (never short-circuits a request)
  * after_request returns the response object completely unmodified
  * every hook is wrapped so an observer bug can never break the app or leak a 500
Phase 0/1 events are attempt-level (HTTP layer). Exploit-level proof (canary
round-trip, pgaudit executed-SQL, DB triggers) is wired in Phase 4.
"""
from __future__ import annotations

import base64
import json
import os
import time
from collections import defaultdict, deque

try:
    from flask import g, request
except Exception:  # pragma: no cover - only meaningful inside the app image
    request = None  # type: ignore
    g = None  # type: ignore

_RUN_ID = os.getenv("LAB_RUN_ID", "dev")
_PROFILE = os.getenv("LAB_PROFILE", "raw")

# injectable endpoints (path prefix) -> the param(s) that reach a SQL sink
_SQLI_ENDPOINTS = ("/login", "/check_balance", "/transactions", "/api/transactions",
                   "/admin/create_admin", "/api/billers", "/api/virtual-cards",
                   "/api/v1/merchants", "/api/v1/payments", "/graphql")
_SQLI_TOKENS = ("' or ", "' or'", "'='", "union select", "--", "/*", " or 1=1", "';", "sleep(", "pg_sleep")
_AI_INJECTION_TOKENS = ("ignore previous", "ignore all previous", "system prompt", "you are now",
                        "disregard", "reveal your", "developer mode", "do anything")
_INTERNAL_SSRF_HINTS = ("127.0.0.1", "localhost", "169.254.169.254", "metadata", "/internal",
                        "canary.internal", "kubernetes.default", "10.", "172.", "192.168.",
                        ".svc", "postgres")

# brute-force counters: (src, bucket) -> deque[timestamps]
_ATTEMPTS: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=200))
_BRUTE_WINDOW = 60.0
_BRUTE_THRESHOLD = 10


def _emit(event_type: str, **fields) -> None:
    try:
        rec = {"ts": round(time.time(), 3), "run_id": _RUN_ID, "profile": _PROFILE,
               "type": event_type}
        rec.update({k: v for k, v in fields.items() if v is not None})
        print("LAB_EVENT " + json.dumps(rec, separators=(",", ":")), flush=True)
    except Exception:
        pass  # never let logging break the request


def _src() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or (request.remote_addr or "")


def _jwt_info() -> dict | None:
    """Decode (NOT verify) a bearer/cookie/query JWT to attribute the actor and
    catch alg=none forgery. Verification-bypass is itself part of the vuln set, so
    we only read the header/payload."""
    tok = ""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        tok = auth[7:].strip()
    tok = tok or request.args.get("token", "") or request.form.get("token", "") \
        or request.cookies.get("token", "")
    if tok.count(".") != 2:
        return None
    try:
        h_b64, p_b64, _sig = tok.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(h_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(p_b64)))
        return {"alg": header.get("alg"), "user_id": payload.get("user_id"),
                "username": payload.get("username"), "is_admin": payload.get("is_admin"),
                "account_number": payload.get("account_number"), "has_exp": "exp" in payload}
    except Exception:
        return None


def _values() -> dict:
    out = {}
    try:
        out.update({k: v for k, v in request.args.items()})
    except Exception:
        pass
    try:
        out.update({k: v for k, v in request.form.items()})
    except Exception:
        pass
    try:
        j = request.get_json(silent=True)
        if isinstance(j, dict):
            out.update({k: (v if isinstance(v, (str, int, float, bool)) else json.dumps(v))
                        for k, v in j.items()})
    except Exception:
        pass
    return out


def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _brute(src: str, bucket: str) -> int:
    now = time.time()
    dq = _ATTEMPTS[(src, bucket)]
    dq.append(now)
    while dq and now - dq[0] > _BRUTE_WINDOW:
        dq.popleft()
    return len(dq)


def _inspect() -> None:
    path = request.path or ""
    method = request.method
    src = _src()
    vals = _values()
    lower_vals = {k.lower(): (str(v).lower() if v is not None else "") for k, v in vals.items()}

    # --- JWT forgery / actor attribution
    jwt = _jwt_info()
    if jwt:
        if (jwt.get("alg") or "").lower() in ("none", ""):
            _emit("JWT_FORGED", reason="alg_none", path=path, src=src, actor=jwt.get("username"))
        if jwt.get("has_exp") is False:
            _emit("JWT_NO_EXP_USED", path=path, src=src, actor=jwt.get("username"))

    # --- business logic: negative / zero amounts
    if method == "POST" and path == "/transfer":
        amt = _num(vals.get("amount"))
        if amt is not None and amt < 0:
            _emit("NEG_TRANSFER", path=path, src=src, amount=amt, actor=(jwt or {}).get("username"))
        elif amt is not None and amt == 0:
            _emit("ZERO_TRANSFER", path=path, src=src, amount=amt)
    if method == "POST" and path == "/request_loan":
        amt = _num(vals.get("amount"))
        if amt is not None and amt < 0:
            _emit("NEG_LOAN", path=path, src=src, amount=amt)

    # --- mass assignment on register
    if method == "POST" and path == "/register":
        extra = [k for k in ("is_admin", "balance", "role", "account_number") if k in lower_vals]
        if extra:
            _emit("MASS_ASSIGN", path=path, src=src, injected_fields=extra)

    # --- SSRF attempt classification
    if method == "POST" and path == "/upload_profile_picture_url":
        url = str(vals.get("image_url", "")).lower()
        if url:
            internal = any(h in url for h in _INTERNAL_SSRF_HINTS)
            target = "metadata" if ("169.254.169.254" in url or "metadata" in url) else (
                "internal" if internal else "external")
            _emit("SSRF_ATTEMPT", path=path, src=src, target_class=target, url=url[:200])

    # --- brute force on login / reset
    if method == "POST" and path in ("/login",):
        n = _brute(src, "login")
        if n >= _BRUTE_THRESHOLD:
            _emit("BRUTE_FORCE", path=path, src=src, attempts_in_window=n)
    if method == "POST" and ("reset-password" in path or "forgot-password" in path):
        n = _brute(src, "reset")
        if n >= _BRUTE_THRESHOLD:
            _emit("BRUTE_FORCE_PIN", path=path, src=src, attempts_in_window=n)

    # --- sensitive endpoint access
    if path == "/debug/users":
        _emit("DEBUG_USERS_ACCESS", path=path, src=src)
    if path == "/sup3r_s3cr3t_admin" or path.startswith("/admin/"):
        _emit("ADMIN_ACCESS", path=path, src=src, actor=(jwt or {}).get("username"),
              is_admin=(jwt or {}).get("is_admin"))

    # --- account-scoped access (for Phase-4 cross-account IDOR join)
    for prefix in ("/check_balance/", "/transactions/", "/api/v3/user/"):
        if path.startswith(prefix):
            target = path[len(prefix):]
            own = (jwt or {}).get("account_number")
            _emit("ACCOUNT_ACCESS", path=path, src=src, target=target,
                  actor=(jwt or {}).get("username"), actor_account=own,
                  authenticated=bool(jwt))

    # --- AI prompt-injection attempt
    if method == "POST" and path.startswith("/api/ai/"):
        blob = " ".join(str(v) for v in vals.values()).lower()
        if any(tok in blob for tok in _AI_INJECTION_TOKENS):
            _emit("AI_INJECTION_ATTEMPT", path=path, src=src,
                  rate_bypass=bool(request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP")))

    # --- SQLi signal (payload seen on an injectable endpoint; execution proof is Phase-4 pgaudit)
    if any(path.startswith(p) or path == p for p in _SQLI_ENDPOINTS):
        for k, v in lower_vals.items():
            if any(tok in v for tok in _SQLI_TOKENS):
                _emit("SQLI_SIGNAL", path=path, src=src, param=k, snippet=v[:120])
                break


def _before():
    try:
        _inspect()
    except Exception:
        pass
    return None  # NEVER short-circuit


def _after(response):
    # read-only: do not touch the response. (Phase 4 may correlate status/size out-of-band.)
    return response


def install(app) -> None:
    """Register the observer hooks on a Flask app. Idempotent."""
    if getattr(app, "_lab_observer_installed", False):
        return
    app.before_request(_before)
    app.after_request(_after)
    app._lab_observer_installed = True
    _emit("OBSERVER_INSTALLED", run_id=_RUN_ID, profile=_PROFILE)
