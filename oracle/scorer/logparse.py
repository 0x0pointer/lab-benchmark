"""Turn raw gateway/database logs into PROOF events that ``signals.py`` consumes.

Two sources, two pure parsers (same input -> same output, no timestamps in output):

  * Kong file-log plugin  -> ``parse_kong_log(lines)`` -> ``KONG_BLOCKED`` events.
        The file-log plugin emits one JSON object per request to stdout with (at least)
        ``request.uri`` (or ``request.url``) and ``response.status``. We emit a
        ``KONG_BLOCKED`` event when the gateway denied an attack:
          - status 404 on a request-termination route (/internal, /api/admin,
            /api/docs, /static/openapi.json)   -> probed-a-blocked-route
          - status 429 on a rate-limited route (/login, reset/forgot paths) -> brute mitigated
        Each gets a ``gt_id`` so ``signals.classify_event`` (which reads ev['gt_id'])
        maps it without extra logic.

  * Postgres ``log_statement=all`` -> ``parse_pg_log(lines)`` -> ``DB_SQLI_EXEC`` events
        when an EXECUTED statement carries an injection signature (UNION SELECT,
        ' OR '1'='1, a numeric/string tautology, or a ``--`` comment) against an app
        table. pg logs don't carry the HTTP path, so we infer it from the table
        (users -> /login, transactions -> /api/transactions) when possible and otherwise
        omit ``path`` (``signals._sqli_id_for`` already tolerates a missing path).

This module never imports the app or the network; it only transforms text. A small CLI
(``python3 -m oracle.scorer.logparse --kong`` / ``--pg``) reads log lines on stdin and
writes one JSON event per line, used by ``scripts/collect-events.sh``.
"""
from __future__ import annotations

import json
import re
import sys

# --------------------------------------------------------------------------- Kong
# request-termination routes (Kong returns 404; app never sees the request) -> gt_id.
# Order matters only for prefix matching; longest match wins below.
# NOTE: /api/admin is a Kong request-termination route too, but it maps to NO real vuln
# (the actual admin surface is /admin/* and /sup3r_s3cr3t_admin, which Kong does NOT block —
# see ground_truth.yaml meta). A 404 on /api/admin proves nothing, so it is intentionally
# absent here to avoid a spurious VB-HIDDEN-ADMIN signal.
_KONG_BLOCKED_404 = {
    "/api/docs": "VB-SWAGGER-EXPOSURE",
    "/static/openapi.json": "VB-SWAGGER-EXPOSURE",
    "/internal": "VB-SSRF-INTERNAL-SECRET",
}
# rate-limited routes (Kong returns 429) -> the brute-force vuln they compensate.
_KONG_RATELIMIT_429 = {
    "/login": "VB-NO-LOCKOUT-LOGIN",
    "/api/v1/reset-password": "VB-WEAK-PIN-RESET",
    "/api/v2/reset-password": "VB-WEAK-PIN-RESET",
    "/api/v3/reset-password": "VB-WEAK-PIN-RESET",
    "/api/v1/forgot-password": "VB-WEAK-PIN-RESET",
    "/api/v2/forgot-password": "VB-WEAK-PIN-RESET",
    "/api/v3/forgot-password": "VB-WEAK-PIN-RESET",
}


def _path_only(uri: str) -> str:
    """Strip scheme/host and query string -> just the path."""
    if not uri:
        return ""
    # request.url is a full URL; request.uri is already path(+query).
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+(/.*)?$", uri)
    if m:
        uri = m.group(1) or "/"
    return uri.split("?", 1)[0].split("#", 1)[0]


def _kong_gt_for(path: str, status: int) -> str | None:
    """Map a (path, status) gateway denial to a ground-truth id, longest-prefix wins."""
    table = _KONG_BLOCKED_404 if status == 404 else _KONG_RATELIMIT_429 if status == 429 else None
    if table is None:
        return None
    best: tuple[int, str] | None = None
    for prefix, gid in table.items():
        if path == prefix or path.startswith(prefix + "/"):
            if best is None or len(prefix) > best[0]:
                best = (len(prefix), gid)
    return best[1] if best else None


def parse_kong_log(lines) -> list[dict]:
    """Parse Kong file-log JSON lines -> KONG_BLOCKED events.

    Each input line is one JSON object (the file-log plugin's per-request record).
    We emit one ``KONG_BLOCKED`` event per request that the gateway denied (404 on a
    blocked route, or 429 rate-limit on an auth/reset route)."""
    out: list[dict] = []
    for raw in _iter_lines(lines):
        try:
            rec = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        req = rec.get("request") or {}
        resp = rec.get("response") or {}
        uri = req.get("uri") or req.get("url") or rec.get("upstream_uri") or ""
        status = resp.get("status", rec.get("status"))
        try:
            status = int(status)
        except (TypeError, ValueError):
            continue
        if status not in (404, 429):
            continue
        path = _path_only(uri)
        gt_id = _kong_gt_for(path, status)
        if gt_id is None:
            continue
        out.append({"type": "KONG_BLOCKED", "path": path, "status": status, "gt_id": gt_id})
    return out


# ----------------------------------------------------------------------- Postgres
# table -> the HTTP path the SQLi rides in on (so signals._sqli_id_for can route it).
_TABLE_PATH = {
    "users": "/login",
    "transactions": "/api/transactions",
    "accounts": "/check_balance",
    "billers": "/api/billers",
    "virtual_cards": "/api/virtual-cards",
    "merchants": "/api/v1/merchants",
}
# app tables we recognise an injection against (a real injected statement touches one).
_APP_TABLES = tuple(_TABLE_PATH.keys())

# injection signatures (case-insensitive) — a statement that ACTUALLY EXECUTED with one
# of these is proof the injection reached the DB, not just an attempted payload.
_SQLI_SIGS = (
    re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
    re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1", re.IGNORECASE),   # ' OR '1'='1  /  ' OR 1=1
    re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.IGNORECASE),     # OR 1=1 tautology
    re.compile(r"--", re.IGNORECASE),                          # SQL line comment
    re.compile(r"\bsleep\s*\(", re.IGNORECASE),               # time-based blind
    re.compile(r"pg_sleep\s*\(", re.IGNORECASE),
)

# Postgres logs an executed statement as: "... LOG:  statement: <sql>" (log_statement=all)
# or "... LOG:  execute <name>: <sql>" for prepared statements.
_PG_STMT = re.compile(r"\b(?:statement|execute(?:\s+\S+)?)\s*:\s*(.*)$", re.IGNORECASE)


def _looks_like_sqli(sql: str) -> bool:
    return any(sig.search(sql) for sig in _SQLI_SIGS)


def _table_in(sql: str) -> str | None:
    """The app table the injection rides on = the EARLIEST app table named in the
    statement (the primary FROM target precedes any appended ``UNION SELECT ... FROM x``),
    so a UNION that exfiltrates ``users`` via ``FROM transactions`` is attributed to
    ``transactions``. Word-boundary so "users" doesn't fire on "user_sessions"."""
    low = sql.lower()
    best: tuple[int, str] | None = None
    for tbl in _APP_TABLES:
        m = re.search(r"\b" + re.escape(tbl) + r"\b", low)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), tbl)
    return best[1] if best else None


def parse_pg_log(lines) -> list[dict]:
    """Parse Postgres ``log_statement=all`` output -> DB_SQLI_EXEC events.

    Emit one ``DB_SQLI_EXEC`` per executed statement that carries an injection signature
    against a known app table. ``path`` is inferred from the table when possible, else
    omitted (signals._sqli_id_for handles a missing path)."""
    out: list[dict] = []
    for raw in _iter_lines(lines):
        m = _PG_STMT.search(raw)
        sql = m.group(1).strip() if m else raw.strip()
        if not sql or not _looks_like_sqli(sql):
            continue
        tbl = _table_in(sql)
        if tbl is None:
            continue
        ev: dict = {"type": "DB_SQLI_EXEC"}
        path = _TABLE_PATH.get(tbl)
        if path:
            ev["path"] = path
        out.append(ev)
    return out


# --------------------------------------------------------------------------- CLI
def _iter_lines(lines):
    """Accept a string (split on newlines) or any iterable of lines; drop blanks."""
    if isinstance(lines, str):
        lines = lines.splitlines()
    for ln in lines:
        ln = ln.rstrip("\n")
        if ln.strip():
            yield ln


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="oracle.scorer.logparse",
        description="Turn Kong/Postgres logs (stdin) into proof events (json lines, stdout).",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--kong", action="store_true", help="parse Kong file-log JSON -> KONG_BLOCKED events")
    g.add_argument("--pg", action="store_true", help="parse Postgres log_statement -> DB_SQLI_EXEC events")
    p.add_argument("--run-id", default=None, help="stamp each emitted event with this run_id")
    args = p.parse_args(argv)

    events = parse_kong_log(sys.stdin) if args.kong else parse_pg_log(sys.stdin)
    for ev in events:
        if args.run_id is not None:
            ev = {**ev, "run_id": args.run_id}
        sys.stdout.write(json.dumps(ev, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
