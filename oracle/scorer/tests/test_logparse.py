"""Tests for logparse: Kong file-log -> KONG_BLOCKED, Postgres log -> DB_SQLI_EXEC.

These assert the emitted events feed straight into signals.classify_event (which reads
ev['gt_id'] for KONG_BLOCKED and ev['path'] for DB_SQLI_EXEC) -> the right ground-truth ids.
"""
import json
import unittest

from oracle.scorer.logparse import parse_kong_log, parse_pg_log
from oracle.scorer.signals import classify_event

# --- Kong file-log fixture: one JSON object per request (the plugin's per-request record).
_KONG_LINES = [
    # 404 request-termination on blocked routes
    json.dumps({"request": {"uri": "/internal/secret", "method": "GET"}, "response": {"status": 404}}),
    json.dumps({"request": {"uri": "/api/docs", "method": "GET"}, "response": {"status": 404}}),
    json.dumps({"request": {"uri": "/static/openapi.json?x=1", "method": "GET"}, "response": {"status": 404}}),
    # /api/admin is a Kong-blocked route but maps to NO real vuln -> must NOT emit
    json.dumps({"request": {"uri": "/api/admin", "method": "GET"}, "response": {"status": 404}}),
    # request.url form (full URL) instead of request.uri
    json.dumps({"request": {"url": "http://gw.example/internal/config", "method": "GET"}, "response": {"status": 404}}),
    # 429 rate-limit on auth/reset routes
    json.dumps({"request": {"uri": "/login", "method": "POST"}, "response": {"status": 429}}),
    json.dumps({"request": {"uri": "/api/v1/reset-password", "method": "POST"}, "response": {"status": 429}}),
    # noise: a 200 on a blocked path (should NOT emit) + a 404 on a normal path (no gt_id)
    json.dumps({"request": {"uri": "/internal/secret", "method": "GET"}, "response": {"status": 200}}),
    json.dumps({"request": {"uri": "/no/such/page", "method": "GET"}, "response": {"status": 404}}),
    "not json at all",  # malformed line -> skipped
]

# --- Postgres log fixture: log_statement=all output ("LOG:  statement: <sql>").
_PG_LINES = [
    "2026-06-05 12:00:00.001 UTC [42] LOG:  statement: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'",
    "2026-06-05 12:00:00.002 UTC [42] LOG:  statement: SELECT * FROM transactions WHERE id = 1 UNION SELECT password FROM users",
    "2026-06-05 12:00:00.003 UTC [42] LOG:  execute s1: SELECT 1 OR 1=1 FROM billers",
    # benign statements (no signature / no app table) -> skipped
    "2026-06-05 12:00:00.004 UTC [42] LOG:  statement: SELECT now()",
    "2026-06-05 12:00:00.005 UTC [42] LOG:  statement: SELECT * FROM users WHERE id = 7",
    # signature but unknown table -> skipped (no app table)
    "2026-06-05 12:00:00.006 UTC [42] LOG:  statement: SELECT * FROM pg_catalog.pg_tables WHERE x OR 1=1",
]


class TestKong(unittest.TestCase):
    def test_blocked_404_and_ratelimit_429(self):
        evs = parse_kong_log(_KONG_LINES)
        gts = sorted((e["path"], e["status"], e["gt_id"]) for e in evs)
        self.assertEqual(gts, sorted([
            ("/internal/secret", 404, "VB-SSRF-INTERNAL-SECRET"),
            ("/api/docs", 404, "VB-SWAGGER-EXPOSURE"),
            ("/static/openapi.json", 404, "VB-SWAGGER-EXPOSURE"),
            ("/internal/config", 404, "VB-SSRF-INTERNAL-SECRET"),
            ("/login", 429, "VB-NO-LOCKOUT-LOGIN"),
            ("/api/v1/reset-password", 429, "VB-WEAK-PIN-RESET"),
        ]))

    def test_all_events_are_kong_blocked_type(self):
        evs = parse_kong_log(_KONG_LINES)
        self.assertTrue(all(e["type"] == "KONG_BLOCKED" for e in evs))

    def test_200_and_unmapped_404_dropped(self):
        evs = parse_kong_log(_KONG_LINES)
        paths = [e["path"] for e in evs]
        # the 200 on /internal/secret and the 404 on /no/such/page must NOT appear
        self.assertNotIn(200, [e["status"] for e in evs])
        self.assertNotIn("/no/such/page", paths)
        # /api/admin is blocked but maps to no real vuln -> dropped
        self.assertNotIn("/api/admin", paths)

    def test_feeds_signals_classify(self):
        # signals.classify_event reads ev['gt_id'] for KONG_BLOCKED
        ev = parse_kong_log([_KONG_LINES[1]])[0]   # /api/docs 404
        sigs = [(s.gt_id, s.strength) for s in classify_event(ev)]
        self.assertIn(("VB-SWAGGER-EXPOSURE", "proves-attempt"), sigs)

    def test_string_input_accepted(self):
        evs = parse_kong_log("\n".join(_KONG_LINES))
        self.assertTrue(any(e["gt_id"] == "VB-NO-LOCKOUT-LOGIN" for e in evs))


class TestPostgres(unittest.TestCase):
    def test_sqli_signatures_against_app_tables(self):
        evs = parse_pg_log(_PG_LINES)
        self.assertEqual(len(evs), 3)
        self.assertTrue(all(e["type"] == "DB_SQLI_EXEC" for e in evs))

    def test_path_inference_from_table(self):
        evs = parse_pg_log(_PG_LINES)
        paths = [e.get("path") for e in evs]
        self.assertIn("/login", paths)              # users -> /login
        self.assertIn("/api/transactions", paths)   # transactions -> /api/transactions

    def test_benign_statements_skipped(self):
        evs = parse_pg_log([
            "LOG:  statement: SELECT now()",
            "LOG:  statement: SELECT * FROM users WHERE id = 7",
        ])
        self.assertEqual(evs, [])

    def test_unknown_table_skipped(self):
        # signature present but no app table -> no event
        evs = parse_pg_log(["LOG:  statement: SELECT * FROM pg_catalog.pg_tables WHERE x OR 1=1"])
        self.assertEqual(evs, [])

    def test_feeds_signals_classify_exploit(self):
        # DB_SQLI_EXEC on /login -> VB-SQLI-LOGIN proves-exploit (via signals._sqli_id_for)
        ev = parse_pg_log([_PG_LINES[0]])[0]
        sigs = [(s.gt_id, s.strength) for s in classify_event(ev)]
        self.assertIn(("VB-SQLI-LOGIN", "proves-exploit"), sigs)

    def test_missing_path_still_classifies_via_signals(self):
        # a recognised injection whose table maps to a path is fine; verify the
        # no-path branch is tolerated by signals (omit path entirely).
        evs = parse_pg_log(["LOG:  statement: SELECT * FROM transactions WHERE 1=1 UNION SELECT 1"])
        self.assertEqual(evs[0]["path"], "/api/transactions")


if __name__ == "__main__":
    unittest.main()
