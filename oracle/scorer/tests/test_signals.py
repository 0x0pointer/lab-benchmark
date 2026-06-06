"""Tests for proof-event -> signal classification."""
import os
import unittest

from oracle.scorer.signals import classify_event, collect_signals, load_events

_EVENTS = os.path.join(os.path.dirname(__file__), "..", "fixtures", "events_sample.jsonl")


def _one(ev):
    sigs = classify_event(ev)
    return [(s.gt_id, s.strength) for s in sigs]


class TestClassifyEvent(unittest.TestCase):
    def test_canary_hit_proves_ssrf(self):
        self.assertIn(("VB-SSRF-PROFILE-URL", "proves-exploit"), _one({"type": "CANARY_HIT", "path": "/x"}))

    def test_debug_users_proves_exploit(self):
        self.assertIn(("VB-DEBUG-USERS", "proves-exploit"), _one({"type": "DEBUG_USERS_ACCESS", "path": "/debug/users"}))

    def test_neg_transfer_attempt_vs_row_exploit(self):
        self.assertIn(("VB-BL-NEG-TRANSFER", "proves-attempt"), _one({"type": "NEG_TRANSFER", "amount": -5}))
        self.assertIn(("VB-BL-NEG-TRANSFER", "proves-exploit"), _one({"type": "DB_NEG_TRANSFER_ROW", "amount": -5}))

    def test_sqli_signal_path_routing(self):
        self.assertIn(("VB-SQLI-API-TRANSACTIONS", "proves-attempt"),
                      _one({"type": "SQLI_SIGNAL", "path": "/api/transactions"}))
        self.assertIn(("VB-SQLI-LOGIN", "proves-attempt"),
                      _one({"type": "SQLI_SIGNAL", "path": "/login"}))
        self.assertIn(("VB-SQLI-LOGIN", "proves-exploit"),
                      _one({"type": "DB_SQLI_EXEC", "path": "/login"}))

    def test_account_access_idor_and_bola(self):
        # unauth account-scoped GET -> BOLA missing-auth, exploit
        self.assertIn(("VB-BOLA-TXN-NOAUTH", "proves-exploit"),
                      _one({"type": "ACCOUNT_ACCESS", "path": "/check_balance/1", "authenticated": False, "target": "1"}))
        # authed cross-account on /api/v3/user -> IDOR exploit
        self.assertIn(("VB-IDOR-API-V3-USER", "proves-exploit"),
                      _one({"type": "ACCOUNT_ACCESS", "path": "/api/v3/user/2", "authenticated": True,
                            "target": "2", "actor_account": "1"}))

    def test_admin_paths(self):
        self.assertIn(("VB-HIDDEN-ADMIN", "proves-exploit"),
                      _one({"type": "ADMIN_ACCESS", "path": "/sup3r_s3cr3t_admin"}))
        self.assertIn(("VB-SQLI-CREATE-ADMIN", "proves-attempt"),
                      _one({"type": "ADMIN_ACCESS", "path": "/admin/create_admin"}))


class TestCollect(unittest.TestCase):
    def test_best_strength_wins(self):
        evs = [{"type": "NEG_TRANSFER", "amount": -1}, {"type": "DB_NEG_TRANSFER_ROW", "amount": -1}]
        sig = collect_signals(evs)
        self.assertEqual(sig["VB-BL-NEG-TRANSFER"]["strength"], "proves-exploit")
        self.assertEqual(sig["VB-BL-NEG-TRANSFER"]["count"], 2)

    def test_run_id_filter(self):
        evs = [{"type": "CANARY_HIT", "run_id": "A"}, {"type": "DEBUG_USERS_ACCESS", "run_id": "B"}]
        sig = collect_signals(evs, run_id="A")
        self.assertIn("VB-SSRF-PROFILE-URL", sig)
        self.assertNotIn("VB-DEBUG-USERS", sig)

    def test_distinct_run_ids(self):
        from oracle.scorer.signals import distinct_run_ids
        evs = [{"run_id": "b"}, {"run_id": "a"}, {"run_id": "a"}, {"type": "x"}]  # one untagged
        self.assertEqual(distinct_run_ids(evs), ["a", "b"])
        self.assertEqual(distinct_run_ids([{"type": "x"}]), [])

    def test_load_events_jsonl_prefix(self):
        evs = load_events(_EVENTS)
        types = {e["type"] for e in evs}
        self.assertIn("CANARY_HIT", types)
        self.assertIn("DEBUG_USERS_ACCESS", types)
        self.assertGreaterEqual(len(evs), 8)


if __name__ == "__main__":
    unittest.main()
