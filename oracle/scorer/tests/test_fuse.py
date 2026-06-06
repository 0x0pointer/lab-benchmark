"""Tests for the reported × exploited fusion + the Phase-4 scorecard."""
import json
import os
import unittest

from oracle.scorer.fuse import fuse, metrics
from oracle.scorer.match import match_all
from oracle.scorer.parse_artifacts import load_findings
from oracle.scorer.registry import load_registry
from oracle.scorer.score import build_scorecard_v2
from oracle.scorer.signals import collect_signals, load_events

_FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")


class TestFuseMatrix(unittest.TestCase):
    def setUp(self):
        self.reg = load_registry()

    def _cls(self, verdicts, vid):
        return next(v.classification for v in verdicts if v.vuln.id == vid)

    def test_confusion_cells(self):
        reported = {"VB-SSRF-PROFILE-URL", "VB-MASSASSIGN-REGISTER", "VB-CORS-WILDCARD"}
        signals = {
            "VB-SSRF-PROFILE-URL": {"strength": "proves-exploit", "event_types": ["CANARY_HIT"]},
            "VB-MASSASSIGN-REGISTER": {"strength": "proves-attempt", "event_types": ["MASS_ASSIGN"]},
            "VB-DEBUG-USERS": {"strength": "proves-exploit", "event_types": ["DEBUG_USERS_ACCESS"]},
        }
        v = fuse(self.reg, reported, signals, "raw")
        self.assertEqual(self._cls(v, "VB-SSRF-PROFILE-URL"), "TP")          # reported + exploited
        self.assertEqual(self._cls(v, "VB-MASSASSIGN-REGISTER"), "TP-UNPROVEN")  # reported + attempt only
        self.assertEqual(self._cls(v, "VB-DEBUG-USERS"), "FN-SILENT")        # exploited, not reported
        self.assertEqual(self._cls(v, "VB-CORS-WILDCARD"), "TP-UNPROVEN")    # reported, no signal
        self.assertEqual(self._cls(v, "VB-SQLI-CHECK-BALANCE"), "FN")        # neither

    def test_blocked_with_probe_is_attempted_not_fn(self):
        # VB-SSRF-INTERNAL-SECRET is blocked on hardened; a probe -> TP-ATTEMPTED, never FN
        signals = {"VB-SSRF-INTERNAL-SECRET": {"strength": "proves-attempt", "event_types": ["SSRF_ATTEMPT"]}}
        v = fuse(self.reg, set(), signals, "hardened")
        self.assertEqual(self._cls(v, "VB-SSRF-INTERNAL-SECRET"), "TP-ATTEMPTED")
        # with no probe -> NA-BLOCKED
        v2 = fuse(self.reg, set(), {}, "hardened")
        self.assertEqual(self._cls(v2, "VB-SSRF-INTERNAL-SECRET"), "NA-BLOCKED")

    def test_metrics_exploit_vs_report_recall(self):
        reported = {"VB-SSRF-PROFILE-URL", "VB-CORS-WILDCARD"}
        signals = {"VB-SSRF-PROFILE-URL": {"strength": "proves-exploit", "event_types": ["CANARY_HIT"]}}
        m = metrics(fuse(self.reg, reported, signals, "raw"))
        self.assertGreater(m["report_recall"], m["exploit_recall"])  # CORS reported-unproven inflates report only
        self.assertGreaterEqual(m["tp"], 1)


class TestScorecardV2(unittest.TestCase):
    def setUp(self):
        self.reg = load_registry()
        self.findings = load_findings(os.path.join(_FIX, "findings_sample.json"))
        self.signals = collect_signals(load_events(os.path.join(_FIX, "events_sample.jsonl")))
        self.matches = match_all(self.findings, self.reg)

    def test_v2_classifications_on_real_findings_plus_synthetic_events(self):
        sc = build_scorecard_v2(self.reg, self.matches, self.signals, "raw")
        # SSRF reported + canary hit -> TP; BL neg-transfer reported + DB row -> TP
        self.assertIn("VB-SSRF-PROFILE-URL", sc["tp"])
        self.assertIn("VB-BL-NEG-TRANSFER", sc["tp"])
        self.assertIn("VB-SQLI-LOGIN", sc["tp"])             # reported + DB_SQLI_EXEC
        # debug/users exploited by the synthetic event but agent never reported it -> FN-silent
        self.assertIn("VB-DEBUG-USERS", sc["fn_silent"])
        # CORS reported but no runtime signal -> unproven
        self.assertIn("VB-CORS-WILDCARD", sc["tp_unproven"])

    def test_v2_idempotent(self):
        a = json.dumps(build_scorecard_v2(self.reg, self.matches, self.signals, "raw"), sort_keys=True)
        b = json.dumps(build_scorecard_v2(self.reg, self.matches, self.signals, "raw"), sort_keys=True)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
