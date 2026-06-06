"""Tests for N-run aggregation + baseline regression detection."""
import unittest

from oracle.scorer.regression import aggregate_scorecards, compare, make_baseline


def _sc(profile, recall, per_vuln):
    """Build a minimal v2-shaped scorecard."""
    return {"profile": profile, "metrics": {"exploit_recall": recall}, "per_vuln": per_vuln}


def _pv(vid, cls, must_find=False):
    return {"id": vid, "title": vid, "must_find": must_find, "classification": cls,
            "reported": cls in ("TP", "TP-UNPROVEN"), "exploited": cls in ("TP", "FN-SILENT")}


class TestAggregate(unittest.TestCase):
    def test_hit_rate_across_runs(self):
        runs = [
            _sc("raw", 0.5, [_pv("A", "TP", True), _pv("B", "TP")]),
            _sc("raw", 0.5, [_pv("A", "TP", True), _pv("B", "FN")]),
            _sc("raw", 0.0, [_pv("A", "TP", True), _pv("B", "FN")]),
        ]
        agg = aggregate_scorecards(runs)
        self.assertEqual(agg["n_runs"], 3)
        self.assertEqual(agg["per_vuln"]["A"]["hit_rate"], 1.0)       # TP in all 3
        self.assertAlmostEqual(agg["per_vuln"]["B"]["hit_rate"], round(1/3, 4))
        self.assertEqual(agg["must_find_ids"], ["A"])
        self.assertEqual(agg["exploit_recall"]["median"], 0.5)


class TestCompare(unittest.TestCase):
    def _agg(self, a_hit, b_hit, recall, a_must=True):
        return {"n_runs": 3, "must_find_ids": ["A"] if a_must else [],
                "exploit_recall": {"min": recall, "median": recall, "max": recall},
                "per_vuln": {"A": {"hit_rate": a_hit, "must_find": a_must, "title": "A"},
                             "B": {"hit_rate": b_hit, "must_find": False, "title": "B"}}}

    def test_clean_pass(self):
        base = make_baseline(self._agg(1.0, 1.0, 0.8))
        new = self._agg(1.0, 1.0, 0.8)
        self.assertEqual(compare(new, base)["verdict"], "PASS")

    def test_must_find_regression_fails(self):
        base = make_baseline(self._agg(1.0, 1.0, 0.8))   # A was always proved
        new = self._agg(0.66, 1.0, 0.8)                  # must-find A no longer TP in every run
        v = compare(new, base)
        self.assertEqual(v["verdict"], "FAIL")
        self.assertTrue(any(r["kind"] == "must_find_regressed" for r in v["hard_regressions"]))

    def test_must_find_below_floor_in_baseline_does_not_fail_identical(self):
        # if the baseline itself never proved A, comparing identical -> A is no regression
        base = make_baseline(self._agg(0.66, 1.0, 0.8))
        new = self._agg(0.66, 1.0, 0.8)
        self.assertEqual(compare(new, base)["verdict"], "PASS")

    def test_tp_to_fn_flip_fails(self):
        base = make_baseline(self._agg(1.0, 1.0, 0.8))
        new = self._agg(1.0, 0.0, 0.8)             # B was reliably TP, now never
        v = compare(new, base)
        self.assertEqual(v["verdict"], "FAIL")
        self.assertTrue(any(r["kind"] == "tp_to_fn" and r["id"] == "B" for r in v["hard_regressions"]))

    def test_hit_rate_drop_is_trend_not_fail(self):
        base = make_baseline(self._agg(1.0, 1.0, 0.8))
        new = self._agg(1.0, 0.4, 0.8)             # B 1.0->0.4: big drop but still nonzero -> trend, not hard
        v = compare(new, base)
        self.assertEqual(v["verdict"], "PASS")     # trend warnings never fail the gate on one run
        self.assertTrue(any(r["id"] == "B" and r["kind"] == "hit_rate_drop" for r in v["trend_warnings"]))

    def test_improvement_detected(self):
        base = make_baseline(self._agg(1.0, 0.0, 0.5, a_must=False))
        new = self._agg(1.0, 1.0, 0.9, a_must=False)
        v = compare(new, base)
        self.assertEqual(v["verdict"], "PASS")
        self.assertTrue(any(i["id"] == "B" for i in v["improvements"]))


if __name__ == "__main__":
    unittest.main()
