"""Oracle meta-determinism self-test.

The scorer must prove its OWN determinism before it can be trusted to judge
agent-smith: scoring the SAME frozen snapshot twice must yield a byte-identical
scorecard. If this fails, no downstream regression signal is trustworthy.
(PLAN.md §7.5)
"""
import json
import os
import unittest

from oracle.scorer.match import match_all
from oracle.scorer.parse_artifacts import load_findings
from oracle.scorer.registry import load_registry
from oracle.scorer.score import build_scorecard

_FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "findings_sample.json")


class TestIdempotency(unittest.TestCase):
    def _score(self, profile):
        reg = load_registry()
        findings = load_findings(_FIXTURE)
        return build_scorecard(reg, match_all(findings, reg), profile=profile)

    def test_scorecard_byte_identical(self):
        for profile in ("raw", "hardened"):
            a = json.dumps(self._score(profile), sort_keys=True)
            b = json.dumps(self._score(profile), sort_keys=True)
            self.assertEqual(a, b, msg=f"non-deterministic scorecard on profile={profile}")

    def test_no_timestamps_in_core_scorecard(self):
        # core scorecard must be free of time/run-id so it stays diffable
        blob = json.dumps(self._score("raw"))
        for token in ("timestamp", "run_id", "2026-", "created"):
            self.assertNotIn(token, blob, msg=f"core scorecard leaked '{token}'")


if __name__ == "__main__":
    unittest.main()
