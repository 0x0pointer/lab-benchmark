"""Tier-2 LLM-judge matcher tests (advisory path).

The judge must (1) degrade to [] with no SDK / no API key / no client — and the
deterministic scorecard must still build — and (2) when given a FAKE injected client,
map an unmatched finding to the chosen id, then serve a byte-identical re-run from the
cache WITHOUT calling the client a second time. The deterministic gate never depends
on the judge.
"""
import os
import tempfile
import unittest

from oracle.scorer.match import match_all
from oracle.scorer.match_tier2_llm import (
    CONFIDENCE_FLOOR,
    judge_unmatched,
    render_adjudication,
)
from oracle.scorer.parse_artifacts import Finding, load_findings
from oracle.scorer.registry import load_registry
from oracle.scorer.score import build_scorecard

_FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "findings_sample.json")


class _ToolUseBlock:
    """Minimal stand-in for an anthropic ToolUseBlock."""
    type = "tool_use"

    def __init__(self, name, inp):
        self.name = name
        self.input = inp


class _Resp:
    def __init__(self, content):
        self.content = content


class _Messages:
    def __init__(self, parent):
        self._parent = parent

    def create(self, **kwargs):
        self._parent.calls.append(kwargs)
        return _Resp([_ToolUseBlock("classify", dict(self._parent.verdict))])


class FakeClient:
    """Injectable client: records calls and returns a canned classify tool_use."""
    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = []
        self.messages = _Messages(self)


def _unmatched_finding():
    return Finding(
        id="F-NEW", title="Open redirect on GET /redirect via next= param",
        severity="medium", target="/redirect",
        description="The next parameter is reflected into a Location header without validation.",
    )


class TestGracefulFallback(unittest.TestCase):
    def setUp(self):
        self.reg = load_registry()

    def test_no_client_no_key_returns_empty(self):
        # no injected client + no API key -> [] (no raise)
        prev = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with tempfile.TemporaryDirectory() as d:
                out = judge_unmatched([_unmatched_finding()], self.reg,
                                      cache_path=os.path.join(d, "cache.json"))
            self.assertEqual(out, [])
        finally:
            if prev is not None:
                os.environ["ANTHROPIC_API_KEY"] = prev

    def test_empty_input_returns_empty(self):
        self.assertEqual(judge_unmatched([], self.reg), [])

    def test_scorecard_still_builds_without_judge(self):
        # the deterministic gate is independent of the judge
        findings = load_findings(_FIXTURE)
        sc = build_scorecard(self.reg, match_all(findings, self.reg), profile="raw")
        self.assertIn("must_find_pass", sc["metrics"])
        self.assertIn("report_recall", sc["metrics"])

    def test_render_handles_empty(self):
        self.assertIn("none", render_adjudication([]).lower())


class TestFakeClientAndCache(unittest.TestCase):
    def setUp(self):
        self.reg = load_registry()
        self.finding = _unmatched_finding()

    def test_maps_finding_and_caches(self):
        fake = FakeClient({
            "ground_truth_id": "VB-SQLI-LOGIN",
            "confidence": 0.92,
            "is_duplicate_of": None,
            "rationale": "matches the login SQLi endpoint",
        })
        with tempfile.TemporaryDirectory() as d:
            cache = os.path.join(d, "cache.json")

            # first call -> hits the (fake) API, maps to the chosen id
            v1 = judge_unmatched([self.finding], self.reg, client=fake, cache_path=cache)
            self.assertEqual(len(v1), 1)
            self.assertEqual(v1[0].gt_id, "VB-SQLI-LOGIN")
            self.assertFalse(v1[0].cached)
            self.assertEqual(len(fake.calls), 1)

            # second identical call -> served from cache, NO second API call
            v2 = judge_unmatched([self.finding], self.reg, client=fake, cache_path=cache)
            self.assertEqual(len(v2), 1)
            self.assertEqual(v2[0].gt_id, "VB-SQLI-LOGIN")
            self.assertTrue(v2[0].cached)
            self.assertEqual(len(fake.calls), 1, "cache miss: fake client called twice")

            # cached output is byte-identical except the `cached` provenance flag
            d1, d2 = v1[0].to_dict(), v2[0].to_dict()
            d1.pop("cached"), d2.pop("cached")
            self.assertEqual(d1, d2)

    def test_low_confidence_maps_to_none(self):
        fake = FakeClient({
            "ground_truth_id": "VB-SQLI-LOGIN",
            "confidence": CONFIDENCE_FLOOR - 0.1,
            "is_duplicate_of": None,
            "rationale": "weak guess",
        })
        with tempfile.TemporaryDirectory() as d:
            v = judge_unmatched([self.finding], self.reg, client=fake,
                                cache_path=os.path.join(d, "cache.json"))
        self.assertIsNone(v[0].gt_id, "below-floor confidence must map to none")

    def test_explicit_none_maps_to_none(self):
        fake = FakeClient({
            "ground_truth_id": "none",
            "confidence": 0.99,
            "is_duplicate_of": None,
            "rationale": "no catalogue match",
        })
        with tempfile.TemporaryDirectory() as d:
            v = judge_unmatched([self.finding], self.reg, client=fake,
                                cache_path=os.path.join(d, "cache.json"))
        self.assertIsNone(v[0].gt_id)

    def test_request_is_deterministic_and_constrained(self):
        fake = FakeClient({
            "ground_truth_id": "VB-SQLI-LOGIN", "confidence": 0.9,
            "is_duplicate_of": None, "rationale": "x",
        })
        with tempfile.TemporaryDirectory() as d:
            judge_unmatched([self.finding], self.reg, client=fake,
                            cache_path=os.path.join(d, "cache.json"))
        req = fake.calls[0]
        self.assertEqual(req["temperature"], 0)                       # deterministic
        self.assertEqual(req["tool_choice"], {"type": "tool", "name": "classify"})
        # registry summary is prompt-cached as a system block
        self.assertEqual(req["system"][0]["cache_control"], {"type": "ephemeral"})
        # the id enum is constrained to catalogue ids + 'none'
        schema = req["tools"][0]["input_schema"]["properties"]["ground_truth_id"]["enum"]
        self.assertIn("VB-SQLI-LOGIN", schema)
        self.assertIn("none", schema)


if __name__ == "__main__":
    unittest.main()
