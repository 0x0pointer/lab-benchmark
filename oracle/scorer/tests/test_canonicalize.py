"""Golden tests for the oracle's path canonicalizer + class inference.

If agent-smith changes how it writes targets, or we tweak the canonicalizer,
these must be deliberately re-blessed — they are the join-key contract.
"""
import unittest

from oracle.scorer.canonicalize import (
    canonicalize_path,
    gt_classes,
    infer_finding_classes,
    is_negative_result,
)


class TestCanonicalizePath(unittest.TestCase):
    CASES = [
        # numeric id, LLM placeholder, and bare path all collapse identically
        ("http://notingbank.org/check_balance/8206264376", "/check_balance/{id}"),
        ("/check_balance/{account_number}", "/check_balance/{id}"),
        ("http://x/transactions/{account_number}", "/transactions/{id}"),
        # query string is stripped
        ("http://notingbank.org/api/transactions?account_number=", "/api/transactions"),
        ("http://x/api/transactions", "/api/transactions"),
        # api version is preserved (v1 != v3)
        ("http://x/api/v1/forgot-password", "/api/v1/forgot-password"),
        ("http://x/api/v3/user/42", "/api/v3/user/{id}"),
        # uuid collapses
        ("/x/123e4567-e89b-12d3-a456-426614174000", "/x/{id}"),
        # root / host-only
        ("http://notingbank.org/", "/"),
        ("http://notingbank.org", "/"),
        # trailing slash trimmed, lowercased
        ("/API/Docs/", "/api/docs"),
    ]

    def test_golden(self):
        for raw, expected in self.CASES:
            self.assertEqual(canonicalize_path(raw), expected, msg=f"input={raw!r}")


class TestClassInference(unittest.TestCase):
    def test_title_drives_class(self):
        self.assertIn("xss", infer_finding_classes("stored xss in post /register param 'username'"))
        self.assertIn("sqli", infer_finding_classes("sql injection on post /login"))
        self.assertIn("ssrf", infer_finding_classes("ssrf via upload_profile_picture_url"))
        self.assertIn("metadata", infer_finding_classes("aws imds iam credentials"))
        self.assertIn("ai-injection", infer_finding_classes("llm01 - prompt injection by design"))
        self.assertIn("bola", infer_finding_classes("bola/idor on get /check_balance"))

    def test_gt_class_gate_separates_shared_path(self):
        # /check_balance is BOTH sqli and bola; classes must keep them distinct
        self.assertEqual(gt_classes("VB-SQLI-CHECK-BALANCE"), {"sqli"})
        self.assertEqual(gt_classes("VB-BOLA-TXN-NOAUTH"), {"bola"})

    def test_negative_result_detection(self):
        self.assertTrue(is_negative_result("IMDSv2 Enforced, No IAM Credentials Obtained"))
        self.assertFalse(is_negative_result("SQL Injection on POST /login — Auth Bypass"))


if __name__ == "__main__":
    unittest.main()
