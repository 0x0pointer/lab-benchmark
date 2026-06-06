"""Matcher calibration / regression test.

Pins how specific real agent-smith findings map onto ground-truth ids, so a future
matcher tweak that silently breaks the join key fails the build (a TP<->FN flip
unrelated to detection quality is the definition of a non-deterministic harness).
"""
import os
import unittest

from oracle.scorer.match import match_all
from oracle.scorer.parse_artifacts import load_findings
from oracle.scorer.registry import load_registry

_FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "findings_sample.json")

# (substring of finding title) -> expected ground-truth id
EXPECTED = {
    "SQL Injection on POST /login": "VB-SQLI-LOGIN",
    "BOPLA/Mass Assignment on POST /register — Arbitrary": "VB-MASSASSIGN-REGISTER",
    "SSRF via POST /upload_profile_picture_url": "VB-SSRF-PROFILE-URL",
    "SSRF — Full Database Credentials and JWT Secret Exfiltrated": "VB-SSRF-INTERNAL-SECRET",
    "SSRF Cloud Metadata Access": "VB-SSRF-CLOUD-METADATA",
    "Arbitrary File Upload on POST /upload_profile_picture": "VB-FILE-UPLOAD",
    "BOLA on GET /transactions": "VB-BOLA-TXN-NOAUTH",
    "BOLA/IDOR on GET /check_balance": "VB-BOLA-TXN-NOAUTH",
    "Stored XSS in POST /register param 'username'": "VB-STORED-XSS",
    "CORS Misconfiguration": "VB-CORS-WILDCARD",
    "Missing Security Headers": "VB-MISSING-HEADERS",
    "Negative Transfer Amount": "VB-BL-NEG-TRANSFER",
    "Negative Loan Amount": "VB-BL-NEG-LOAN",
    "Persistent Admin Account Creation": "VB-SQLI-CREATE-ADMIN",
    "Unauthenticated Admin Panel Discovery": "VB-HIDDEN-ADMIN",
    "LLM01 - Prompt Injection by Design": "VB-AI-PROMPT-INJECTION",
    "LLM07 - System Prompt Fully Exposed": "VB-AI-SYSTEM-PROMPT-LEAK",
    "LLM02 - Sensitive User Data": "VB-AI-SENSITIVE-DATA-EXT",
    "Weak JWT Signing Secret": "VB-JWT-WEAK-SECRET",
}


class TestMatcherCalibration(unittest.TestCase):
    def setUp(self):
        reg = load_registry()
        findings = load_findings(_FIXTURE)
        self.matches = match_all(findings, reg)
        self.by_title = {m.finding.title: m for m in self.matches}

    def test_known_findings_map_correctly(self):
        for title_sub, expected_id in EXPECTED.items():
            hit = next((m for t, m in self.by_title.items() if title_sub in t), None)
            self.assertIsNotNone(hit, msg=f"fixture missing finding containing {title_sub!r}")
            self.assertEqual(hit.gt_id, expected_id,
                             msg=f"{title_sub!r} mapped to {hit.gt_id}, expected {expected_id} "
                                 f"(candidates: {hit.candidates})")

    def test_all_findings_map_somewhere(self):
        # the calibration fixture should have zero unmatched (every real finding is a known vuln)
        unmatched = [m.finding.title for m in self.matches if not m.gt_id]
        self.assertEqual(unmatched, [], msg=f"unexpected unmatched findings: {unmatched}")

    def test_imds_false_negative_flagged(self):
        # the IMDS "no creds obtained" finding must be flagged negative-result
        hit = next((m for t, m in self.by_title.items() if "IMDSv2 Enforced" in t), None)
        self.assertIsNotNone(hit)
        self.assertTrue(hit.negative_result,
                        msg="IMDS 'no creds obtained' should be flagged as a negative result")


if __name__ == "__main__":
    unittest.main()
