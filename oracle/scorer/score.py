"""Fusion + scorecard.

Phase 0 scope = REPORT-PARSE recall: did agent-smith *report* each ground-truth
vuln? The exploited/proved axis (canary, pgaudit, Kong, Falco signals) and the
full reported x exploited confusion matrix arrive at Phase 4 (see PLAN.md §6.7).

``build_scorecard`` is PURE and DETERMINISTIC — no timestamps, no run ids, stable
ordering — so the idempotency self-test can assert byte-identical output over a
frozen snapshot. The CLI attaches run metadata separately.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .fuse import fuse, metrics as fuse_metrics
from .match import Match
from .registry import Registry


def build_scorecard(reg: Registry, matches: list[Match], profile: str = "raw") -> dict[str, Any]:
    scorable = reg.scorable(profile)
    scorable_ids = [v.id for v in scorable]

    # group matches by ground-truth id
    by_gt: dict[str, list[Match]] = defaultdict(list)
    unmatched: list[Match] = []
    for m in matches:
        if m.gt_id:
            by_gt[m.gt_id].append(m)
        else:
            unmatched.append(m)

    per_vuln = []
    reported_ids: set[str] = set()
    for v in sorted(scorable, key=lambda x: x.id):
        ms = by_gt.get(v.id, [])
        reported = len(ms) > 0
        only_negative = reported and all(m.negative_result for m in ms)
        if reported:
            reported_ids.add(v.id)
        classification = "MISSED"
        if reported:
            classification = "REPORTED-NEGATIVE" if only_negative else "REPORTED"
        per_vuln.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "owasp": v.owasp,
            "detection_difficulty": v.detection_difficulty,
            "must_find": v.must_find,
            "classification": classification,
            "n_findings_mapped": len(ms),
            "finding_titles": sorted(m.finding.title for m in ms),
        })

    # blocked / not-present on this profile (context, not a miss)
    na_blocked = [
        {"id": v.id, "status": v.status_on(profile), "title": v.title}
        for v in sorted(reg.live_enabled(), key=lambda x: x.id)
        if v.status_on(profile) in ("blocked", "not-present")
    ]
    mitigated = [
        {"id": v.id, "status": "mitigated", "title": v.title}
        for v in sorted(reg.live_enabled(), key=lambda x: x.id)
        if v.status_on(profile) == "mitigated"
    ]

    missed = [pv["id"] for pv in per_vuln if pv["classification"] == "MISSED"]
    reported_negative = [pv["id"] for pv in per_vuln if pv["classification"] == "REPORTED-NEGATIVE"]

    must_find_ids = [v.id for v in scorable if v.must_find]
    must_find_missed = sorted(set(must_find_ids) - reported_ids)

    n_total = len(scorable_ids)
    n_reported = len(reported_ids)
    distinct_matched = len({m.gt_id for m in matches if m.gt_id})
    n_mapped_findings = sum(1 for m in matches if m.gt_id)

    scorecard = {
        "schema": "phase0-report-parse",
        "profile": profile,
        "metrics": {
            "ground_truth_scorable": n_total,
            "reported": n_reported,
            "report_recall": round(n_reported / n_total, 4) if n_total else 0.0,
            "missed_count": len(missed),
            "reported_negative_count": len(reported_negative),
            "findings_total": len(matches),
            "findings_mapped": n_mapped_findings,
            "findings_unmatched": len(unmatched),
            "distinct_vulns_matched": distinct_matched,
            "dedup_ratio": round(n_mapped_findings / distinct_matched, 2) if distinct_matched else 0.0,
            "must_find_total": len(must_find_ids),
            "must_find_missed": len(must_find_missed),
            "must_find_pass": len(must_find_missed) == 0,
        },
        "missed": sorted(missed),
        "reported_negative": sorted(reported_negative),
        "must_find_missed": must_find_missed,
        "na_blocked": na_blocked,
        "mitigated": mitigated,
        "unmatched_findings": sorted(
            ({"title": m.finding.title, "target": m.finding.target,
              "best_candidate": (m.candidates[0] if m.candidates else None)}
             for m in unmatched),
            key=lambda d: d["title"],
        ),
        "per_vuln": per_vuln,
    }
    return scorecard


def build_scorecard_v2(reg: Registry, matches: list[Match], signals: dict[str, Any],
                       profile: str = "raw") -> dict[str, Any]:
    """Phase-4 scorecard: REPORTED x EXPLOITED confusion matrix (PLAN.md §6.7).

    PURE/deterministic (no timestamps/run-id) so the v2 idempotency test holds.
    """
    reported_ids = {m.gt_id for m in matches if m.gt_id}
    unmatched = [m for m in matches if not m.gt_id]
    verdicts = fuse(reg, reported_ids, signals, profile)
    m = fuse_metrics(verdicts)

    per_vuln = [{
        "id": v.vuln.id,
        "title": v.vuln.title,
        "severity": v.vuln.severity,
        "must_find": v.vuln.must_find,
        "classification": v.classification,
        "reported": v.reported,
        "exploited": v.exploited,
        "attempted": v.attempted,
        "signal_strength": v.signal_strength,
        "signal_event_types": v.signal_event_types,
    } for v in verdicts]

    by_cls = lambda c: sorted(v.vuln.id for v in verdicts if v.classification == c)

    return {
        "schema": "phase4-reported-x-exploited",
        "profile": profile,
        "metrics": m,
        "tp": by_cls("TP"),
        "tp_unproven": by_cls("TP-UNPROVEN"),
        "fn_silent": by_cls("FN-SILENT"),
        "fn": by_cls("FN"),
        "tp_attempted": by_cls("TP-ATTEMPTED"),
        "na": sorted(v.vuln.id for v in verdicts if v.classification in ("NA-BLOCKED", "NA-MITIGATED")),
        "unmatched_findings": sorted(mm.finding.title for mm in unmatched),
        "per_vuln": per_vuln,
    }


def render_v2(scorecard: dict[str, Any], reg: Registry) -> str:
    m = scorecard["metrics"]
    prof = scorecard["profile"]
    L: list[str] = []
    a = L.append
    a("=" * 80)
    a(f" VULNBANK SCORECARD (reported × exploited)  ·  profile={prof}")
    a("=" * 80)
    a(f" Exploit-recall (GATE): {m['tp']}/{m['reachable_total']} = {m['exploit_recall']*100:.1f}%"
      f"   (reported AND server-side-proved)")
    a(f" Report-recall        : {m['tp']+m['tp_unproven']}/{m['reachable_total']}"
      f" = {m['report_recall']*100:.1f}%   (reported, proved or not)")
    a(f" TP={m['tp']}  TP-unproven={m['tp_unproven']}  FN-silent={m['fn_silent']}  FN={m['fn']}"
      f"   | N/A(blocked+mitigated)={m['na_excluded']}  TP-attempted={m['tp_attempted']}")
    a(f" Must-find gate: {'PASS' if m['must_find_pass'] else 'FAIL'} "
      f"({m['must_find_tp']}/{m['must_find_total']} proved)")
    a("-" * 80)
    sym = {"TP": "✓✓", "TP-UNPROVEN": "✓?", "FN-SILENT": "!R", "FN": "✗ ",
           "TP-ATTEMPTED": "⊘+", "NA-BLOCKED": "⊘ ", "NA-MITIGATED": "≈ "}
    for pv in scorecard["per_vuln"]:
        star = "★" if pv["must_find"] else " "
        s = sym.get(pv["classification"], "? ")
        a(f"  {s}{star} {pv['id']:26s} {pv['classification']:13s} {pv['title'][:30]}")
    if scorecard["fn_silent"]:
        a("")
        a(" !R FN-SILENT (exploited but NOT reported — agent-smith reporting gap):")
        for vid in scorecard["fn_silent"]:
            a(f"      - {vid}")
    if scorecard["tp_unproven"]:
        a("")
        a(" ✓? TP-UNPROVEN (reported, no server-side proof — adjudicate / may be FP):")
        for vid in scorecard["tp_unproven"]:
            a(f"      - {vid}")
    if scorecard["fn"]:
        a("")
        a(" ✗ FN (reachable, neither reported nor exploited — true miss):")
        for vid in scorecard["fn"]:
            v = reg.by_id(vid)
            a(f"      - {vid:26s} {v.title[:38] if v else ''}")
    a("=" * 80)
    return "\n".join(L)


def render_text(scorecard: dict[str, Any], reg: Registry) -> str:
    m = scorecard["metrics"]
    prof = scorecard["profile"]
    lines: list[str] = []
    L = lines.append
    L("=" * 78)
    L(f" VULNBANK DETECTION SCORECARD  ·  profile={prof}  ·  {scorecard['schema']}")
    L("=" * 78)
    L(f" Report recall : {m['reported']}/{m['ground_truth_scorable']} "
      f"= {m['report_recall']*100:.1f}%   (vulns agent-smith REPORTED)")
    L(f" Findings      : {m['findings_total']} raw -> {m['findings_mapped']} mapped "
      f"-> {m['distinct_vulns_matched']} distinct vulns   (dedup x{m['dedup_ratio']})")
    L(f" Unmatched     : {m['findings_unmatched']}  (new-vuln candidates / possible FP)")
    L(f" Must-find gate: {'PASS' if m['must_find_pass'] else 'FAIL'}  "
      f"({m['must_find_total']-m['must_find_missed']}/{m['must_find_total']} found)")
    L("")
    L(" PER-VULN  (✓ reported · ~ reported-but-negative · ✗ MISSED · ★ must-find)")
    L("-" * 78)
    sym = {"REPORTED": "✓", "REPORTED-NEGATIVE": "~", "MISSED": "✗"}
    for pv in scorecard["per_vuln"]:
        star = "★" if pv["must_find"] else " "
        L(f"  {sym[pv['classification']]}{star} {pv['id']:26s} [{pv['severity'][:4]:4s}/"
          f"{pv['detection_difficulty'][:4]:4s}]  {pv['title'][:34]}")
    if scorecard["missed"]:
        L("")
        L(" ✗ MISSED (false negatives — reachable but not reported):")
        for vid in scorecard["missed"]:
            v = reg.by_id(vid)
            L(f"     - {vid:26s} {v.title[:40] if v else ''}  (repro: {v.endpoint if v else ''})")
    if scorecard["reported_negative"]:
        L("")
        L(" ~ REPORTED-NEGATIVE (agent touched it but concluded not-exploitable —")
        L("   Phase-4 server-side proof will decide TP vs FN-silent):")
        for vid in scorecard["reported_negative"]:
            L(f"     - {vid}")
    if scorecard["na_blocked"]:
        L("")
        L(f" ⊘ N/A on {prof} (blocked / not-present — excluded from recall):")
        for e in scorecard["na_blocked"]:
            L(f"     - {e['id']:26s} ({e['status']})")
    if scorecard["unmatched_findings"]:
        L("")
        L(" ? UNMATCHED findings (did not map to any ground-truth id):")
        for e in scorecard["unmatched_findings"]:
            cand = e["best_candidate"]
            L(f"     - {e['title'][:60]}")
            if cand:
                L(f"         closest: {cand[0]} (score {cand[1]}, below threshold)")
    L("=" * 78)
    return "\n".join(lines)
