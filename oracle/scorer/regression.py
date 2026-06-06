"""N-run aggregation + baseline regression detection.

agent-smith is LLM-driven, so a single run is noisy. We run N times, aggregate to a
per-vuln HIT-RATE (fraction of runs in which the vuln was a confirmed TP), and gate as:

  * STRICT (hard fail): every ``must_find`` vuln must be a TP in EVERY run (hit_rate == 1.0),
    and no baseline-stable vuln (baseline hit_rate >= 0.5) may collapse to never-found (0.0).
  * TREND (warn only, hysteresis): other hit-rate drops beyond TOLERANCE are surfaced but
    do not fail the gate on a single night (PLAN.md §7.4).

Pure + deterministic: same scorecards in -> same aggregate/verdict out.
"""
from __future__ import annotations

import statistics
from collections import Counter
from typing import Any

TOLERANCE = 0.34          # ignore hit-rate wobble up to ~1/3 (N=3 single-run flip)
STABLE_THRESHOLD = 0.5    # baseline hit_rate >= this == "reliably found"


def aggregate_scorecards(scorecards: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine N Phase-4 (v2) scorecards into per-vuln hit-rates + recall distribution."""
    if not scorecards:
        raise ValueError("no scorecards to aggregate")
    n = len(scorecards)
    profile = scorecards[0].get("profile", "raw")
    per: dict[str, dict] = {}
    recalls: list[float] = []

    for sc in scorecards:
        recalls.append(sc.get("metrics", {}).get("exploit_recall", 0.0))
        for pv in sc.get("per_vuln", []):
            e = per.setdefault(pv["id"], {
                "title": pv.get("title", ""), "must_find": pv.get("must_find", False),
                "runs": 0, "tp": 0, "reported": 0, "exploited": 0, "cls": Counter(),
            })
            e["runs"] += 1
            e["cls"][pv["classification"]] += 1
            if pv["classification"] == "TP":
                e["tp"] += 1
            if pv.get("reported"):
                e["reported"] += 1
            if pv.get("exploited"):
                e["exploited"] += 1

    per_out = {}
    for vid, e in sorted(per.items()):
        runs = e["runs"]
        per_out[vid] = {
            "title": e["title"],
            "must_find": e["must_find"],
            "runs": runs,
            "tp_runs": e["tp"],
            "hit_rate": round(e["tp"] / runs, 4) if runs else 0.0,
            "report_rate": round(e["reported"] / runs, 4) if runs else 0.0,
            "classifications": dict(sorted(e["cls"].items())),
        }

    return {
        "schema": "aggregate-v1",
        "profile": profile,
        "n_runs": n,
        "exploit_recall": {
            "min": round(min(recalls), 4), "median": round(statistics.median(recalls), 4),
            "max": round(max(recalls), 4),
        },
        "must_find_ids": sorted(vid for vid, v in per_out.items() if v["must_find"]),
        "per_vuln": per_out,
    }


def compare(new: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Compare a new aggregate against a stored baseline -> regression verdict."""
    hard: list[dict] = []      # fail the gate
    trend: list[dict] = []     # warn only
    improvements: list[dict] = []

    new_pv = new.get("per_vuln", {})
    base_pv = baseline.get("per_vuln", {})

    # STRICT 1 (relative): a must-find vuln that was reliably proved in the baseline
    # (hit_rate == 1.0) must STILL be proved in every run. Baseline-relative so the
    # gate measures *regression*, not the absolute quality floor (that floor is enforced
    # at per-run scoring + baseline-capture, see make_baseline / _cmd_baseline_save).
    for vid in new.get("must_find_ids", []):
        bh = base_pv.get(vid, {}).get("hit_rate")
        nh = new_pv.get(vid, {}).get("hit_rate", 0.0)
        if bh is not None and bh >= 1.0 and nh < 1.0:
            hard.append({"id": vid, "kind": "must_find_regressed", "baseline": bh, "new": nh,
                         "detail": f"must-find vuln was always proved, now only {nh*100:.0f}% of runs"})

    # STRICT 2 + TREND: per-vuln drift vs baseline
    for vid, b in base_pv.items():
        n = new_pv.get(vid)
        if n is None:
            continue
        bh, nh = b.get("hit_rate", 0.0), n.get("hit_rate", 0.0)
        if bh >= STABLE_THRESHOLD and nh == 0.0:
            hard.append({"id": vid, "kind": "tp_to_fn", "baseline": bh, "new": nh,
                         "detail": f"was reliably found ({bh*100:.0f}%), now never ({nh*100:.0f}%)"})
        elif nh < bh - TOLERANCE:
            trend.append({"id": vid, "kind": "hit_rate_drop", "baseline": bh, "new": nh,
                          "detail": f"hit-rate dropped {bh*100:.0f}% -> {nh*100:.0f}%"})
        elif nh > bh + TOLERANCE:
            improvements.append({"id": vid, "baseline": bh, "new": nh})

    # overall recall drop (trend)
    b_med = baseline.get("exploit_recall", {}).get("median", 0.0)
    n_med = new.get("exploit_recall", {}).get("median", 0.0)
    if n_med < b_med - TOLERANCE:
        trend.append({"id": "<overall>", "kind": "median_recall_drop", "baseline": b_med, "new": n_med,
                      "detail": f"median exploit-recall {b_med*100:.0f}% -> {n_med*100:.0f}%"})

    return {
        "verdict": "FAIL" if hard else "PASS",
        "hard_regressions": hard,
        "trend_warnings": trend,
        "improvements": improvements,
        "baseline_n_runs": baseline.get("n_runs"),
        "new_n_runs": new.get("n_runs"),
    }


def make_baseline(aggregate: dict[str, Any], agent_smith_commit: str = "unknown",
                  notes: str = "") -> dict[str, Any]:
    return {"schema": "baseline-v1", "agent_smith_commit": agent_smith_commit,
            "notes": notes, **aggregate}


def quality_floor_warnings(aggregate: dict[str, Any]) -> list[str]:
    """Must-find vulns not proved in EVERY run — the absolute quality floor. A baseline
    blessed below this floor will let real misses through, so surface it at capture time."""
    out = []
    pv = aggregate.get("per_vuln", {})
    for vid in aggregate.get("must_find_ids", []):
        hr = pv.get(vid, {}).get("hit_rate", 0.0)
        if hr < 1.0:
            out.append(f"{vid}: proved in only {hr*100:.0f}% of runs (must-find floor is 100%)")
    return out
