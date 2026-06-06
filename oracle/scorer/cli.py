"""CLI: score an agent-smith findings.json against the ground-truth registry.

Usage:
  python -m oracle.scorer.cli score \
      --findings /path/to/findings.json \
      [--ground-truth ground_truth.yaml] [--profile raw] \
      [--json out/scorecard.json] [--explain]

  python -m oracle.scorer.cli validate [--ground-truth ground_truth.yaml]
"""
from __future__ import annotations

import argparse
import json
import sys

from .match import match_all
from .parse_artifacts import load_findings
from .regression import aggregate_scorecards, compare, make_baseline, quality_floor_warnings
from .registry import load_registry
from .score import build_scorecard, build_scorecard_v2, render_text, render_v2
from .signals import collect_signals, distinct_run_ids, load_events


def _load_json(path):
    with open(path) as fh:
        return json.load(fh)


def _cmd_validate(args) -> int:
    reg = load_registry(args.ground_truth)
    live = reg.live_enabled()
    ext = [v for v in reg.vulns if v.id.startswith("EXT-")]
    ext_off = sum(1 for v in ext if not v.enabled)
    print(f"OK  {len(reg.vulns)} vulns | {len(live)} live+enabled | "
          f"{len(ext)} extensions ({ext_off} disabled) | "
          f"{sum(1 for v in reg.vulns if v.must_find)} must-find")
    print(f"    raw scorable={len(reg.scorable('raw'))}  hardened scorable={len(reg.scorable('hardened'))}")
    return 0


def _cmd_score(args) -> int:
    reg = load_registry(args.ground_truth)
    findings = load_findings(args.findings)
    matches = match_all(findings, reg)

    if args.events:
        events = load_events(args.events)
        present = distinct_run_ids(events)
        # Guard against the #1 footgun: scoring a STALE or MIXED proof stream (events from a
        # different run / before a reseed) against this findings.json.
        if args.run_id:
            if present and args.run_id not in present:
                print(f"[score] WARNING: no proof events tagged run_id={args.run_id} "
                      f"(events.jsonl contains: {', '.join(present)}). Run "
                      f"`RUN_ID={args.run_id} make collect-events` AFTER the agent attacked THIS "
                      f"lab state — exploit-recall will read ~0 otherwise.", file=sys.stderr)
        elif len(present) > 1:
            print(f"[score] WARNING: events.jsonl mixes {len(present)} runs ({', '.join(present)}); "
                  f"scoring ALL of them. Pass RUN_ID=<id> to isolate one run.", file=sys.stderr)
        elif len(present) == 1:
            print(f"[score] note: scoring proof events from run {present[0]} "
                  f"(pass RUN_ID={present[0]} to pin it; verify it matches this findings.json).",
                  file=sys.stderr)
        signals = collect_signals(events, run_id=args.run_id)
        scorecard = build_scorecard_v2(reg, matches, signals, profile=args.profile)
        print(render_v2(scorecard, reg))
    else:
        scorecard = build_scorecard(reg, matches, profile=args.profile)
        print(render_text(scorecard, reg))

    if args.explain:
        print("\n--- MATCH DETAIL (finding -> ground-truth) ---")
        for m in matches:
            tgt = m.gt_id or "UNMATCHED"
            print(f"  [{m.score:5.1f}] {tgt:26s} <- {m.finding.title[:52]}")
            if not m.gt_id and m.candidates:
                print(f"            closest: {m.candidates[:2]}")

    if args.llm_judge:
        # ADVISORY ONLY: adjudicate Tier-1 leftovers with the LLM judge. This runs
        # AFTER the deterministic scorecard is built and prints alongside it; it
        # never mutates `scorecard` or the must-find gate (computed below).
        from .match_tier2_llm import judge_unmatched, render_adjudication
        unmatched = [m.finding for m in matches if not m.gt_id]
        verdicts = judge_unmatched(unmatched, reg, model=args.llm_model)
        print("\n--- LLM-judge adjudication ---")
        print(render_adjudication(verdicts))

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(scorecard, fh, indent=2, sort_keys=True)
        print(f"\nWrote {args.json}")

    # exit non-zero if the strict must-find gate fails (CI-friendly)
    passed = scorecard["metrics"].get("must_find_pass", True)
    return 0 if passed else 2


def _cmd_aggregate(args) -> int:
    scs = [_load_json(p) for p in args.scorecards]
    agg = aggregate_scorecards(scs)
    out = json.dumps(agg, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(out)
        print(f"Wrote {args.out}  (n_runs={agg['n_runs']}, median exploit-recall="
              f"{agg['exploit_recall']['median']*100:.1f}%)")
    else:
        print(out)
    return 0


def _cmd_baseline_save(args) -> int:
    agg = _load_json(args.aggregate)
    bl = make_baseline(agg, agent_smith_commit=args.agent_smith_commit, notes=args.notes)
    with open(args.out, "w") as fh:
        json.dump(bl, fh, indent=2, sort_keys=True)
    print(f"Wrote baseline {args.out}  (agent-smith={args.agent_smith_commit}, n_runs={agg['n_runs']})")
    warns = quality_floor_warnings(agg)
    if warns:
        print(f"  ⚠ baseline is BELOW the must-find floor ({len(warns)} vulns) — a stronger run/lab "
              f"should prove all must-find vulns before blessing:")
        for w in warns:
            print(f"      - {w}")
    return 0


def _cmd_regress(args) -> int:
    new = _load_json(args.aggregate)
    baseline = _load_json(args.baseline)
    verdict = compare(new, baseline)
    print(f"REGRESSION VERDICT: {verdict['verdict']}  "
          f"(baseline n={verdict['baseline_n_runs']} vs new n={verdict['new_n_runs']})")
    for r in verdict["hard_regressions"]:
        print(f"  ✗ HARD  {r['id']:26s} {r['detail']}")
    for r in verdict["trend_warnings"]:
        print(f"  ~ trend {r['id']:26s} {r['detail']}")
    for r in verdict["improvements"]:
        print(f"  ✓ up    {r['id']:26s} {r['baseline']*100:.0f}% -> {r['new']*100:.0f}%")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(verdict, fh, indent=2, sort_keys=True)
    return 0 if verdict["verdict"] == "PASS" else 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="oracle.scorer", description="VulnBank detection oracle")
    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("validate", help="validate ground_truth.yaml")
    pv.add_argument("--ground-truth", default=None)
    pv.set_defaults(func=_cmd_validate)

    ps = sub.add_parser("score", help="score a findings.json")
    ps.add_argument("--findings", required=True)
    ps.add_argument("--ground-truth", default=None)
    ps.add_argument("--profile", default="raw", choices=["raw", "hardened"])
    ps.add_argument("--events", default=None,
                    help="proof-event stream (LAB_EVENT jsonl) -> Phase-4 reported×exploited scorecard")
    ps.add_argument("--run-id", default=None, help="only count events tagged with this run_id")
    ps.add_argument("--json", default=None, help="write scorecard.json here")
    ps.add_argument("--explain", action="store_true", help="print per-finding match detail")
    ps.add_argument("--llm-judge", action="store_true",
                    help="run the Tier-2 LLM judge over Tier-1-unmatched findings and print "
                         "an ADVISORY adjudication (does not change metrics/gate; needs "
                         "ANTHROPIC_API_KEY + the optional 'anthropic' SDK, else no-op)")
    ps.add_argument("--llm-model", default=None,
                    help="model id for --llm-judge (default: claude-sonnet-4-6)")
    ps.set_defaults(func=_cmd_score)

    pa = sub.add_parser("aggregate", help="combine N run scorecards into per-vuln hit-rates")
    pa.add_argument("scorecards", nargs="+", help="v2 scorecard.json files")
    pa.add_argument("--out", default=None)
    pa.set_defaults(func=_cmd_aggregate)

    pb = sub.add_parser("baseline-save", help="freeze an aggregate as the regression baseline")
    pb.add_argument("--aggregate", required=True)
    pb.add_argument("--out", required=True)
    pb.add_argument("--agent-smith-commit", default="unknown")
    pb.add_argument("--notes", default="")
    pb.set_defaults(func=_cmd_baseline_save)

    pr = sub.add_parser("regress", help="compare an aggregate vs a baseline (exit 2 on regression)")
    pr.add_argument("--aggregate", required=True)
    pr.add_argument("--baseline", required=True)
    pr.add_argument("--json", default=None)
    pr.set_defaults(func=_cmd_regress)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
