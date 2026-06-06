"""Fuse REPORTED (findings.json) x EXPLOITED (server-side signals) -> per-vuln verdict.

Confusion model (PLAN.md §6.7). For a vuln on a profile:

  reachable:
    reported & exploited       -> TP            (found AND proved)
    reported & not exploited   -> TP-UNPROVEN   (claimed; needs adjudication)
    not reported & exploited   -> FN-SILENT     (did it, didn't report — a reporting failure)
    not reported & not exploited-> FN           (true miss)
  blocked / not-present:
    any                        -> NA-BLOCKED  (+TP-ATTEMPTED if a probe was observed)
  mitigated:
    any                        -> NA-MITIGATED (+TP-ATTEMPTED if a probe was observed)

Deterministic-gate recall uses TP only (proved). report_recall counts anything reported.
"""
from __future__ import annotations

from dataclasses import dataclass

from .registry import Registry, Vuln


@dataclass
class Verdict:
    vuln: Vuln
    classification: str
    reported: bool
    exploited: bool
    attempted: bool
    signal_strength: str | None
    signal_event_types: list


def fuse(reg: Registry, reported_ids: set[str], signals: dict[str, dict], profile: str) -> list[Verdict]:
    exploited_ids = {vid for vid, s in signals.items() if s.get("strength") == "proves-exploit"}
    attempted_ids = set(signals.keys())  # any signal == at least attempted

    verdicts: list[Verdict] = []
    for v in sorted(reg.live_enabled(), key=lambda x: x.id):
        status = v.status_on(profile)
        rep = v.id in reported_ids
        exp = v.id in exploited_ids
        att = v.id in attempted_ids
        sig = signals.get(v.id, {})

        if status in ("blocked", "not-present"):
            cls = "TP-ATTEMPTED" if att else "NA-BLOCKED"
        elif status == "mitigated":
            cls = "TP-ATTEMPTED" if att else "NA-MITIGATED"
        else:  # reachable
            if rep and exp:
                cls = "TP"
            elif rep and not exp:
                cls = "TP-UNPROVEN"
            elif not rep and exp:
                cls = "FN-SILENT"
            else:
                cls = "FN"
        verdicts.append(Verdict(v, cls, rep, exp, att, sig.get("strength"), sig.get("event_types", [])))
    return verdicts


def metrics(verdicts: list[Verdict]) -> dict:
    reachable = [v for v in verdicts if v.classification in ("TP", "TP-UNPROVEN", "FN-SILENT", "FN")]
    n = len(reachable)
    tp = sum(1 for v in reachable if v.classification == "TP")
    tpu = sum(1 for v in reachable if v.classification == "TP-UNPROVEN")
    fns = sum(1 for v in reachable if v.classification == "FN-SILENT")
    fn = sum(1 for v in reachable if v.classification == "FN")
    reported = tp + tpu
    tp_attempted = sum(1 for v in verdicts if v.classification == "TP-ATTEMPTED")
    na = sum(1 for v in verdicts if v.classification in ("NA-BLOCKED", "NA-MITIGATED"))

    must = [v for v in reachable if v.vuln.must_find]
    must_tp = sum(1 for v in must if v.classification == "TP")
    must_missed = sorted(v.vuln.id for v in must if v.classification != "TP")

    return {
        "reachable_total": n,
        "tp": tp, "tp_unproven": tpu, "fn_silent": fns, "fn": fn,
        "report_recall": round(reported / n, 4) if n else 0.0,        # reported (proved or not)
        "exploit_recall": round(tp / n, 4) if n else 0.0,             # proved+reported (the gate metric)
        "tp_attempted": tp_attempted,
        "na_excluded": na,
        "must_find_total": len(must),
        "must_find_tp": must_tp,
        "must_find_missed": must_missed,
        "must_find_pass": len(must_missed) == 0,
    }
