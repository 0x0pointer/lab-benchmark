"""Tier-1 deterministic matcher: map an agent-smith finding onto a ground-truth id.

Scoring combines three gated signals:
  * class gate   — finding's inferred vuln-class must intersect the candidate id's
                   class set (prevents a BOLA finding on /check_balance mapping onto
                   the SQLi id that shares the same path).
  * hint score   — how many of the id's ``match_hints`` appear in the finding text
                   (endpoint-specific hints like "/api/transactions" weigh double).
  * path score   — canonical-path equality (+4) or significant-segment overlap (+2).

This is fully deterministic and byte-reproducible. The Tier-2 LLM judge (Phase 4)
only adjudicates leftovers and dedup; it never creates or destroys a match here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .canonicalize import (
    canonicalize_path,
    gt_classes,
    infer_finding_classes,
    is_negative_result,
)
from .parse_artifacts import Finding
from .registry import Registry, Vuln

MATCH_THRESHOLD = 2.0
_STOP_SEGMENTS = {"", "api", "v1", "v2", "v3", "{id}", "latest", "static"}


def _significant_segments(canon: str) -> set[str]:
    return {s for s in canon.split("/") if s and s not in _STOP_SEGMENTS}


@dataclass
class Match:
    finding: Finding
    gt_id: str | None
    score: float
    hint_hits: list[str] = field(default_factory=list)
    finding_classes: set[str] = field(default_factory=set)
    path_relation: str = "none"          # equal | overlap | none
    negative_result: bool = False
    candidates: list[tuple[str, float]] = field(default_factory=list)  # (id, score) for transparency


def _hint_weight(h: str) -> float:
    hl = h.lower()
    specific = ("/" in hl) or hl.startswith("llm") or any(c.isdigit() for c in hl) or len(hl) >= 12
    return 2.0 if specific else 1.0


def _score_pair(f_title: str, f_body: str, f_canon: str, f_classes: set[str], v: Vuln) -> tuple[float, list[str], str]:
    v_classes = gt_classes(v.id)
    # class gate: if both sides have a class opinion, they must intersect.
    # f_classes is inferred from the TITLE (the finding's declared identity) so an
    # incidental keyword in the body (e.g. an XSS sink that "fires in the admin panel")
    # cannot pull the finding onto an unrelated id.
    if f_classes and v_classes and not (f_classes & v_classes):
        return 0.0, [], "none"

    f_text = f_title + " " + f_body
    title_hits = [h for h in v.match_hints if h.lower() in f_title]
    body_hits = [h for h in v.match_hints if h.lower() in f_body and h.lower() not in f_title]
    # title hits count double (the headline states what the finding IS)
    hint_score = sum(2.0 * _hint_weight(h) for h in title_hits) + sum(_hint_weight(h) for h in body_hits)
    hits = title_hits + body_hits

    # path
    v_canon = canonicalize_path(v.path) if v.path and not v.path.startswith("<") else ""
    path_score, relation = 0.0, "none"
    if v_canon and f_canon:
        if v_canon == f_canon:
            path_score, relation = 4.0, "equal"
        elif _significant_segments(v_canon) & _significant_segments(f_canon):
            path_score, relation = 2.0, "overlap"
    if relation == "none" and v_canon:
        for seg in _significant_segments(v_canon):
            if seg.replace("_", " ") in f_text or seg in f_text:
                path_score, relation = max(path_score, 1.5), "text"
                break

    class_bonus = 2.0 if (f_classes & v_classes) else 0.0
    return hint_score + path_score + class_bonus, hits, relation


def match_finding(finding: Finding, reg: Registry) -> Match:
    f_title = finding.title.lower()
    f_body = " ".join(x for x in (finding.description, finding.evidence,
                                  finding.business_impact, finding.target) if x).lower()
    f_canon = canonicalize_path(finding.target)
    f_text = f_title + " " + f_body
    # class from the title first; fall back to full text only if the title is class-silent
    f_classes = infer_finding_classes(f_title) or infer_finding_classes(f_text)

    scored: list[tuple[float, Vuln, list[str], str]] = []
    for v in reg.vulns:
        if not v.enabled:
            continue  # extension not deployed
        s, hits, rel = _score_pair(f_title, f_body, f_canon, f_classes, v)
        if s > 0:
            scored.append((s, v, hits, rel))

    scored.sort(key=lambda x: x[0], reverse=True)
    candidates = [(v.id, round(s, 2)) for s, v, _, _ in scored[:4]]

    if scored and scored[0][0] >= MATCH_THRESHOLD:
        s, v, hits, rel = scored[0]
        return Match(
            finding=finding, gt_id=v.id, score=round(s, 2), hint_hits=hits,
            finding_classes=f_classes, path_relation=rel,
            negative_result=is_negative_result(f_text), candidates=candidates,
        )
    return Match(
        finding=finding, gt_id=None, score=round(scored[0][0], 2) if scored else 0.0,
        finding_classes=f_classes, negative_result=is_negative_result(f_text),
        candidates=candidates,
    )


def match_all(findings: list[Finding], reg: Registry) -> list[Match]:
    return [match_finding(f, reg) for f in findings]
