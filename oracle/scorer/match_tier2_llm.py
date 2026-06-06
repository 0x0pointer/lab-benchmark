"""Tier-2 LLM-judge matcher — ADVISORY ONLY, off the deterministic counting path.

Tier-1 (``match.py``) is the gate: pure, byte-reproducible, and the sole source of
the scorecard metrics + must-find verdict. This module asks an LLM to adjudicate the
*leftovers* — agent-smith findings Tier-1 could not map to any ground-truth id — and
to flag duplicates. Nothing here ever changes a Tier-1 match, a metric, or the gate.

Determinism is preserved by caching every verdict to a JSON file keyed by
``sha256(title|description|target|registry_version|model_id)``. Identical input ->
identical cached output, so re-runs are byte-reproducible and only *novel* finding
text reaches the API. The Anthropic SDK is imported LAZILY and the whole module
degrades to ``[]`` (no adjudication) when the SDK is missing, no API key is set, or
no client is available — the deterministic gate must never depend on this.

Usage (wired behind the ``--llm-judge`` flag on the ``score`` subcommand):

    from .match_tier2_llm import judge_unmatched
    verdicts = judge_unmatched(unmatched_findings, reg)   # [] if no key/SDK
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field

from .parse_artifacts import Finding
from .registry import Registry

DEFAULT_MODEL = "claude-sonnet-4-6"   # honors temperature=0 (Opus 4.7/4.8 reject it)
DEFAULT_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".judge_cache.json")
CONFIDENCE_FLOOR = 0.7                 # below this -> 'none' (human review)
_NONE = "none"


@dataclass
class Verdict:
    """One LLM adjudication of a single Tier-1-unmatched finding (advisory)."""
    finding_title: str
    finding_target: str
    gt_id: str | None          # chosen ground-truth id, or None (= 'none'/no map)
    confidence: float
    is_duplicate_of: str | None
    rationale: str
    cached: bool = False       # served from the verdict cache (not the API)

    def to_dict(self) -> dict:
        return asdict(self)


def registry_version(reg: Registry) -> str:
    """Stable fingerprint of the scorable registry surface, for cache-key isolation.

    Folds the schema_version and the sorted enabled-vuln ids so that adding/enabling
    a vuln (which changes the candidate enum the LLM chooses from) invalidates stale
    cached verdicts — without depending on volatile meta like app_commit=TBD."""
    schema = str(reg.meta.get("schema_version", "?"))
    ids = ",".join(sorted(v.id for v in reg.vulns if v.enabled))
    return f"{schema}:{hashlib.sha256(ids.encode()).hexdigest()[:12]}"


def _cache_key(finding: Finding, reg_version: str, model_id: str) -> str:
    raw = "|".join((finding.title or "", finding.description or "",
                    finding.target or "", reg_version, model_id))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_cache(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cache(path: str, cache: dict) -> None:
    # sort_keys for byte-reproducible cache files
    with open(path, "w") as fh:
        json.dump(cache, fh, indent=2, sort_keys=True)


def _candidate_ids(reg: Registry) -> list[str]:
    """The id enum the LLM may choose from: live, enabled vulns (the scorable surface)."""
    return sorted(v.id for v in reg.live_enabled())


def _registry_summary(reg: Registry, ids: list[str]) -> str:
    """Compact, deterministic registry description cached as the prompt prefix."""
    by_id = {v.id: v for v in reg.vulns}
    lines = [
        "You are adjudicating a security pentest oracle. Below is the catalogue of "
        "known ground-truth vulnerabilities in the VulnBank target. For a given "
        "agent-smith finding that the deterministic matcher could NOT map, decide "
        "which ground_truth_id (if any) it describes, and whether it duplicates "
        "another finding. Choose 'none' if it matches no catalogue entry or you are "
        "not confident.",
        "",
        "GROUND-TRUTH CATALOGUE:",
    ]
    for vid in ids:
        v = by_id.get(vid)
        if not v:
            continue
        hints = ", ".join(v.match_hints[:6])
        ep = f"{v.method} {v.path}".strip()
        lines.append(f"- {vid} [{v.owasp}] {v.title} | endpoint: {ep} | hints: {hints}")
    return "\n".join(lines)


def _classify_tool(ids: list[str]) -> dict:
    """Single constrained tool: id must be one of the catalogue ids or 'none'."""
    return {
        "name": "classify",
        "description": "Record the adjudication for one unmatched finding.",
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "ground_truth_id": {
                    "type": "string",
                    "enum": ids + [_NONE],
                    "description": "The ground-truth id this finding describes, or "
                                   "'none' if it matches no catalogue entry.",
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence 0.0-1.0 in the chosen id.",
                },
                "is_duplicate_of": {
                    "type": ["string", "null"],
                    "description": "The id of another finding this duplicates, or null.",
                },
                "rationale": {
                    "type": "string",
                    "description": "One-sentence justification.",
                },
            },
            "required": ["ground_truth_id", "confidence", "is_duplicate_of", "rationale"],
            "additionalProperties": False,
        },
    }


def _finding_prompt(finding: Finding) -> str:
    parts = [f"FINDING TITLE: {finding.title}"]
    if finding.target:
        parts.append(f"TARGET: {finding.target}")
    if finding.severity:
        parts.append(f"SEVERITY: {finding.severity}")
    if finding.description:
        parts.append(f"DESCRIPTION: {finding.description}")
    if finding.evidence:
        parts.append(f"EVIDENCE: {finding.evidence}")
    parts.append("\nCall the `classify` tool with your adjudication.")
    return "\n".join(parts)


def _maybe_client(client):
    """Return a usable Anthropic client, or None (graceful fallback)."""
    if client is not None:
        return client
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # lazy: degrade gracefully if the package is missing
    except ImportError:
        return None
    try:
        return anthropic.Anthropic()
    except Exception:
        return None


def _extract_tool_input(resp) -> dict | None:
    """Pull the `classify` tool_use input from a Messages API response."""
    content = getattr(resp, "content", None) or []
    for block in content:
        btype = getattr(block, "type", None) or (block.get("type") if isinstance(block, dict) else None)
        if btype == "tool_use":
            name = getattr(block, "name", None) or (block.get("name") if isinstance(block, dict) else None)
            if name == "classify":
                inp = getattr(block, "input", None)
                if inp is None and isinstance(block, dict):
                    inp = block.get("input")
                return inp
    return None


def _verdict_from_input(finding: Finding, inp: dict) -> Verdict:
    gt = inp.get("ground_truth_id")
    conf = float(inp.get("confidence", 0.0) or 0.0)
    dup = inp.get("is_duplicate_of")
    rationale = inp.get("rationale", "") or ""
    # low-confidence or explicit 'none' -> no map (human review)
    if gt == _NONE or conf < CONFIDENCE_FLOOR:
        gt = None
    return Verdict(
        finding_title=finding.title, finding_target=finding.target,
        gt_id=gt, confidence=conf, is_duplicate_of=dup, rationale=rationale,
    )


def judge_unmatched(findings_unmatched: list[Finding], registry: Registry, *,
                    model: str | None = None, cache_path: str | None = None,
                    client=None) -> list[Verdict]:
    """Adjudicate Tier-1-unmatched findings with an LLM (advisory only).

    Returns one Verdict per input finding, or ``[]`` if no client is available
    (SDK missing / no ANTHROPIC_API_KEY / no injected client). Verdicts are cached
    by ``sha256(title|description|target|registry_version|model_id)`` so identical
    input is byte-reproducible and only novel finding text hits the API.

    The fake-client injection path (``client=...``) is the testing seam: any object
    exposing ``client.messages.create(...)`` returning a tool_use block works.
    """
    if not findings_unmatched:
        return []

    model_id = model or DEFAULT_MODEL
    cache_file = cache_path or DEFAULT_CACHE_PATH
    reg_version = registry_version(registry)
    ids = _candidate_ids(registry)

    cache = _load_cache(cache_file)
    cache_dirty = False
    verdicts: list[Verdict] = []
    live_client = None  # resolved lazily only when we actually need the API

    system_blocks = None  # built once, prompt-cached across findings

    for finding in findings_unmatched:
        key = _cache_key(finding, reg_version, model_id)
        if key in cache:
            v = Verdict(**cache[key])
            v.cached = True
            verdicts.append(v)
            continue

        # cache miss -> need the API. Resolve the client lazily; bail out gracefully.
        if live_client is None:
            live_client = _maybe_client(client)
            if live_client is None:
                return []   # no adjudication available; never touch the gate
            system_blocks = [{
                "type": "text",
                "text": _registry_summary(registry, ids),
                "cache_control": {"type": "ephemeral"},   # cache the registry prefix
            }]

        resp = live_client.messages.create(
            model=model_id,
            max_tokens=1024,
            temperature=0,
            system=system_blocks,
            tools=[_classify_tool(ids)],
            tool_choice={"type": "tool", "name": "classify"},
            messages=[{"role": "user", "content": _finding_prompt(finding)}],
        )
        inp = _extract_tool_input(resp)
        if inp is None:
            # model didn't emit the tool — treat as 'none', don't cache a non-answer
            verdicts.append(Verdict(
                finding_title=finding.title, finding_target=finding.target,
                gt_id=None, confidence=0.0, is_duplicate_of=None,
                rationale="no classify tool_use in response",
            ))
            continue

        v = _verdict_from_input(finding, inp)
        cache[key] = v.to_dict()   # cached=False persisted; re-read sets cached=True
        cache_dirty = True
        verdicts.append(v)

    if cache_dirty:
        _save_cache(cache_file, cache)
    return verdicts


def render_adjudication(verdicts: list[Verdict]) -> str:
    """Advisory text block for the CLI. Does NOT feed any metric."""
    if not verdicts:
        return "LLM-judge adjudication: (none — no unmatched findings, or no API key/SDK)"
    L = ["LLM-judge adjudication (ADVISORY — does not change scorecard or must-find gate):"]
    mapped = [v for v in verdicts if v.gt_id]
    review = [v for v in verdicts if not v.gt_id]
    for v in mapped:
        src = "cache" if v.cached else "api"
        dup = f"  dup-of={v.is_duplicate_of}" if v.is_duplicate_of else ""
        L.append(f"  ~ {v.finding_title[:48]:48s} -> {v.gt_id:26s} "
                 f"(conf {v.confidence:.2f}, {src}){dup}")
    for v in review:
        src = "cache" if v.cached else "api"
        L.append(f"  ? {v.finding_title[:48]:48s} -> none / human-review "
                 f"(conf {v.confidence:.2f}, {src})")
    L.append(f"  [{len(mapped)} suggested map(s), {len(review)} for human review]")
    return "\n".join(L)
