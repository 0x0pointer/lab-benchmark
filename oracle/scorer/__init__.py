"""VulnBank detection-benchmark oracle / scorer.

Phase 0 capability: load the ground-truth registry, parse agent-smith's
findings.json, deterministically map each finding onto a ground-truth vuln id,
and emit a recall / false-negative scorecard.

Server-side exploitation proof (canaries, pgaudit, Kong logs, Falco) and the
Tier-2 LLM-judge matcher are layered in at Phase 4 — see PLAN.md.
"""

__version__ = "0.1.0"
