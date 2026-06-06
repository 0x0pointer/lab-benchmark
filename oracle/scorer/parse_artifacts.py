"""Parse agent-smith output artifacts into normalized records."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    target: str
    description: str = ""
    evidence: str = ""
    tool_used: str = ""
    cve: str = ""
    business_impact: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """All searchable text for class inference + hint matching."""
        return " ".join(
            x for x in (self.title, self.description, self.evidence,
                        self.business_impact, self.target)
            if x
        )


def load_findings(path: str) -> list[Finding]:
    with open(path) as fh:
        doc = json.load(fh)
    items = doc.get("findings", doc) if isinstance(doc, dict) else doc
    out: list[Finding] = []
    for f in items:
        out.append(Finding(
            id=f.get("id", ""),
            title=f.get("title", ""),
            severity=f.get("severity", ""),
            target=f.get("target", ""),
            description=f.get("description", ""),
            evidence=f.get("evidence", ""),
            tool_used=f.get("tool_used", ""),
            cve=f.get("cve", ""),
            business_impact=f.get("business_impact", ""),
            raw=f,
        ))
    return out


def load_coverage(path: str) -> dict[str, Any]:
    """Return coverage_matrix.json (meta/endpoints/matrix) or empty if absent."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
