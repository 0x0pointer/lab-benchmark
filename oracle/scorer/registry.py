"""Load + validate ground_truth.yaml into typed vuln records."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_GROUND_TRUTH = os.path.join(_REPO_ROOT, "ground_truth.yaml")

_VALID_EXPOSURE = {"reachable", "mitigated", "blocked", "not-present"}
_VALID_STRENGTH = {"proves-exploit", "proves-attempt", "proof-by-oracle-probe", "reported-only"}


@dataclass
class Vuln:
    id: str
    title: str
    owasp: str
    cwe: str
    endpoint: dict[str, Any]
    severity: str
    source_ref: str = ""
    detection_difficulty: str = "medium"
    exposure: dict[str, str] = field(default_factory=lambda: {"raw": "reachable", "hardened": "reachable"})
    oracle_signals: list[dict[str, str]] = field(default_factory=list)
    match_hints: list[str] = field(default_factory=list)
    must_find: bool = False
    runtime: str = "live"
    enabled: bool = True
    notes: str = ""
    blind: bool = False

    @property
    def path(self) -> str:
        return str(self.endpoint.get("path", ""))

    @property
    def method(self) -> str:
        return str(self.endpoint.get("method", "ANY")).upper()

    def reachable_on(self, profile: str) -> bool:
        return self.exposure.get(profile, "reachable") == "reachable"

    def status_on(self, profile: str) -> str:
        return self.exposure.get(profile, "reachable")


@dataclass
class Registry:
    meta: dict[str, Any]
    vulns: list[Vuln]

    def by_id(self, vid: str) -> Vuln | None:
        for v in self.vulns:
            if v.id == vid:
                return v
        return None

    def live_enabled(self) -> list[Vuln]:
        """Vulns that actually run in the lab (enabled + not source-only)."""
        return [v for v in self.vulns if v.enabled and v.runtime != "source-only"]

    def scorable(self, profile: str) -> list[Vuln]:
        """Vulns that count toward recall on a profile (live, enabled, reachable)."""
        return [v for v in self.live_enabled() if v.reachable_on(profile)]

    def must_find(self, profile: str) -> list[Vuln]:
        return [v for v in self.scorable(profile) if v.must_find]


def load_registry(path: str | None = None) -> Registry:
    path = path or DEFAULT_GROUND_TRUTH
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    meta = doc.get("meta", {})
    vulns = [Vuln(**_coerce(entry)) for entry in doc.get("vulns", [])]
    _validate(vulns)
    return Registry(meta=meta, vulns=vulns)


def _coerce(entry: dict[str, Any]) -> dict[str, Any]:
    # tolerate unknown future keys by dropping them, keep only dataclass fields
    allowed = set(Vuln.__dataclass_fields__.keys())
    return {k: v for k, v in entry.items() if k in allowed}


def _validate(vulns: list[Vuln]) -> None:
    errs: list[str] = []
    seen: set[str] = set()
    for v in vulns:
        if not v.id:
            errs.append("vuln with empty id")
            continue
        if v.id in seen:
            errs.append(f"duplicate id: {v.id}")
        seen.add(v.id)
        for prof, status in v.exposure.items():
            if status not in _VALID_EXPOSURE:
                errs.append(f"{v.id}: bad exposure '{status}' for profile '{prof}'")
        for sig in v.oracle_signals:
            s = sig.get("strength")
            if s and s not in _VALID_STRENGTH:
                errs.append(f"{v.id}: bad oracle_signal strength '{s}'")
        if not v.match_hints:
            errs.append(f"{v.id}: no match_hints (matcher cannot map findings to it)")
    if errs:
        raise ValueError("ground_truth.yaml validation failed:\n  - " + "\n  - ".join(errs))


if __name__ == "__main__":
    import sys
    reg = load_registry(sys.argv[1] if len(sys.argv) > 1 else None)
    live = reg.live_enabled()
    print(f"OK: {len(reg.vulns)} vulns total | {len(live)} live+enabled | "
          f"{sum(1 for v in reg.vulns if v.id.startswith('EXT-'))} extensions | "
          f"{sum(1 for v in reg.vulns if v.must_find)} must-find")
    print(f"raw scorable: {len(reg.scorable('raw'))} | hardened scorable: {len(reg.scorable('hardened'))}")
