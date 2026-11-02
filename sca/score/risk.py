"""Risk score — deterministic code only.

    risk = 100 × likelihood × impact
    likelihood = 1.0 if any CVE of the finding is in CISA KEV else max EPSS over its CVEs
                 (prior from config when no CVE / no EPSS)
    impact     = (CVSS / 10) × exposure_weight × criticality_weight × (dev_weight if dev-only)
"""
from __future__ import annotations

import re

from pydantic import BaseModel

from sca.config import Asset, ScoringConfig
from sca.ingest.schema import CvssScore, Finding

def cvss_band(score: float) -> str:
    """CVSS v3/v4 qualitative band of the chosen score (scanner labels may come from another record)."""
    return ("Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0
            else "Low" if score > 0 else "None")


def vuln_sort_key(vid: str) -> tuple:
    m = re.match(r"CVE-(\d+)-(\d+)$", vid)
    return (0, int(m.group(1)), int(m.group(2)), "") if m else (1, 0, 0, vid)


SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}


class Scored(BaseModel):
    finding: Finding
    cvss: float
    cvss_version: str
    cvss_source: str
    epss: float | None
    epss_percentile: float | None
    epss_source: str               # first.org | prior
    kev: bool
    kev_date_added: str = ""
    info_gap: bool = False         # no KEV and no EPSS → likelihood is a prior, needs human eye
    likelihood: float
    impact: float
    score: float


def pick_cvss(scores: list[CvssScore]) -> CvssScore | None:
    """v3.x first (NVD Primary preferred, then highest), then v4.0, then v2 — highest within."""
    def tier(c: CvssScore) -> int:
        if c.version.startswith("3"):
            return 0
        if c.version.startswith("4"):
            return 1
        return 2
    if not scores:
        return None
    best_tier = min(tier(c) for c in scores)
    cands = [c for c in scores if tier(c) == best_tier]
    nvd = [c for c in cands if "nvd" in c.source and c.type == "Primary"]
    return max(nvd or cands, key=lambda c: c.base_score)


def epss_prior(cfg: ScoringConfig, epss: dict[str, dict]) -> float:
    p = cfg.likelihood["epss_missing_prior"]
    if p != "median":
        return float(p)
    vals = sorted(r["epss"] for r in epss.values())
    if not vals:
        return 0.0
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def score_finding(f: Finding, asset: Asset, epss: dict[str, dict], kev: dict[str, dict],
                  cfg: ScoringConfig, prior: float) -> Scored:
    c = pick_cvss(f.cvss)
    if c:
        cvss, cver, csrc = c.base_score, c.version, c.source
    else:
        cvss, cver, csrc = cfg.cvss_fallback.get(f.severity, cfg.cvss_fallback["Unknown"]), "", "severity-fallback"

    cves = f.cve_ids
    e_rows = [epss[c] for c in cves if c in epss]
    kev_hits = [kev[c] for c in cves if c in kev]
    if e_rows:
        top = max(e_rows, key=lambda r: r["epss"])
        e, pct, esrc = top["epss"], top["percentile"], "first.org"
    else:
        e, pct, esrc = None, None, "prior"
    likelihood = float(cfg.likelihood["kev"]) if kev_hits else (e if e is not None else prior)
    impact = (cvss / 10.0) * cfg.exposure_weight[asset.exposure] * cfg.criticality_weight[asset.criticality]
    if f.package.dev:
        impact *= cfg.dev_weight
    return Scored(
        finding=f, cvss=cvss, cvss_version=cver, cvss_source=csrc,
        epss=e, epss_percentile=pct, epss_source=esrc,
        info_gap=not kev_hits and e is None,
        kev=bool(kev_hits), kev_date_added=min((k["dateAdded"] for k in kev_hits), default=""),
        likelihood=likelihood, impact=round(impact, 6), score=round(100 * likelihood * impact, 4),
    )


def rank_by_score(rows: list[Scored]) -> list[Scored]:
    return sorted(rows, key=lambda r: (-r.score, -r.cvss, vuln_sort_key(r.finding.vuln_id), r.finding.service,
                                       r.finding.package.key))


def rank_by_severity(rows: list[Scored]) -> list[Scored]:
    """Baseline a scanner UI gives you: CVSS desc (band of the same score as tiebreak)."""
    return sorted(rows, key=lambda r: (-r.cvss, -SEVERITY_RANK.get(cvss_band(r.cvss), 0),
                                       vuln_sort_key(r.finding.vuln_id), r.finding.service, r.finding.package.key))
