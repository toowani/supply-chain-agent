"""ranked.csv + Markdown summary (graph numbers, direct vs transitive, severity vs score Top-10)."""
from __future__ import annotations

import csv
from pathlib import Path

import networkx as nx

from sca.config import Asset
from sca.graph.build import blast_radius, explain_path
from sca.ingest.inventory import dependency_class
from sca.ingest.schema import ServiceInventory
from sca.score.risk import Scored, cvss_band

CSV_FIELDS = [
    "rank", "service", "owner_team", "exposure", "criticality", "ecosystem", "package", "version",
    "dependency", "dev", "vuln_id", "aliases", "severity", "severity_cvss", "cvss", "cvss_version", "cvss_source",
    "epss", "epss_percentile", "epss_source", "info_gap", "kev", "kev_date_added", "likelihood", "impact",
    "score", "severity_rank", "verdict", "rule", "fix_version", "fix_state", "blast_radius", "path",
]


def clip(text, n: int) -> str:
    """One line, at most n chars, cut at a word boundary with '…' (never mid-word when a space
    exists in the last 40%)."""
    t = " ".join(str(text).split())
    if len(t) <= n:
        return t
    cut = t[:n - 1]
    sp = cut.rfind(" ")
    if sp >= int(n * 0.6):
        cut = cut[:sp]
    return cut.rstrip(" ,;:·") + "…"


def _fmt(x, nd=4):
    return "" if x is None else (f"{x:.{nd}f}" if isinstance(x, float) else x)


def build_rows(ranked: list[Scored], by_sev: list[Scored], invs: list[ServiceInventory],
               assets: dict[str, Asset], g: nx.DiGraph) -> list[dict]:
    cls = {inv.service: dependency_class(inv) for inv in invs}
    sev_rank = {id(r): i + 1 for i, r in enumerate(by_sev)}
    rows = []
    for i, r in enumerate(ranked, 1):
        f, a = r.finding, assets[r.finding.service]
        rows.append({
            "rank": i, "service": f.service, "owner_team": a.owner_team, "exposure": a.exposure,
            "criticality": a.criticality, "ecosystem": f.package.ecosystem, "package": f.package.name,
            "version": f.package.version, "dependency": cls[f.service].get(f.package.key, "?"),
            "dev": f.package.dev, "vuln_id": f.vuln_id, "aliases": " ".join(f.aliases),
            "severity": f.severity, "severity_cvss": cvss_band(r.cvss), "cvss": r.cvss, "cvss_version": r.cvss_version,
            "cvss_source": r.cvss_source, "epss": _fmt(r.epss, 5),
            "epss_percentile": _fmt(r.epss_percentile, 5), "epss_source": r.epss_source, "info_gap": r.info_gap,
            "kev": r.kev, "kev_date_added": r.kev_date_added, "likelihood": _fmt(r.likelihood, 5),
            "impact": _fmt(r.impact, 4), "score": _fmt(r.score, 3), "severity_rank": sev_rank[id(r)],
            "fix_version": f.fix_versions[0] if f.fix_versions else "", "fix_state": f.fix_state,
            "blast_radius": " ".join(blast_radius(g, f.vuln_id)),
            "path": " > ".join(explain_path(g, f.service, f.package.key)),
        })
    return rows


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)


def _table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def _label(r: Scored) -> str:
    f = r.finding
    return f"{f.service} · {f.package.name}@{f.package.version} · {f.vuln_id}"


def compare_top10(ranked: list[Scored], by_sev: list[Scored], assets: dict[str, Asset],
                  k: int = 10) -> tuple[str, dict]:
    sev_pos = {id(r): i + 1 for i, r in enumerate(by_sev)}
    score_pos = {id(r): i + 1 for i, r in enumerate(ranked)}
    rows = []
    for i in range(min(k, len(ranked))):
        s, c = by_sev[i], ranked[i]
        rows.append([i + 1,
                     _label(s), s.cvss, "Y" if s.kev else "", _fmt(s.epss, 4), score_pos[id(s)],
                     _label(c), _fmt(c.score, 2), c.cvss, "Y" if c.kev else "", _fmt(c.epss, 4),
                     sev_pos[id(c)]])
    top_s, top_c = by_sev[:k], ranked[:k]
    overlap = len({id(r) for r in top_s} & {id(r) for r in top_c})

    def stats(xs):
        return {"kev": sum(r.kev for r in xs),
                "internet": sum(assets[r.finding.service].exposure == "internet" for r in xs),
                "fixable": sum(bool(r.finding.fix_versions) for r in xs),
                "services": len({r.finding.service for r in xs}),
                "with_epss": sum(r.epss is not None for r in xs),
                "prior": sum(r.info_gap for r in xs),
                "mean_epss": round(sum(r.epss for r in xs if r.epss is not None)
                                   / max(sum(r.epss is not None for r in xs), 1), 4),
                "max_epss": round(max((r.epss or 0) for r in xs), 4) if xs else 0}
    st = {"k": k, "overlap": overlap, "severity": stats(top_s), "score": stats(top_c)}
    md = _table(["#", "심각도(CVSS) 정렬", "CVSS", "KEV", "EPSS", "→종합순위",
                 "종합 점수 정렬", "점수", "CVSS", "KEV", "EPSS", "→심각도순위"], rows)
    return md, st
