"""Fill CVE aliases from OSV for advisories the scanner reported only by GHSA id, so EPSS/KEV
lookups (keyed by CVE) don't miss them."""
from __future__ import annotations

from sca.ingest.parsers import canonical_id, merge_findings
from sca.ingest.schema import Finding


def advisory_ids(findings: list[Finding]) -> list[str]:
    return sorted({a for f in findings for a in [f.vuln_id, *f.aliases] if not a.startswith("CVE-")})


def apply_osv_aliases(findings: list[Finding], osv: dict[str, dict]) -> tuple[list[Finding], int]:
    added = 0
    for f in findings:
        ids = {f.vuln_id, *f.aliases}
        extra = {a for i in ids for a in (osv.get(i) or {}).get("aliases", []) if a.startswith("CVE-")}
        new = extra - ids
        if not new:
            continue
        added += 1
        ids |= new
        f.vuln_id = canonical_id(f.vuln_id, sorted(ids))
        f.aliases = sorted(ids - {f.vuln_id})
    return merge_findings(findings), added
