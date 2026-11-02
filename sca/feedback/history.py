"""Run snapshots + rescan verification (did a 'fixed' remediation actually remove the finding?)."""
from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from sca.config import OUT_DIR
from sca.contracts import Judgment, finding_id
from sca.feedback.store import FeedbackStore, pkg_name_key

HISTORY_DIR = OUT_DIR / "history"


def _dirname(run_at: str) -> str:
    return run_at.replace(":", "")          # 2026-11-01T120000Z — filesystem-safe, still sortable


def _row_id(r: dict) -> str:
    return finding_id(r["service"], f"{r['ecosystem']}:{r['package']}@{r['version']}", r["vuln_id"])


def _jdump(judgments) -> list[dict]:
    return [j.model_dump() if isinstance(j, Judgment) else dict(j) for j in (judgments or [])]


def snapshot(run_at: str, rows: list[dict], judgments: list[Judgment] | None,
             out_dir: Path | str = HISTORY_DIR) -> Path:
    """Write <out_dir>/<run_at>/ranked.csv + judgments.json; returns the snapshot dir."""
    d = Path(out_dir) / _dirname(run_at)
    d.mkdir(parents=True, exist_ok=True)
    cols = list(rows[0].keys()) if rows else ["service", "ecosystem", "package", "version", "vuln_id", "score"]
    with (d / "ranked.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    (d / "judgments.json").write_text(json.dumps({"run_at": run_at, "judgments": _jdump(judgments)},
                                                 ensure_ascii=False, indent=1), encoding="utf-8")
    return d


def latest_snapshot(before: str | None = None, out_dir: Path | str = HISTORY_DIR) -> Path | None:
    """Most recent snapshot dir strictly before `before` (run_at), or the latest overall."""
    base = Path(out_dir)
    if not base.exists():
        return None
    dirs = sorted(p for p in base.iterdir() if p.is_dir() and (p / "ranked.csv").exists())
    if before:
        dirs = [p for p in dirs if p.name < _dirname(before)]
    return dirs[-1] if dirs else None


def load_snapshot(d: Path | str) -> tuple[list[dict], list[dict]]:
    d = Path(d)
    with (d / "ranked.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    jp = d / "judgments.json"
    js = json.loads(jp.read_text(encoding="utf-8")).get("judgments", []) if jp.exists() else []
    return rows, js


def _totals(rows: list[dict], judgments: list[dict]) -> dict:
    return {"rows": len(rows), "score": round(sum(float(r.get("score") or 0) for r in rows), 4),
            "affected": sum(j.get("verdict") == "affected" for j in judgments)}


def rescan_verify(prev_snapshot_dir: Path | str | None, rows: list[dict], judgments: list[Judgment] | None,
                  store: FeedbackStore | None = None,
                  scanned_services: Iterable[str] | None = None) -> dict:
    """Diff previous snapshot vs current rows; verify each 'fixed' decision against the rescan.

    fixed decision → 'verified' if no current finding matches (service, eco:name, vuln)
    (any version; scope all_services → any service), else 'not_verified'.
    scanned_services: services whose rescan succeeded (e.g. names of built inventories); a
    service-scoped fixed decision for a service not in it is 'not_verified' (absence of rows
    from a failed scan proves nothing). None → no such check (a clean service has no rows)."""
    prev_rows, prev_js = load_snapshot(prev_snapshot_dir) if prev_snapshot_dir else ([], [])
    cur_js = _jdump(judgments)
    prev_ids = {_row_id(r) for r in prev_rows}
    cur_ids = {_row_id(r) for r in rows}
    cur_keys = {(r["service"], f"{r['ecosystem']}:{r['package']}", r["vuln_id"]) for r in rows}
    cur_keys |= {(r["service"], f"{r['ecosystem']}:{r['package']}", a)
                 for r in rows for a in str(r.get("aliases") or "").split()}

    scanned = set(scanned_services) if scanned_services is not None else None
    fixed = []
    for d in (store.decisions() if store else []):
        if d.reason != "fixed":
            continue
        pkg = pkg_name_key(d.package)
        still = [k for k in cur_keys if k[1] == pkg and k[2] == d.vuln_id
                 and (d.scope == "all_services" or k[0] == d.service)]
        missing = scanned is not None and d.scope == "service" and d.service not in scanned
        fixed.append({"service": d.service, "package": pkg, "vuln_id": d.vuln_id, "scope": d.scope,
                      "at": d.at, "status": "not_verified" if (still or missing) else "verified",
                      "still_present_in": sorted({k[0] for k in still}),
                      "service_not_in_rescan": missing})
    return {
        "prev_snapshot": str(prev_snapshot_dir) if prev_snapshot_dir else None,
        "resolved": sorted(prev_ids - cur_ids),
        "new": sorted(cur_ids - prev_ids),
        "persisting": sorted(prev_ids & cur_ids),
        "fixed_decisions": fixed,
        "fixed_verified": sum(f["status"] == "verified" for f in fixed),
        "fixed_not_verified": sum(f["status"] == "not_verified" for f in fixed),
        "before": _totals(prev_rows, prev_js),
        "after": _totals(rows, cur_js),
    }
