"""OSV affected ranges → [[introduced, fixed|""]] and an in-range check — deterministic code only.

Versions are compared with sca.versions (never as strings). Only ECOSYSTEM / SEMVER ranges are
evaluated; GIT ranges carry commit hashes and are ignored.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from sca.ingest.manifests import norm_pypi
from sca.versions import compare

_ECO = {"pypi": "pypi", "npm": "npm"}


class RangeInfo(BaseModel):
    advisory_id: str = ""                       # OSV record that matched the package ("" = none)
    ranges: list[list[str]] = Field(default_factory=list)   # [[introduced, fixed|""]]
    last_affected: list[str] = Field(default_factory=list)  # inclusive upper bounds, if any
    in_range: bool | None = None                # None = no evaluable range / versions data


def norm_name(ecosystem: str, name: str) -> str:
    return norm_pypi(name) if ecosystem == "pypi" else name.lower()


def matching_affected(record: dict, ecosystem: str, name: str) -> list[dict]:
    """affected[] entries of `record` for this package (OSV 'PyPI' ↔ 'pypi', normalized names)."""
    want = norm_name(ecosystem, name)
    out = []
    for a in record.get("affected", []) or []:
        p = a.get("package") or {}
        eco = _ECO.get(str(p.get("ecosystem", "")).lower())
        if eco == ecosystem and norm_name(eco, p.get("name", "")) == want:
            out.append(a)
    return out


def find_record(osv: dict[str, dict], ids: list[str], ecosystem: str,
                name: str) -> tuple[str, dict, list[dict]] | None:
    """First of `ids` (vuln_id first, then aliases) whose OSV record covers the package."""
    for vid in ids:
        rec = osv.get(vid) or {}
        aff = matching_affected(rec, ecosystem, name)
        if aff:
            return vid, rec, aff
    return None


def _intervals(rng: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Events in order → ([(introduced, fixed|"")], [(introduced, last_affected)])."""
    half, closed = [], []
    start = None
    for ev in rng.get("events", []) or []:
        if "introduced" in ev:
            if start is not None:          # consecutive introduced: previous stays open
                half.append((start, ""))
            start = ev["introduced"]
        elif "fixed" in ev and start is not None:
            half.append((start, ev["fixed"]))
            start = None
        elif "last_affected" in ev and start is not None:
            closed.append((start, ev["last_affected"]))
            start = None
        elif "limit" in ev and start is not None:
            half.append((start, ev["limit"]))
            start = None
    if start is not None:
        half.append((start, ""))
    return half, closed


def _ge(eco: str, v: str, lo: str) -> bool:
    return lo in ("0", "") or compare(eco, v, lo) >= 0


def range_info(advisory_id: str, affected: list[dict], ecosystem: str, version: str) -> RangeInfo:
    """in_range True/False only from comparisons that parsed; an unparseable installed version
    (e.g. a git/url ref) gives None, never a silent False (which R1 would turn into not_affected)."""
    ranges: list[list[str]] = []
    last: list[str] = []
    hit, evaluable = False, False
    listed = False                              # an explicit `versions` entry was comparable
    explicit = [v for a in affected for v in (a.get("versions") or [])]
    for a in affected:
        for rng in a.get("ranges", []) or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            half, closed = _intervals(rng)
            for lo, hi in half:
                ranges.append([lo, hi])
                try:
                    inside = _ge(ecosystem, version, lo) and (not hi or compare(ecosystem, version, hi) < 0)
                except ValueError:          # unparseable version/bound → this range says nothing
                    continue
                evaluable = True
                hit = hit or inside
            for lo, hi in closed:
                ranges.append([lo, ""])
                last.append(hi)
                try:
                    inside = _ge(ecosystem, version, lo) and compare(ecosystem, version, hi) <= 0
                except ValueError:
                    continue
                evaluable = True
                hit = hit or inside
    if version in explicit:
        hit = True
    elif not hit:
        for v in explicit:
            try:
                same = compare(ecosystem, version, v) == 0
            except ValueError:
                continue
            listed = True
            if same:
                hit = True
                break
    if hit:
        in_range: bool | None = True
    elif evaluable or listed:
        in_range = False
    else:
        in_range = None
    return RangeInfo(advisory_id=advisory_id, ranges=ranges, last_affected=last, in_range=in_range)


def resolve(osv: dict[str, dict], ids: list[str], ecosystem: str, name: str,
            version: str) -> tuple[RangeInfo, dict]:
    """(RangeInfo, matched OSV record or {}). in_range None when no record covers the package."""
    found = find_record(osv, ids, ecosystem, name)
    if not found:
        return RangeInfo(), {}
    vid, rec, aff = found
    return range_info(vid, aff, ecosystem, version), rec
