"""Top-k plan follow-ups (deterministic code, no LLM).

1. compat_alternative — per upgrade action, the highest release that carries no compatibility
   risk (same major line, Requires-Python satisfied by the service runtime, not yanked/pre) and
   which of the action's open findings it still fixes.
2. shared_upgrades — upgrade/remove candidates touching ≥2 services (group-wide fix in one go).

Pipeline hook (sca/pipeline.py run(), right after `runtime_check(plan, services, offline)`):
    analyze_plan(plan, ranked, judgments, dep_class, services, invs=invs, offline=offline)
In scope there: plan: PlanResult · ranked: list[Scored] · judgments: list[Judgment] ·
dep_class: {service: {pkg_key: class}} · services: list[ServiceSpec] · invs: list[Inventory].
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping

import requests
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from sca.contracts import Action, PlanResult
from sca.enrich.feeds import _get, _now, _read, _write
from sca.plan.greedy import _fid, _verdicts, candidate_actions, is_major_bump, needed_fix, rank_all_actions
from sca.score.risk import Scored
from sca.versions import compare, is_newer, sort_versions

# {version: {"requires_python": str, "yanked": bool}}
Releases = dict[str, dict]


def fetch_pypi_index(name: str, offline: bool = False) -> Releases:
    """All releases of a PyPI project (public JSON). Cached as data/cache/pypi/<name>__index.json
    with only version → requires_python/yanked. {} when unavailable."""
    path = f"pypi/{name}__index.json"
    rec = _read(path)
    if not rec and not offline:
        try:
            r = _get(f"https://pypi.org/pypi/{name}/json")
            data = r.json() if r.status_code == 200 else {}
        except requests.RequestException:
            data = {}
        rels: Releases = {}
        for v, files in (data.get("releases") or {}).items():
            if not files:                      # no distribution uploaded
                continue
            specs = sorted({f.get("requires_python") or "" for f in files} - {""})
            rels[v] = {"requires_python": specs[0] if specs else "",
                       "yanked": all(f.get("yanked") for f in files)}
        if rels:
            rec = {"fetched_at": _now(), "releases": rels}
            _write(path, rec)
    return rec.get("releases", {}) if rec else {}


def service_pythons(services) -> dict[str, list[str]]:
    """{service: [python_full_version of each venv]} — empty list when no venv/unreadable."""
    from sca.ingest.manifests import venv_marker_env
    from sca.judge.run import service_venvs
    out: dict[str, list[str]] = {}
    for s in services:
        vs = []
        for v in service_venvs(s):
            try:
                vs.append(venv_marker_env(v)["python_full_version"])
            except Exception:  # missing venv / broken interpreter → runtime unknown
                pass
        out[s.name] = vs
    return out


def _pre(eco: str, v: str) -> bool:
    if eco == "npm":
        return "-" in v.split("+", 1)[0]
    try:
        return Version(v).is_prerelease
    except InvalidVersion:
        return True


def _py_ok(spec: str, pys: Iterable[str]) -> bool:
    if not spec:
        return True
    try:
        ss = SpecifierSet(spec)
    except InvalidSpecifier:
        return True
    return all(ss.contains(p, prereleases=True) for p in pys)


def _cmp(eco: str, a: str, b: str) -> int | None:
    try:
        return compare(eco, a, b)
    except ValueError:
        return None


def _fixed_by(s: Scored, ranges: list[list[str]], eco: str, v: str) -> bool:
    """v fixes the finding: outside every OSV affected range [introduced, fixed) when the
    judgment has ranges, else ≥ the lowest fix version newer than installed (greedy's rule).
    Ranges built from OSV last_affected are stored open-ended ([intro, ""]), so callers pass []
    for those and the greedy rule applies."""
    if ranges:
        ok = True
        for intro, fixed in ranges:
            lo = _cmp(eco, v, intro) if intro and intro != "0" else 1
            hi = _cmp(eco, v, fixed) if fixed else -1
            if lo is None or hi is None:      # unparseable bound → fall back to greedy's rule
                ok = False
                continue
            if lo >= 0 and hi < 0:
                return False
        if ok:
            return True
    need = needed_fix(s)
    c = _cmp(eco, need, v) if need else None
    return c is not None and c <= 0


def _line(eco: str, v: str) -> str:
    parts = v.split(".")
    return f"{parts[0]}.{parts[1]}.x" if parts[0] == "0" and len(parts) > 1 else f"{parts[0]}.x"


def compat_alternative(action: Action, ranked: list[Scored], judgments, weight: Mapping[str, float],
                       pythons: Mapping[str, list[str]], releases: Releases | None) -> dict:
    """Best no-compat-risk alternative for one upgrade action.
    releases: PyPI index for pypi; None for npm → candidates are the fix versions in the findings.
    Returns {package, ecosystem, from_versions, plan_target, target, fixes_findings, fixes_count,
    open_count, risk_covered, risk_share_of_action, note} or
    {package, ecosystem, from_versions, plan_target, target: None, best_compatible, reason}."""
    eco, name = action.ecosystem, action.package
    base = {"package": name, "ecosystem": eco, "from_versions": action.from_versions,
            "plan_target": action.target_version}
    if action.kind != "upgrade":
        return {**base, "target": None, "best_compatible": None, "reason": "제거 조치 — 버전 대안 해당 없음"}
    verdicts = _verdicts(judgments)
    ranges = {}
    js = judgments.values() if isinstance(judgments, Mapping) else (judgments or [])
    for j in js:
        # last_affected bounds are lost in affected_ranges (stored open-ended) → greedy rule
        closed = bool((j.evidence or {}).get("last_affected"))
        ranges[(j.service, j.package, j.cve)] = [] if closed else j.affected_ranges
    cover = set(action.covers)
    items = []
    for s in ranked:
        fid, v = _fid(s, verdicts)
        if fid in cover and v != "not_affected":
            f = s.finding
            rg = next((ranges[k] for vid in (f.vuln_id, *f.aliases)
                       if (k := (f.service, f.package.key, vid)) in ranges), [])
            items.append((fid, s, rg))
    total = sum(weight.get(fid, 0.0) for fid, _, _ in items)
    pys = sorted({p for svc in action.services for p in pythons.get(svc, [])})

    if releases is None:
        rels = {v: {"requires_python": "", "yanked": False}
                for _, s, rg in items for v in [*s.finding.fix_versions, *(r[1] for r in rg if r[1])]}
    else:
        rels = releases
    highest = sort_versions(eco, list(action.from_versions))[-1]   # no downgrade for any service
    newer = [v for v, m in rels.items()
             if not m.get("yanked") and not _pre(eco, v) and is_newer(eco, v, highest)]
    same_line = [v for v in newer if not any(is_major_bump(eco, f, v) for f in action.from_versions)]
    check_py = eco == "pypi"
    ok = [v for v in same_line if not check_py or _py_ok(rels[v].get("requires_python", ""), pys)]
    line = _line(eco, action.from_versions[-1])
    py_s = "/".join(pys) or "?"

    best = sort_versions(eco, ok)[-1] if ok else None
    fixes = [fid for fid, s, rg in items if best and _fixed_by(s, rg, eco, best)] if best else []
    if best and fixes:
        risk = round(sum(weight.get(f, 0.0) for f in fixes), 4)
        rest = len(items) - len(fixes)
        note = ("호환 범위 안에서 전부 해소" if rest == 0 else
                f"부분 조치: {len(fixes)}/{len(items)}건 해소, 나머지 {rest}건은 {action.target_version} 필요")
        return {**base, "target": best, "fixes_findings": sorted(fixes), "fixes_count": len(fixes),
                "open_count": len(items), "risk_covered": risk,
                "risk_share_of_action": round(risk / total, 4) if total > 0 else 0.0, "note": note}

    # why none: lowest version that fixes anything and what it needs
    fixers = [v for v in newer if any(_fixed_by(s, rg, eco, v) for _, s, rg in items)]
    min_fix = sort_versions(eco, fixers)[0] if fixers else ""
    need = f"(Python {rels[min_fix]['requires_python']})" if (
        min_fix and check_py and rels[min_fix].get("requires_python")) else ""
    if best:
        reason = f"{line} 계열 최신 {best}에도 수정 없음 — 모든 수정 버전이 {min_fix or action.target_version} 이상{need}"
    elif same_line:
        top = sort_versions(eco, same_line)[-1]
        spec = rels[top].get("requires_python", "")
        reason = (f"{line} 계열 새 릴리스(~{top})는 Python {spec} 필요, 서비스는 {py_s} — "
                  f"수정 버전 {min_fix or action.target_version}{need}도 런타임 업그레이드 필요")
    elif releases is not None and not releases:
        reason = "릴리스 목록 없음(오프라인 캐시 미존재) — 판단 불가"
    else:
        cur = action.from_versions[-1]
        reason = f"{line} 계열 마지막 릴리스가 현재 {cur} — 수정 버전은 {min_fix or action.target_version}{need}부터(메이저 변경)"
    return {**base, "target": None, "best_compatible": best, "reason": reason}


def _installed(invs, ranked: list[Scored]) -> dict[tuple[str, str], dict[str, list[str]]]:
    """(ecosystem, name) → {service: [installed versions]} (inventory, plus vulnerable findings)."""
    out: dict[tuple[str, str], dict[str, set[str]]] = {}
    pkgs = [(inv.service, p) for inv in invs or [] for p in inv.packages]
    pkgs += [(s.finding.service, s.finding.package) for s in ranked]
    for svc, p in pkgs:
        out.setdefault((p.ecosystem, p.name), {}).setdefault(svc, set()).add(p.version)
    return {k: {svc: sorted(vs) for svc, vs in sorted(d.items())} for k, d in out.items()}


def shared_upgrades(plan: PlanResult, ranked: list[Scored], judgments, dep_class, invs=None,
                    top: int = 3) -> dict:
    """Group-wide candidates. Returns {top3: [{package, shared, services, installed_in, reason}],
    best_shared: [{rank, kind, package, ecosystem, target_version, services, findings,
    services_cleared, risk_covered, risk_total, risk_share, major_bump}], shared_count,
    candidate_count}. rank = position in the full greedy order; risk_covered = marginal there."""
    full = rank_all_actions(ranked, judgments, dep_class)
    _, weight, _ = candidate_actions(ranked, judgments, dep_class)
    total = sum(weight.values())
    verdicts = _verdicts(judgments)
    open_by_pkg: dict[tuple[str, str, str], set[str]] = {}
    for s in ranked:
        fid, v = _fid(s, verdicts)
        if v != "not_affected":
            p = s.finding.package
            open_by_pkg.setdefault((s.finding.service, p.ecosystem, p.name), set()).add(fid)
    inst = _installed(invs, ranked)

    shared = []
    for i, a in enumerate(full.actions, 1):
        if len(a.services) < 2:
            continue
        cov = set(a.covers)
        cleared = [svc for svc in a.services if open_by_pkg.get((svc, a.ecosystem, a.package), set()) <= cov]
        rt = round(sum(weight.get(f, 0.0) for f in cov), 4)
        shared.append({"rank": i, "kind": a.kind, "package": a.package, "ecosystem": a.ecosystem,
                       "target_version": a.target_version, "services": a.services,
                       "findings": len(a.covers), "services_cleared": cleared,
                       "risk_covered": a.risk_covered, "risk_total": rt,
                       "risk_share": round(rt / total, 4) if total > 0 else 0.0,
                       "major_bump": a.major_bump})

    flagged = {(s.finding.service, s.finding.package.ecosystem, s.finding.package.name) for s in ranked}
    rows = []
    for a in plan.actions:
        where = inst.get((a.ecosystem, a.package)) or {svc: [] for svc in a.services}
        others = [svc for svc in where if svc not in a.services]
        if len(a.services) >= 2:
            reason = ""
        elif not others:
            reason = f"{a.package}는 {', '.join(a.services)}에만 설치됨"
        else:
            quiet = [svc for svc in others if (svc, a.ecosystem, a.package) not in flagged]
            done = [svc for svc in others if svc not in quiet]
            parts = []
            if quiet:
                parts.append(", ".join(f"{svc}({'/'.join(where[svc])})" for svc in quiet) + "는 스캔 경고 없음")
            if done:
                parts.append(", ".join(done) + "는 경고가 모두 not_affected")
            reason = f"{a.package}는 다른 서비스에도 설치됐지만 " + " · ".join(parts)
        rows.append({"package": a.package, "shared": len(a.services) >= 2, "services": a.services,
                     "installed_in": list(where), "reason": reason})
    return {"top3": rows, "best_shared": shared[:top], "shared_count": len(shared),
            "candidate_count": len(full.actions)}


def analyze_plan(plan: PlanResult, ranked: list[Scored], judgments, dep_class, services, invs=None,
                 offline: bool = False, pythons: Mapping[str, list[str]] | None = None,
                 index: Callable[[str, bool], Releases] = fetch_pypi_index) -> dict:
    """{alternatives: [compat_alternative per plan action], shared: shared_upgrades(...)}.
    Call after runtime_check. pythons/index are injectable for tests."""
    _, weight, _ = candidate_actions(ranked, judgments, dep_class)
    if pythons is None:
        need = {s for a in plan.actions if a.ecosystem == "pypi" for s in a.services}
        pythons = service_pythons([s for s in services if s.name in need])
    alts = []
    for a in plan.actions:
        rels = index(a.package, offline) if a.ecosystem == "pypi" else None
        alts.append(compat_alternative(a, ranked, judgments, weight, pythons, rels))
    return {"alternatives": alts, "shared": shared_upgrades(plan, ranked, judgments, dep_class, invs)}
