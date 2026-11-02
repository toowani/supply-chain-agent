"""Remediation plan — weighted greedy set cover (deterministic code, no LLM).

Universe  = open findings (verdict != not_affected; findings without a judgment count as open).
Weight    = Scored.score.
Actions   = upgrade (ecosystem, package) to one target version across services
          | remove (service, package) when the package is installed but unreferenced.
Greedy    = repeatedly take the action with max marginal uncovered risk
            (tie: fewer services, then package name, then kind), up to k.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from packaging.version import InvalidVersion, Version

from sca.contracts import Action, Judgment, PlanResult, finding_id
from sca.score.risk import Scored
from sca.versions import _semver_key, compare, is_newer, sort_versions

REMOVE_NOTE = "not declared nor required: uninstall (e.g. stale venv leftover)"


def _release(ecosystem: str, v: str) -> tuple[int, ...] | None:
    """Numeric release tuple (PEP 440 release / semver core), None when unparseable."""
    if ecosystem != "npm":
        try:
            return tuple(Version(v).release)
        except InvalidVersion:
            pass
    try:
        return _semver_key(v)[0]
    except ValueError:
        return None


def is_major_bump(ecosystem: str, current: str, target: str) -> bool:
    """Compatibility-risk flag: major increases; for 0.x → 0.y a minor increase counts as major."""
    a, b = _release(ecosystem, current), _release(ecosystem, target)
    if not a or not b:
        return False
    a, b = a + (0,) * (2 - len(a)), b + (0,) * (2 - len(b))
    if a[0] == 0 and b[0] == 0:
        return b[1] > a[1]
    return b[0] > a[0]


def _sort(eco: str, vs: set[str]) -> list[str]:
    try:
        return sort_versions(eco, sorted(vs))
    except ValueError:
        return sorted(vs)


def _lt(eco: str, a: str, b: str) -> bool:
    try:
        return compare(eco, a, b) < 0
    except ValueError:
        return False


def _le(eco: str, a: str, b: str) -> bool:
    try:
        return compare(eco, a, b) <= 0
    except ValueError:
        return False


def needed_fix(s: Scored) -> str:
    """Lowest fix version newer than the installed one ('' if none). fix_versions may list
    backport branches (e.g. 1.2.5 and 2.3.1 for 2.2.0), so fix_versions[0] is not enough."""
    p = s.finding.package
    newer = [v for v in s.finding.fix_versions if is_newer(p.ecosystem, v, p.version)]
    return _sort(p.ecosystem, set(newer))[0] if newer else ""


def _verdicts(judgments: Iterable[Judgment] | Mapping[str, Judgment] | None) -> dict[str, str]:
    if not judgments:
        return {}
    js = judgments.values() if isinstance(judgments, Mapping) else judgments
    return {finding_id(j.service, j.package, j.cve): j.verdict for j in js}


def _fid(s: Scored, verdicts: dict[str, str]) -> tuple[str, str | None]:
    """Finding id + its verdict (judgment may be keyed by an alias of the canonical id)."""
    f = s.finding
    fid = finding_id(f.service, f.package.key, f.vuln_id)
    for vid in (f.vuln_id, *f.aliases):
        v = verdicts.get(finding_id(f.service, f.package.key, vid))
        if v is not None:
            return fid, v
    return fid, None


def _dep(dep_class: Mapping[str, Mapping[str, str]], s: Scored) -> str:
    p = s.finding.package
    svc = dep_class.get(s.finding.service, {})
    return svc.get(p.key) or svc.get(f"{p.ecosystem}:{p.name}") or ""


def candidate_actions(scored: list[Scored], judgments, dep_class) -> tuple[list[Action], dict[str, float], list[str]]:
    """All candidate actions (covers = every open finding the action fixes), weights per open
    finding id, and the open ids no action can cover."""
    verdicts = _verdicts(judgments)
    open_: dict[str, Scored] = {}
    for s in scored:
        fid, v = _fid(s, verdicts)
        if v != "not_affected":
            open_[fid] = s
    weight = {fid: s.score for fid, s in open_.items()}

    actions: list[Action] = []
    by_pkg: dict[tuple[str, str], list[tuple[str, Scored]]] = {}
    for fid, s in open_.items():
        by_pkg.setdefault((s.finding.package.ecosystem, s.finding.package.name), []).append((fid, s))

    for (eco, name), items in sorted(by_pkg.items()):
        need = {fid: needed_fix(s) for fid, s in items}
        firsts = {v for v in need.values() if v}
        if not firsts:
            continue
        try:
            target = sort_versions(eco, sorted(firsts))[-1]
        except ValueError:
            continue
        cov = [(fid, s) for fid, s in items if need[fid]
               and _le(eco, need[fid], target)
               and _lt(eco, s.finding.package.version, target)]
        if not cov:
            continue
        pairs = sorted({(s.finding.service, s.finding.package.version) for _, s in cov})
        actions.append(Action(
            kind="upgrade", ecosystem=eco, package=name, target_version=target,
            services=sorted({p[0] for p in pairs}), from_versions=_sort(eco, {p[1] for p in pairs}),
            covers=sorted(fid for fid, _ in cov),
            risk_covered=round(sum(weight[fid] for fid, _ in cov), 4),
            major_bump=any(is_major_bump(eco, v, target) for _, v in pairs),
        ))

    by_svc_pkg: dict[tuple[str, str, str], list[tuple[str, Scored]]] = {}
    for fid, s in open_.items():
        if _dep(dep_class, s) == "unreferenced":
            p = s.finding.package
            by_svc_pkg.setdefault((s.finding.service, p.ecosystem, p.name), []).append((fid, s))
    for (svc, eco, name), items in sorted(by_svc_pkg.items()):
        actions.append(Action(
            kind="remove", ecosystem=eco, package=name, services=[svc],
            from_versions=_sort(eco, {s.finding.package.version for _, s in items}),
            covers=sorted(fid for fid, _ in items),
            risk_covered=round(sum(weight[fid] for fid, _ in items), 4),
            note=REMOVE_NOTE,
        ))

    coverable = {fid for a in actions for fid in a.covers}
    unfixable = sorted(fid for fid in open_ if fid not in coverable)
    return actions, weight, unfixable


def _greedy(scored, judgments, dep_class, k: int | None) -> PlanResult:
    actions, weight, unfixable = candidate_actions(scored, judgments, dep_class)
    total = sum(weight.values())
    covered: set[str] = set()
    chosen: list[Action] = []
    pool = list(actions)
    while pool and (k is None or len(chosen) < k):
        def gain(a: Action) -> float:
            return sum(weight[f] for f in a.covers if f not in covered)
        best = min(pool, key=lambda a: (-round(gain(a), 6), len(a.services), a.package, a.kind,
                                        a.services, a.target_version))
        g = gain(best)
        if g <= 0:
            break
        pool.remove(best)
        # risk_covered = marginal risk in greedy order, so Σ risk_covered == covered_risk
        chosen.append(best.model_copy(update={"risk_covered": round(g, 4)}))
        covered |= set(best.covers)
    cov_risk = sum(weight[f] for f in covered)
    return PlanResult(k=len(chosen) if k is None else k, total_risk=round(total, 4), actions=chosen,
                      covered_risk=round(cov_risk, 4),
                      coverage=round(cov_risk / total, 4) if total > 0 else 0.0,
                      unfixable=unfixable)


def plan_actions(scored: list[Scored], judgments, dep_class: Mapping[str, Mapping[str, str]],
                 k: int = 3) -> PlanResult:
    """Top-k remediation actions by weighted greedy set cover.

    judgments: list[Judgment] or {finding_id: Judgment} (missing → counted as open).
    dep_class: {service: {Package.key or 'eco:name': direct|transitive|unreferenced}}.
    Action.covers = all findings the action fixes; Action.risk_covered = marginal risk it adds
    at its position in the greedy order."""
    return _greedy(scored, judgments, dep_class, k)


def rank_all_actions(scored: list[Scored], judgments, dep_class) -> PlanResult:
    """Full greedy order (until no action adds risk) for reports; PlanResult.k = len(actions)."""
    return _greedy(scored, judgments, dep_class, None)
