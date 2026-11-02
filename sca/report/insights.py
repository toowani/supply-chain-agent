"""Portfolio insights over judge output: hold (uncertain) breakdown + call-graph estimate,
automation KPIs, one showcase not_affected example, group-sharing effect.

Pure functions, deterministic code only (no LLM). Outputs may go into public docs, so service
code is reduced to "path:line" references — never source text.
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from sca.contracts import Decision, Judgment

# ── hold breakdown ───────────────────────────────────────────────────────────────────
CALLGRAPH = "콜그래프로 해소 가능"
INPUT_TRUST = "입력 신뢰 판단 필요(사람)"
NOT_CHECKABLE = "검사 불가 조건(사람)"
# code_unavailable (no code / unsupported ecosystem) is NOT a call-graph case → falls into 검사 불가
CATEGORY_RULES = {
    CALLGRAPH: {"reachable_via_dependency", "transitive_needs_callgraph"},
    INPUT_TRUST: {"input_trust_needs_human"},
}
CATEGORY_ORDER = [CALLGRAPH, INPUT_TRUST, NOT_CHECKABLE]


def _js(judgments: Iterable) -> list[Judgment]:
    return [j if isinstance(j, Judgment) else Judgment.model_validate(j) for j in judgments]


def _key(j: Judgment) -> tuple[str, str, str]:
    return (j.service, j.package, j.cve)


def category_of(rule: str) -> str:
    """Hold cause category for an uncertain rule; unknown rules fall into 검사 불가(사람)."""
    for cat, rules in CATEGORY_RULES.items():
        if rule in rules:
            return cat
    return NOT_CHECKABLE


def hold_breakdown(judgments, gt=None) -> dict:
    """Uncertain verdicts by cause category + 추정 review rate after call-graph integration.

    gt: GTItem list (core+extended) or None. Returns keys: total, uncertain, review_rate,
    categories [{category, count, share, rules{rule: n}}], estimate {label, assumptions,
    upper_bound{...}, grounded{...} | None}."""
    js = _js(judgments)
    n = len(js)
    unc = [j for j in js if j.verdict == "uncertain"]
    by_cat: dict[str, Counter] = {c: Counter() for c in CATEGORY_ORDER}
    for j in unc:
        by_cat[category_of(j.rule)][j.rule] += 1
    cats = [{"category": c, "count": sum(r.values()), "share": _r(sum(r.values()) / n if n else 0),
             "rules": dict(r.most_common())} for c, r in by_cat.items()]
    cg = sum(by_cat[CALLGRAPH].values())
    u = len(unc)
    rate = u / n if n else 0.0
    ub = (u - cg) / n if n else 0.0
    est = {
        "label": "추정",
        "assumptions": [
            "콜그래프는 '콜그래프로 해소 가능' 범주만 판정 가능하게 만들고, 사람 범주(입력 신뢰·검사 불가)는 그대로 남는다",
            "상한: 해당 범주 전부가 affected/not_affected로 결정된다고 가정",
            "근거 추정: 정답셋(core+extended) 중 에이전트가 같은 범주로 보류한 건의 정답 라벨이 결정 가능"
            "(affected/not_affected)한 비율을 전체 해당 범주에 그대로 적용",
        ],
        "upper_bound": {"review_rate": _r(ub), "uncertain_after": u - cg,
                        "formula": f"({u} - {cg}) / {n} = {ub:.1%}"},
        "grounded": None,
    }
    if gt:
        jx = {_key(j): j for j in js}
        hit = [(g, jx[g.key]) for g in gt
               if g.key in jx and jx[g.key].verdict == "uncertain"
               and category_of(jx[g.key].rule) == CALLGRAPH]
        dec = [g for g, _ in hit if g.label in ("affected", "not_affected")]
        if hit:
            share = len(dec) / len(hit)
            resolved = cg * share
            after = u - resolved
            est["grounded"] = {
                "gt_items": len(hit), "gt_decidable": len(dec), "decidable_share": _r(share),
                "resolved": round(resolved, 1), "uncertain_after": round(after, 1),
                "review_rate": _r(after / n if n else 0),
                "formula": f"({u} - {cg} × {len(dec)}/{len(hit)}) / {n} = {after / n:.1%}"}
    return {"total": n, "uncertain": u, "review_rate": _r(rate), "categories": cats,
            "estimate": est}


# ── automation KPIs ──────────────────────────────────────────────────────────────────
def automation_kpis(judgments, gt_core) -> dict:
    """자동 처리율 / 보류율 / 오판 (test set) + majority-class baseline.

    Returns keys: total, auto_decided, auto_rate, auto_decided_with_feedback,
    auto_rate_with_feedback, uncertain, hold_rate, misjudged {wrong, decided, text, wrong_keys},
    misjudged_with_feedback {...}, test_n, baseline {label, accuracy, text}."""
    js = _js(judgments)
    n = len(js)
    dec = [j for j in js if j.verdict != "uncertain"]
    code_dec = [j for j in dec if j.rule != "feedback_suppressed"]
    unc = n - len(dec)
    jx = {_key(j): j for j in js}
    gt_core = list(gt_core or [])

    def wrong(include_feedback: bool) -> dict:
        pairs = [(g, jx[g.key]) for g in gt_core if g.key in jx
                 and jx[g.key].verdict != "uncertain"
                 and (include_feedback or jx[g.key].rule != "feedback_suppressed")]
        bad = [g for g, j in pairs if j.verdict != g.label]
        return {"wrong": len(bad), "decided": len(pairs), "text": f"{len(bad)}/{len(pairs)}",
                "wrong_keys": ["|".join(g.key) for g in bad]}

    labels = Counter(g.label for g in gt_core)
    base = None
    if labels:
        lab, c = labels.most_common(1)[0]
        acc = c / len(gt_core)
        base = {"label": lab, "accuracy": _r(acc), "correct": c, "n": len(gt_core),
                "text": f"전부 {lab}로 찍는 기준선 정확도 {c}/{len(gt_core)} = {acc:.0%} "
                        f"(대신 affected를 하나도 못 잡음)"}
    return {"total": n,
            "auto_decided": len(code_dec), "auto_rate": _r(len(code_dec) / n if n else 0),
            "auto_decided_with_feedback": len(dec), "auto_rate_with_feedback": _r(len(dec) / n if n else 0),
            "uncertain": unc, "hold_rate": _r(unc / n if n else 0),
            "misjudged": wrong(False), "misjudged_with_feedback": wrong(True),
            "test_n": len(gt_core), "baseline": base}


# ── showcase not_affected ────────────────────────────────────────────────────────────
PREFERRED_RULES = ("api_not_referenced", "platform_excluded")
_HIT = re.compile(r"^(?:\[[^\]]+\]\s*)?(.+?):(\d+)(?::|$)")
_MISSING = re.compile(r"not referenced:\s*(\[.*?\])")


def fileline(hit: str) -> str | None:
    """'path/x.py:12: code…' → 'path/x.py:12' (code text dropped); None if unparsable."""
    m = _HIT.match(hit.strip())
    return f"{m.group(1)}:{m.group(2)}" if m else None


def _cvss_index(ranked) -> dict[tuple[str, str, str], float]:
    """(service, pkg_key, vuln) → CVSS from ranked.csv path, csv row dicts, or Scored list."""
    if isinstance(ranked, (str, Path)):
        with open(ranked, encoding="utf-8") as fh:
            ranked = list(csv.DictReader(fh))
    out = {}
    for r in ranked or []:
        if isinstance(r, dict):
            try:
                cv = float(r.get("cvss") or 0)
            except ValueError:
                cv = 0.0
            out[(r["service"], f'{r["ecosystem"]}:{r["package"]}@{r["version"]}', r["vuln_id"])] = cv
        else:  # Scored
            f = r.finding
            out[(f.service, f.package.key, f.vuln_id)] = float(r.cvss or 0)
    return out


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def osv_text(osv_cache_dir, advisory_id: str) -> str:
    p = Path(osv_cache_dir) / f"{advisory_id}.json"
    if not advisory_id or not p.exists():
        return ""
    rec = json.loads(p.read_text(encoding="utf-8")) or {}
    return f'{rec.get("summary", "")}\n{rec.get("details", "")}'


def _clip(quote: str, limit: int = 220) -> str:
    """Verbatim prefix ≤limit chars, cut at a word boundary, '…' appended when clipped."""
    q = _norm(quote)
    if len(q) <= limit:
        return q
    cut = q[:limit - 1].rsplit(" ", 1)[0]
    return cut + "…"


def showcase_not_affected(judgments, osv_cache_dir, ranked, gt=None, core_keys=None,
                          min_cvss: float = 7.0) -> dict | None:
    """One code-decided not_affected example with high CVSS and a verified advisory quote.

    gt: GTItem list (core+extended); core_keys: keys of the held-out core set.
    Preference: CVSS ≥ min_cvss, GT agrees (core > extended), quote_verified, quote found in the
    OSV record, preferred rule, has import sites, then CVSS. Returns keys: service, package,
    vuln_id, advisory_id, cvss, rule, advisory_quote, quote_in_osv, condition, missing_symbols,
    evidence_fileline, import_hits_total, files_importing, searched, gt_label, gt_set,
    explanation — or None."""
    js = _js(judgments)
    cv = _cvss_index(ranked)
    gtx = {g.key: g for g in (gt or [])}
    core = set(core_keys or ())
    cands = []
    for j in js:
        if j.verdict != "not_affected" or j.decided_by != "code" or j.rule == "feedback_suppressed":
            continue
        e = j.evidence or {}
        quote = e.get("advisory_quote", "")
        in_osv = bool(quote) and _norm(quote) in _norm(osv_text(osv_cache_dir, e.get("advisory_id", "")))
        g = gtx.get(_key(j))
        gt_rank = 0 if g is None else (-1 if g.label != "not_affected" else (2 if _key(j) in core else 1))
        c = cv.get(_key(j), 0.0)
        cands.append(((c >= min_cvss, gt_rank, bool(e.get("quote_verified")), in_osv,
                       j.rule in PREFERRED_RULES, bool(e.get("import_hits")), c), j, in_osv, g))
    if not cands:
        return None
    _, j, in_osv, g = max(cands, key=lambda t: t[0])
    e = j.evidence or {}
    m = _MISSING.search(e.get("note", ""))
    missing = _parse_list(m.group(1)) if m else []
    cond = next((c for c in j.conditions if any(s in c for s in missing)), j.conditions[0] if j.conditions else "")
    hits = [fl for h in e.get("import_hits", []) for fl in [fileline(h)] if fl]
    tot = (re.search(r"직접 import (\d+)곳", j.check_in_code)
           or re.search(r"direct import of [^:]+: (\d+) hit", j.check_in_code))      # pre-v5 label
    files = (re.search(r"import 파일 (\d+)개", j.check_in_code)
             or re.search(r"\((\d+) file\(s\) importing", j.check_in_code))
    n_hits = int(tot.group(1)) if tot else len(hits)
    # file count only when the scan recorded it (import_hits is capped at 5 → not a file count)
    n_files = int(files.group(1)) if files else None
    pkg = j.package.split(":", 1)[-1]
    c = cv.get(_key(j), 0.0)
    need = ", ".join(missing) or "취약 API"
    if j.rule == "platform_excluded":
        expl = (f"{pkg}는 영향 버전 범위 안이지만 권고문의 전제 플랫폼이 {j.service} 런타임과 달라 "
                f"not_affected로 판정했다(CVSS {c}).")
    elif hits:
        where = f"{n_files}개 파일·{n_hits}곳" if n_files is not None else f"{n_hits}곳"
        expl = (f"{j.service} 코드에 {pkg} import가 {where} 있지만 권고문의 전제인 {need} 참조는 "
                f"0건이어서 not_affected로 판정했다(CVSS {c}).")
    else:
        scope = f"서비스 코드 {n_files}개 파일" if n_files is not None else "서비스 코드"
        expl = (f"{j.service} 코드에 {pkg} 직접 import는 0건이고, {scope}와 의존 패키지에서 권고문의 "
                f"전제인 {need} 참조도 0건이어서 not_affected로 판정했다(CVSS {c}).")
    return {"service": j.service, "package": j.package, "vuln_id": j.cve,
            "advisory_id": e.get("advisory_id", ""), "cvss": c, "rule": j.rule,
            "advisory_quote": _clip(e.get("advisory_quote", "")), "quote_in_osv": in_osv,
            "condition": cond, "missing_symbols": missing, "evidence_fileline": hits,
            "import_hits_total": n_hits, "files_importing": n_files,
            "searched": _searched_scopes(j.check_in_code),
            "gt_label": g.label if g else None,
            "gt_set": ("core" if _key(j) in core else "extended") if g else None,
            "explanation": expl}


def _parse_list(s: str) -> list[str]:
    return re.findall(r"'([^']*)'", s)


def _searched_scopes(check: str) -> str:
    """Scope part of check_in_code ('service code (N file(s) …); dep; …') — no code text."""
    m = re.search(r"(?:검색 범위|searched): (.*)$", check)
    return m.group(1) if m else check


# ── group-sharing effect ─────────────────────────────────────────────────────────────
def _load_decisions(path) -> list[Decision]:
    p = Path(path)
    if not p.exists():
        return []
    return [Decision.model_validate_json(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def shared_judgment_kpis(judgments, feedback_path) -> dict:
    """One judgment per (package@version, vuln) reused across services + all_services feedback.

    Returns keys: findings, unique_pairs, shared_pairs, shared_findings, shared_services_max,
    shared_consistent, judgments_saved, text, feedback {decisions_all_services, rows_resolved,
    rows_other_services, services, text}."""
    js = _js(judgments)
    groups: dict[tuple[str, str], list[Judgment]] = defaultdict(list)
    for j in js:
        groups[(j.package, j.cve)].append(j)
    shared = {k: v for k, v in groups.items() if len({j.service for j in v}) >= 2}
    sf = sum(len(v) for v in shared.values())
    consistent = sum(len({j.verdict for j in v}) == 1 for v in shared.values())
    decs = [d for d in _load_decisions(feedback_path) if d.scope == "all_services"]
    from sca.feedback.store import pkg_name_key
    origin = {(d.package, d.vuln_id): d.service for d in decs}
    # only rows suppressed by an all_services decision (service-scope suppressions excluded)
    sup = [j for j in js if j.rule == "feedback_suppressed" and (pkg_name_key(j.package), j.cve) in origin]
    other = [j for j in sup if origin.get((pkg_name_key(j.package), j.cve), j.service) != j.service]
    svcs = sorted({j.service for j in sup})
    return {
        "findings": len(js), "unique_pairs": len(groups),
        "shared_pairs": len(shared), "shared_findings": sf,
        "shared_services_max": max((len({j.service for j in v}) for v in shared.values()), default=0),
        "shared_consistent": consistent, "judgments_saved": len(js) - len(groups),
        "text": f"판정 {len(shared)}회로 경고 {sf}건 (여러 서비스 공유 패키지@버전×취약점)",
        "feedback": {"decisions_all_services": len(decs), "rows_resolved": len(sup),
                     "rows_other_services": len(other), "services": svcs,
                     "text": f"그룹 공유 결정 {len(decs)}건 → {len(svcs)}개 서비스 {len(sup)}건 자동 해소"
                             f"(그중 다른 서비스 {len(other)}건)"},
    }


def _r(x: float) -> float:
    return round(x, 4)
