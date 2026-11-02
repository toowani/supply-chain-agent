"""Judge accuracy against ground truth + the four KPIs for the 기획서 (CLAUDE.md §5).
All numbers are computed by code from Judgment / PlanResult / Scored objects."""
from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

import yaml

from sca.config import OUT_DIR, ROOT
from sca.contracts import Judgment, PlanResult, finding_id
from sca.eval.groundtruth import GTItem
from sca.score.risk import Scored
from sca.versions import compare

CLASSES = ["affected", "not_affected", "uncertain"]
HUMAN_TIMING_PATH = ROOT / "data" / "eval" / "human_timing.yaml"
CACHED_SECONDS = 0.05                  # reported separately: rule-only judgments are this fast too


def _ratio(a: float, b: float) -> float | None:
    return round(a / b, 4) if b else None


def _split_key(pkg: str) -> tuple[str, str, str]:
    """'pypi:Pillow@11.3.0' → ('pypi', 'pillow', '11.3.0'); names normalised like ingest (PEP 503 / lowercase)."""
    eco, _, rest = pkg.partition(":")
    name, _, ver = rest.rpartition("@") if "@" in rest.lstrip("@") else (rest, "", "")
    eco = eco.lower()
    name = re.sub(r"[-_.]+", "-", name.lower()) if eco == "pypi" else name.lower()
    return eco, name, ver


def _same_version(eco: str, a: str, b: str) -> bool:
    if a == b:
        return True
    try:
        return compare(eco, a, b) == 0
    except ValueError:
        return False


def _matcher(judgments: list[Judgment]):
    """Exact (service, package key, vuln id) first; else normalised name + version equality via
    sca.versions, with the vuln id or the OSV advisory id (e.g. GHSA alias) the judge recorded."""
    exact = {(j.service, j.package, j.cve): j for j in judgments}
    loose: dict[tuple[str, str, str, str], list[Judgment]] = {}
    for j in judgments:
        eco, name, _ = _split_key(j.package)
        for vid in {j.cve, (j.evidence or {}).get("advisory_id") or j.cve}:
            loose.setdefault((j.service, eco, name, vid), []).append(j)

    def find(it: GTItem) -> Judgment | None:
        if it.key in exact:
            return exact[it.key]
        eco, name, ver = _split_key(it.package)
        for j in loose.get((it.service, eco, name, it.vuln_id), []):
            if _same_version(eco, _split_key(j.package)[2], ver):
                return j
        return None
    return find


def evaluate(judgments: list[Judgment], gt: list[GTItem] | None) -> dict:
    """Agent verdict vs human label, matched on (service, package key, vuln id). Duplicate
    ground-truth keys are counted once (first wins) and listed in `duplicates`."""
    if gt is None:
        return {"available": False, "note": "정답셋 없음 (data/eval/ground_truth.yaml)", "n": 0,
                "matched": 0, "accuracy": None, "accuracy_reviewed_only": None}
    find = _matcher(judgments)
    seen, uniq, duplicates = set(), [], []
    for it in gt:
        if it.key in seen:
            duplicates.append({"service": it.service, "package": it.package, "vuln_id": it.vuln_id})
            continue
        seen.add(it.key)
        uniq.append(it)
    gt = uniq
    conf = {t: {p: 0 for p in CLASSES} for t in CLASSES}
    mismatches, missing = [], []
    correct = reviewed_n = reviewed_correct = 0
    matched = 0
    for it in gt:
        j = find(it)
        if j is None:
            missing.append({"service": it.service, "package": it.package, "vuln_id": it.vuln_id})
            continue
        matched += 1
        conf[it.label][j.verdict] += 1
        ok = it.label == j.verdict
        correct += ok
        if it.reviewed:
            reviewed_n += 1
            reviewed_correct += ok
        if not ok:
            mismatches.append({"service": it.service, "package": it.package, "vuln_id": it.vuln_id,
                               "label": it.label, "verdict": j.verdict, "rule": j.rule,
                               "decided_by": j.decided_by})
    per_class = {}
    for c in CLASSES:
        tp = conf[c][c]
        pred = sum(conf[t][c] for t in CLASSES)
        true = sum(conf[c].values())
        per_class[c] = {"precision": _ratio(tp, pred), "recall": _ratio(tp, true),
                        "support": true, "predicted": pred}
    return {
        "available": True, "n": len(gt), "matched": matched, "correct": correct,
        "accuracy": _ratio(correct, matched),
        "n_reviewed": reviewed_n, "accuracy_reviewed_only": _ratio(reviewed_correct, reviewed_n),
        "confusion": {"rows_label_cols_verdict": CLASSES, "matrix": conf},
        "per_class": per_class, "mismatches": mismatches, "missing": missing, "duplicates": duplicates,
    }


def _verdicts(judgments: list[Judgment]) -> dict[str, str]:
    return {finding_id(j.service, j.package, j.cve): j.verdict for j in judgments}


def _human_timing(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {"mean": None, "median": None, "n": 0, "note": "미측정"}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    mins = [float(it["minutes"]) for it in data.get("items", []) if it.get("minutes") is not None]
    if not mins:
        return {"mean": None, "median": None, "n": 0, "note": "미측정"}
    return {"mean": round(statistics.mean(mins), 2), "median": round(statistics.median(mins), 2),
            "n": len(mins), "note": f"{path.name}, {len(mins)}건 수작업 측정"}


def kpis(scored: list[Scored], judgments: list[Judgment], plan: PlanResult | None, gt_eval: dict | None,
         human_timing_path: Path = HUMAN_TIMING_PATH) -> dict:
    """측정값: 경고 감소율 · 조건 판정 정확도 · Top-3 위험 커버율 · 사람 검토 비율 · 처리 시간."""
    n = len(judgments)
    counts = {c: sum(j.verdict == c for j in judgments) for c in CLASSES}

    by_vuln: dict[str, set[str]] = {}
    for j in judgments:
        by_vuln.setdefault(j.cve, set()).add(j.verdict)
    vuln_na = sum(v == {"not_affected"} for v in by_vuln.values())

    from sca.feedback.store import is_demo
    fb_rows = sum(j.decided_by == "feedback" for j in judgments)
    demo_rows = sum(is_demo(j) for j in judgments)
    fb_note = ""
    if demo_rows:
        fb_note = (f" 시연용 데모 결정(demo-reviewer, 실제 검토 아님)으로 처리된 {demo_rows}행 포함"
                   f"{f'(사람 피드백 {fb_rows - demo_rows}행 별도)' if fb_rows > demo_rows else ''} — "
                   "에이전트 단독 값은 extra.agent_only_reduction.")
    elif fb_rows:
        fb_note = f" 사람 피드백으로 처리된 {fb_rows}행 포함 — 에이전트 단독 값은 extra.agent_only_reduction."
    warning = {
        "by_finding": _ratio(counts["not_affected"], n), "not_affected": counts["not_affected"],
        "feedback_rows": fb_rows, "demo_feedback_rows": demo_rows,
        "judged": n, "scanner_findings": len(scored),
        "by_unique_vuln": _ratio(vuln_na, len(by_vuln)), "unique_vulns_not_affected": vuln_na,
        "unique_vulns_judged": len(by_vuln),
        "note": "not_affected / 판정 행 수. 고유 취약점 기준은 모든 서비스에서 not_affected인 ID만 제외로 계산."
                + fb_note,
    }

    top3 = {"coverage": None, "plan_coverage": None, "plan_k": None, "covered_risk": None, "total_risk": None}
    if plan is not None:
        verdict = _verdicts(judgments)
        score = {finding_id(s.finding.service, s.finding.package.key, s.finding.vuln_id): s.score
                 for s in scored}
        ids = {fid for a in plan.actions[:3] for fid in a.covers}
        cov = sum(score.get(fid, 0.0) for fid in ids if verdict.get(fid) != "not_affected")
        top3 = {"coverage": _ratio(cov, plan.total_risk) if plan.total_risk else None,
                "covered_risk": round(cov, 4), "total_risk": round(plan.total_risk, 4),
                "plan_coverage": round(plan.coverage, 4), "plan_k": plan.k,
                "actions": [f"{a.kind} {a.ecosystem}:{a.package}"
                            + (f"→{a.target_version}" if a.target_version else "") for a in plan.actions[:3]]}

    secs = [j.seconds for j in judgments]
    # judge marks cache use in evidence; a judgment-cache hit keeps the ORIGINAL run's seconds
    jcache = sum((j.evidence or {}).get("judgment_cache") == "hit" for j in judgments)
    llm_cached = sum(bool((j.evidence or {}).get("llm_cached")) for j in judgments)
    fast = sum(s < CACHED_SECONDS for s in secs)
    cached = sum((j.evidence or {}).get("judgment_cache") == "hit" or bool((j.evidence or {}).get("llm_cached"))
                 for j in judgments)
    agent = {"mean": round(statistics.mean(secs), 3) if secs else None,
             "median": round(statistics.median(secs), 3) if secs else None,
             "n": len(secs), "cached_like": cached, "judgment_cache_hits": jcache,
             "llm_cached": llm_cached, "under_threshold": fast,
             "note": (f"{cached}/{len(secs)}건 캐시 사용(판정 캐시 {jcache}, LLM 조건 캐시 {llm_cached}) — "
                      "콜드 실행 시간은 캐시 삭제 후 재측정" if cached else "캐시 미사용 실행")
                     + f" · {fast}건은 {CACHED_SECONDS}s 미만(LLM 호출 없는 규칙 판정 포함)"}
    human = _human_timing(human_timing_path)
    speedup = None
    if human["mean"] is not None and agent["mean"]:
        speedup = round(human["mean"] * 60 / agent["mean"], 1)

    return {
        "warning_reduction": warning,
        "condition_accuracy": {"accuracy": (gt_eval or {}).get("accuracy"),
                               "accuracy_reviewed_only": (gt_eval or {}).get("accuracy_reviewed_only"),
                               "matched": (gt_eval or {}).get("matched", 0),
                               "note": None if (gt_eval or {}).get("available") else "정답셋 없음"},
        "top3_risk_coverage": top3,
        "human_review_ratio": {"ratio": _ratio(counts["uncertain"], n), "uncertain": counts["uncertain"],
                               "judged": n},
        "verdict_counts": counts,
        "agent_seconds_per_item": agent,
        "human_minutes_per_item": human,
        "speedup": speedup,
    }


def write_metrics(metrics: dict, path: Path = OUT_DIR / "metrics.json") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, ensure_ascii=False, indent=1), encoding="utf-8")
    return path
