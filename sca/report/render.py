"""Final Korean Markdown report (out/report.md): run info, KPIs, verdict distribution,
Top-3 upgrades, human review queue, overall Top-10 with verdict, graph image, ticket links."""
from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

from sca.config import OUT_DIR
from sca.contracts import Action, Judgment, PlanResult, finding_id
from sca.feedback.store import feedback_by, is_demo
from sca.report.tables import _table, clip
from sca.score.risk import Scored

CLASSES = ["affected", "not_affected", "uncertain"]
QUEUE_TOP = 20
# Markdown tables only (CSV/JSON keep the enums)
VERDICT_KO = {"affected": "영향", "not_affected": "영향 없음", "uncertain": "보류(사람)"}
DEP_KO = {"direct": "직접", "transitive": "전이", "unreferenced": "미참조", "undeclared": "미선언 import",
          "tooling": "설치 도구", "unknown": "미상"}


def _cell(x, n: int | None = None) -> str:
    """Markdown table cell: one line (word-boundary cut with '…'), '|' escaped."""
    t = clip(x, n) if n else " ".join(str(x).split())
    return t.replace("|", "\\|")


def compat_label(a: Action) -> str:
    """'호환성 위험' column: semver major and Python runtime are separate facts."""
    if a.kind == "remove":
        return "삭제"
    parts = []
    if a.major_bump:
        parts.append("메이저")
    if a.runtime_upgrade:
        parts.append(f"런타임({a.runtime_note})" if a.runtime_note else "런타임")
    return " · ".join(parts)


def feedback_summary(judgments: list[Judgment]) -> dict:
    """Feedback-decided rows split into demo records (DEMO_BY) and real reviews."""
    fb = [j for j in judgments if j.decided_by == "feedback"]
    demo = [j for j in fb if is_demo(j)]
    return {"rows": len(fb), "demo_rows": len(demo), "real_rows": len(fb) - len(demo),
            "demo_decisions": len({(j.package.split("@")[0], j.cve) for j in demo}),
            "demo_by": sorted({feedback_by(j) for j in demo})}


def _pct(x) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def _num(x, nd=2) -> str:
    return "-" if x is None else f"{x:.{nd}f}"


def _kpi_table(m: dict, fbs: dict | None = None) -> str:
    w = m.get("warning_reduction", {})
    c = m.get("condition_accuracy", {})
    t = m.get("top3_risk_coverage", {})
    h = m.get("human_review_ratio", {})
    a = m.get("agent_seconds_per_item", {})
    hu = m.get("human_minutes_per_item", {})
    x = m.get("extra", {})
    fbs = fbs or {"rows": x.get("feedback_rows", 0), "demo_rows": 0, "real_rows": x.get("feedback_rows", 0),
                  "demo_decisions": 0, "demo_by": []}
    if fbs["demo_rows"] and not fbs["real_rows"]:
        who = f"시연용 데모 결정 {fbs['demo_decisions']}건({', '.join(fbs['demo_by'])}, 실제 검토 아님)"
        with_label, excl = "경고 감소율 (데모 결정 포함)", f"{who}으로 처리된 {fbs['rows']}행 제외"
        incl = f"{who}으로 처리된 {fbs['rows']}행 포함"
    elif fbs["rows"]:
        demo = f" (그중 데모 기록 {fbs['demo_rows']}행)" if fbs["demo_rows"] else ""
        with_label = "경고 감소율 (사람 결정 포함)"
        excl = f"사람 피드백으로 처리된 {fbs['rows']}행{demo} 제외"
        incl = f"사람 피드백으로 처리된 {fbs['rows']}행{demo} 포함"
    else:
        with_label, excl, incl = "경고 감소율 (판정 행 기준)", "피드백 처리 행 없음", "피드백 처리 행 없음"
    rows = [
        ["경고 감소율 (에이전트 단독)", _pct(x.get("agent_only_reduction")),
         f"{excl}: not_affected {x.get('agent_only_not_affected', 0)} / 판정 {w.get('judged', 0)}"],
        [with_label, _pct(w.get("by_finding")),
         f"{incl}: not_affected {w.get('not_affected', 0)} / 판정 {w.get('judged', 0)} "
         f"(스캐너 탐지 {w.get('scanner_findings', 0)})"],
        ["경고 감소율 (고유 취약점 기준)", _pct(w.get("by_unique_vuln")),
         f"{w.get('unique_vulns_not_affected', 0)} / {w.get('unique_vulns_judged', 0)}"
         + (" · 데모 결정 포함" if fbs["demo_rows"] else "")],
        ["조건 판정 정확도 (테스트셋)", _pct(c.get("accuracy")),
         c.get("note") or (f"매칭 {c.get('matched', 0)}건 중 정답 {x.get('core_correct', '?')}건 · "
                           f"사람 검수 {x.get('core_reviewed', 0)}/{c.get('matched', 0)} · "
                           f"다수 클래스(전부 not_affected) 기준선 {_pct(x.get('core_baseline'))}")],
        ["판정한 건의 정밀도 (테스트셋)", _pct(x.get("core_decided_precision")),
         f"uncertain 제외 {x.get('core_decided', 0)}건 중 정답 {x.get('core_decided_correct', 0)}건 · "
         f"보류(사람에게) {x.get('core_abstain', 0)}건"
         + (f" · 정답 라벨은 AI 초안(사람 검수 {x.get('core_reviewed', 0)}/{c.get('matched', 0)})"
            if x.get("core_reviewed", 0) < c.get("matched", 0) else "")],
        ["조건 판정 정확도 (튜닝셋)", _pct(x.get("ext_accuracy")),
         f"규칙 개선에 사용한 세트 {x.get('ext_n', 0)}건 — 참고용"],
        ["Top-3 업그레이드 위험 커버율", _pct(t.get("coverage")),
         f"상위 3개 조치 {_num(t.get('covered_risk'), 3)} / 잔여 위험 {_num(t.get('total_risk'), 3)}"
         + (f" · 계획 전체(k={t.get('plan_k')}) {_pct(t.get('plan_coverage'))}" if t.get("plan_k") else "")],
        ["사람 검토 비율", _pct(h.get("ratio")), f"uncertain {h.get('uncertain', 0)} / 판정 {h.get('judged', 0)}"],
        ["에이전트 처리 시간 (건당)", f"{_num(a.get('mean'), 2)}s",
         f"중앙값 {_num(a.get('median'), 2)}s · {a.get('note', '')}"],
        ["사람 처리 시간 (건당)", "미측정" if hu.get("mean") is None else f"{hu['mean']}분",
         "data/eval/human_timing.yaml 기록 후 계산" if hu.get("mean") is None else hu.get("note", "")],
        ["속도 향상", "미산출" if m.get("speedup") is None else f"{m['speedup']}배",
         "사람 시간 측정 후" if m.get("speedup") is None else "사람 평균 / 에이전트 평균"],
    ]
    out = _table(["지표", "값", "산출 근거"], rows)
    mc = m.get("mode_comparison")
    if mc:
        out += "\n\n**판정 모드 비교** (같은 입력, 규칙만 다름 · 현재 모드: " + m.get("judge_mode", "conservative") + ")\n\n" + _table(
            ["모드", "경고 감소율(에이전트 단독)", "사람 검토 비율", "테스트셋 정확도", "판정한 건 정밀도", "놓친 affected"],
            [[k, _pct(v["reduction_agent_only"]), _pct(v["human_review"]), _pct(v["core_accuracy"]),
              f'{_pct(v["core_decided_precision"])} ({v["core_decided"]}건)', v["core_false_not_affected"]]
             for k, v in mc.items()])
    return out


def write_report(path: Path = OUT_DIR / "report.md", *, gsum: dict, rows: list[dict], scored: list[Scored],
                 judgments: list[Judgment], plan: PlanResult | None, metrics: dict, llm_name: str,
                 tickets: list[Path] | None = None, graph_png: str = "graph.png") -> Path:
    """metrics = kpis(...) output; may carry 'eval' = evaluate(...) for the confusion matrix."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    j_idx = {finding_id(j.service, j.package, j.cve): j for j in judgments}
    score = {finding_id(s.finding.service, s.finding.package.key, s.finding.vuln_id): s.score for s in scored}
    fbs = feedback_summary(judgments)
    p = gsum.get("provenance", {})

    info = [
        f"- 실행 시각: {p.get('run_at', '-')} · 소요 {p.get('seconds_total', '-')}s",
        f"- 범위: 본인 레포 {gsum.get('services', '-')}개 파일럿 (가상의 계열사 서비스) · "
        f"패키지 {gsum.get('package_versions', '-')}개 · 고유 취약점 {gsum.get('vulnerabilities', '-')}개 · "
        f"탐지 행 {len(scored)}",
        f"- 도구: syft {p.get('tools', {}).get('syft', '-')} · grype {p.get('tools', {}).get('grype', '-')} "
        f"(DB {p.get('grype_db_built', '-')}) · KEV {p.get('kev', {}).get('catalogVersion', '-')} · "
        f"EPSS {p.get('epss', {}).get('fetched_at', '-')}",
        f"- 판정 LLM: {llm_name} (공개 권고문만 입력, 내부 자산 정보는 코드로만 결합)",
    ]

    # verdict × rule
    by_rule = Counter((j.rule, j.verdict) for j in judgments)
    rules = sorted({r for r, _ in by_rule})
    dist = [[r, *[by_rule[(r, c)] for c in CLASSES], sum(by_rule[(r, c)] for c in CLASSES)] for r in rules]
    tot = [sum(by_rule[(r, c)] for r in rules) for c in CLASSES]
    dist.append(["**합계**", *tot, sum(tot)])
    by_who = Counter(j.decided_by for j in judgments)
    who_txt = " · ".join(f"{k} {v}" + (" (데모 기록)" if k == "feedback" and fbs["demo_rows"] == v and v else "")
                         for k, v in sorted(by_who.items()))

    conf_md = ""
    ev = metrics.get("eval") or {}
    if ev.get("available"):
        mat = ev["confusion"]["matrix"]
        conf_md = "\n".join([
            "", f"테스트셋 혼동 행렬 (행: 정답, 열: 판정, 매칭 {ev['matched']}/{ev['n']}건)", "",
            _table(["정답 \\ 판정", *CLASSES], [[t, *[mat[t][c] for c in CLASSES]] for t in CLASSES]),
        ])

    # Top-3 upgrades
    plan_md = "(조치 계획 없음)"
    if plan is not None and plan.actions:
        pr = []
        for i, a in enumerate(plan.actions[:3], 1):
            what = (f"삭제 {a.ecosystem}:{a.package}" if a.kind == "remove"
                    else f"{a.ecosystem}:{a.package} {', '.join(a.from_versions)} → {a.target_version}")
            pr.append([i, what, ", ".join(a.services), len(a.covers), f"{a.risk_covered:.3f}",
                       _pct(a.risk_covered / plan.total_risk if plan.total_risk else None),
                       _cell(compat_label(a)) or "-"])
        t3 = metrics.get("top3_risk_coverage", {})
        plan_md = "\n".join([
            _table(["#", "조치", "서비스", "해소 행", "위험 감소", "비중", "호환성 위험"], pr), "",
            "호환성 위험: 메이저 = semver 메이저 버전 변경 · 런타임 = 목표 버전의 Requires-Python이 "
            "서비스 Python과 맞지 않음", "",
            f"Top-3 위험 커버율: **{_pct(t3.get('coverage'))}** · 계획 전체 k={plan.k}: {_pct(plan.coverage)}"
            f" · 수정 불가/삭제 불가 {len(plan.unfixable)}건",
        ])

    # human review queue
    unc = [j for j in judgments if j.verdict == "uncertain"]
    unc.sort(key=lambda j: (-score.get(finding_id(j.service, j.package, j.cve), 0.0), j.service, j.package, j.cve))
    q = [[_cell(j.service), _cell(j.package), _cell(j.cve),
          _num(score.get(finding_id(j.service, j.package, j.cve)), 3), _cell(j.rule),
          _cell("; ".join(j.conditions) or j.check_in_code or "-", 120)] for j in unc[:QUEUE_TOP]]
    queue_md = ((f"{len(unc)}건 중 종합 점수 상위 {min(QUEUE_TOP, len(unc))}건. 전체 목록은 `out/ranked.csv`"
                 "(verdict = uncertain). 조건 열은 LLM이 권고문에서 뽑은 영문 원문입니다.\n\n"
                 + _table(["서비스", "패키지", "취약점", "점수", "사유(규칙)", "조건/검색"], q)) if q else "(없음)")

    # Top-10 overall
    t10 = []
    for r in rows[:10]:
        key = f"{r['ecosystem']}:{r['package']}@{r['version']}"
        j = j_idx.get(finding_id(r["service"], key, r["vuln_id"]))
        t10.append([r["rank"], r["service"], r["owner_team"], f"{r['package']}@{r['version']}",
                    DEP_KO.get(r["dependency"], r["dependency"]),
                    r["vuln_id"], r["cvss"], r["epss"] or "-", "Y" if r["kev"] in (True, "True") else "", r["score"],
                    VERDICT_KO.get(j.verdict, j.verdict) if j else "미판정", r["fix_version"] or "-"])
    top_md = _table(["#", "서비스", "팀", "패키지", "의존", "취약점", "CVSS", "EPSS", "KEV", "점수", "판정",
                     "수정 버전"], t10)

    links = []
    found = tickets if tickets is not None else sorted((path.parent / "tickets").glob("T[0-9][0-9]-*.md"))
    for t in found:
        rel = os.path.relpath(Path(t), path.parent)
        links.append(f"- [{Path(t).stem}]({rel})")

    parts = [
        "# SW 공급망 스캐닝 리포트", "",
        "## 실행 정보", *info, "",
        "## 핵심 지표", _kpi_table(metrics, fbs), "",
        "## 판정 분포 (판정 × 규칙)",
        _table(["규칙", *CLASSES, "합계"], dist), "",
        "결정 주체: " + who_txt
        + (f"\n\nfeedback_suppressed {fbs['demo_rows']}행은 시연용 데모 결정 {fbs['demo_decisions']}건"
           f"({', '.join(fbs['demo_by'])})으로 처리됐습니다. 실제 사람 검토가 아닙니다." if fbs["demo_rows"] else "")
        + conf_md, "",
        "## 업그레이드 Top-3", plan_md, "",
        f"## 사람 검토 대기열 ({len(unc)}건)", queue_md, "",
        "## 종합 위험 Top-10", top_md, "",
        "## 영향 그래프", f"![graph]({graph_png})", "",
        f"## 조치 티켓 ({len(links)}건)", *(links or ["(없음)"]),
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path
