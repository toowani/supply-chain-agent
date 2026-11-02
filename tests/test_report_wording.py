"""Report/ticket wording guards: compatibility facts kept apart, demo feedback labelled, LLM ticket
prose cleaned deterministically, word-boundary cuts, Korean evidence labels parsed."""
from sca.contracts import Action, Judgment, PlanResult
from sca.report import tickets as tk
from sca.report.insights import _searched_scopes
from sca.report.render import _kpi_table, compat_label, feedback_summary, write_report
from sca.report.tables import clip


def _act(**kw):
    base = dict(kind="upgrade", ecosystem="pypi", package="aiohttp", target_version="3.14.4",
                services=["s"], from_versions=["3.13.5"], covers=[], risk_covered=1.0)
    return Action(**{**base, **kw})


def test_compat_major_and_runtime_are_separate():
    assert compat_label(_act()) == ""
    assert compat_label(_act(major_bump=True)) == "메이저"
    rt = _act(runtime_upgrade=True, runtime_note="Python 3.9.6 → >=3.10")
    assert compat_label(rt) == "런타임(Python 3.9.6 → >=3.10)"
    assert compat_label(_act(major_bump=True, runtime_upgrade=True)) == "메이저 · 런타임"
    t = tk.compat_text(rt)
    assert "메이저" not in t and "Python 런타임 업그레이드 필요(Python 3.9.6 → >=3.10)" in t
    assert tk.compat_text(_act()) == "낮음 (메이저 버전 유지)"
    assert "메이저 버전 변경(1.26.20 → 2.8.0)" in tk.compat_text(
        _act(major_bump=True, from_versions=["1.26.20"], target_version="2.8.0"))


FACTS = {"action": "upgrade", "ecosystem": "pypi", "package": "aiohttp", "fix_version": "3.14.4",
         "major_version_bump": False, "python_runtime_upgrade_required": True, "total_vulnerabilities": 2,
         "vulnerabilities": [{"id": "CVE-1", "summary": "s", "workaround": ""}]}


def test_clean_narrative_strips_numbers_tools_absolutes_and_false_major():
    raw = tk.TicketNarrative(
        summary="aiohttp를 3.14.4(메이저 버전)로 업그레이드합니다. 알려진 취약점을 모두 제거합니다.",
        impact="조건 충족 시 요청 스머글링이 가능해집니다.",
        steps=["1. requirements.txt에서 버전을 3.14.4로 변경", "2) 테스트 실행",
               "3. Docker 이미지에 반영", "4. 재스캔(예: Snyk, Trivy)으로 검증", "모든 공격 경로 차단 확인"])
    c = tk.clean_narrative(raw, FACTS)
    assert c.summary == "aiohttp를 3.14.4로 업그레이드합니다."
    assert c.impact == "조건 충족 시 요청 스머글링이 가능해질 수 있습니다."
    assert c.steps == ["requirements.txt에서 버전을 3.14.4로 변경", "테스트 실행"]
    steps = tk._code_steps(FACTS, _act(runtime_upgrade=True, runtime_note="Python 3.9.6 → >=3.10"), c.steps)
    assert steps[0].startswith("Python 런타임 업그레이드") and steps[-1] == tk.VERIFY_STEP
    # an LLM-written runtime step is dropped when the code adds its own
    dup = tk._code_steps(FACTS, _act(runtime_upgrade=True, runtime_note="Python 3.9.6 → >=3.10"),
                         ["Python 3.10 이상으로 런타임을 올립니다", "테스트 실행"])
    assert [s for s in dup if "런타임" in s] == [dup[0]] and "테스트 실행" in dup
    assert "Python 3.10 이상으로 런타임을 올립니다" in tk._code_steps(FACTS, _act(), ["Python 3.10 이상으로 런타임을 올립니다"])
    assert "python -m sca run" in tk.VERIFY_STEP
    # everything filtered → template text, never empty
    empty = tk.clean_narrative(tk.TicketNarrative(summary="모두 해결합니다.", impact="", steps=["1. 스캔"]), FACTS)
    assert empty.summary and empty.steps and empty.impact
    # a real major bump keeps the word
    major = tk.clean_narrative(tk.TicketNarrative(summary="2.8.0(메이저 버전)로 올립니다.", impact="x", steps=["a"]),
                               {**FACTS, "major_version_bump": True})
    assert "메이저" in major.summary


def _fb(by):
    return Judgment(service="s", cve="CVE-1", package="npm:undici@7.0.0", verdict="not_affected",
                    rule="feedback_suppressed", decided_by="feedback",
                    evidence={"note": f"reject by {by} at 2026-10-31T16:24:25Z (reason=dev_only, scope=all_services)"})


def test_demo_feedback_labelled_in_kpis():
    js = [_fb("demo-reviewer"), _fb("demo-reviewer").model_copy(update={"service": "t"}),
          Judgment(service="s", cve="CVE-2", package="pypi:p@1", verdict="not_affected", rule="api_not_referenced")]
    fbs = feedback_summary(js)
    assert fbs == {"rows": 2, "demo_rows": 2, "real_rows": 0, "demo_decisions": 1, "demo_by": ["demo-reviewer"]}
    m = {"warning_reduction": {"by_finding": 0.3, "not_affected": 3, "judged": 10, "scanner_findings": 10},
         "extra": {"agent_only_reduction": 0.1, "agent_only_not_affected": 1, "feedback_rows": 2,
                   "core_reviewed": 0, "core_decided": 5, "core_decided_correct": 5, "core_decided_precision": 1.0},
         "condition_accuracy": {"matched": 20}, "human_minutes_per_item": {"mean": None}}
    md = _kpi_table(m, fbs)
    lines = [ln for ln in md.splitlines() if ln.startswith("| 경고 감소율")]
    assert lines[0].startswith("| 경고 감소율 (에이전트 단독) | 10.0%")          # agent-only first
    assert lines[1].startswith("| 경고 감소율 (데모 결정 포함) | 30.0%")
    assert "실제 검토 아님" in lines[1] and "사람 피드백" not in md
    assert "정답 라벨은 AI 초안(사람 검수 0/20)" in md
    assert "| 사람 처리 시간 (건당) | 미측정 | data/eval/human_timing.yaml 기록 후 계산 |" in md
    assert "| 속도 향상 | 미산출 | 사람 시간 측정 후 |" in md
    real = feedback_summary([_fb("kim")])
    assert real["real_rows"] == 1 and "사람 피드백으로 처리된 1행" in _kpi_table(m, real)


def test_report_compat_column_and_queue(tmp_path):
    a = _act(runtime_upgrade=True, runtime_note="Python 3.9.6 → >=3.10")
    plan = PlanResult(k=1, total_risk=1.0, actions=[a], covered_risk=1.0, coverage=1.0)
    js = [Judgment(service="s", cve=f"CVE-{i}", package="pypi:p@1", verdict="uncertain", rule="r",
                   conditions=["word " * 60]) for i in range(25)]
    rep = write_report(tmp_path / "r.md", gsum={}, rows=[], scored=[], judgments=js, plan=plan,
                       metrics={}, llm_name="x").read_text()
    assert "| 호환성 위험 |" in rep and "런타임(Python 3.9.6 → >=3.10)" in rep and "메이저 변경" not in rep
    assert "25건 중 종합 점수 상위 20건" in rep
    queue = rep.split("## 사람 검토 대기열", 1)[1].split("##", 1)[0]
    assert sum(ln.startswith("| s |") for ln in queue.splitlines()) == 20
    assert "word…" in queue and "wor…" not in queue


def test_clip_word_boundary():
    assert clip("short", 10) == "short"
    assert clip("alpha beta gamma delta", 15) == "alpha beta…"
    assert clip("a" * 30, 10) == "a" * 9 + "…"


def test_insights_parse_korean_and_old_labels():
    new = "p 직접 import 3곳; API ['x']: 서비스 코드 0곳, 의존 패키지 0곳 · 검색 범위: 서비스 코드(p import 파일 2개); dep"
    assert _searched_scopes(new) == "서비스 코드(p import 파일 2개); dep"
    assert _searched_scopes("direct import of p: 3 hit(s); searched: service code (2 file(s) importing p)") == \
        "service code (2 file(s) importing p)"
