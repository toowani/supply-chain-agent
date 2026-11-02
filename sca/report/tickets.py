"""One Markdown ticket per plan action (Korean).

LLM writes only the narrative (요약·영향·작업 단계) from PUBLIC data: package name, vuln ids,
OSV summaries, fix version, advisory workaround, compatibility flags. Everything internal
(services, teams, paths, scores, code hits, interpreter versions) is filled in by the template
after the LLM call, so it never enters a prompt.

The LLM text is post-processed by code (clean_narrative): list numbers stripped (the template
numbers steps), steps naming tools the agent does not use or a rescan dropped (the verification
step is fixed code text), sentences with absolute claims dropped, and "메이저" removed when the
change is not a semver-major bump.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field

from sca.config import CACHE_DIR, OUT_DIR, Asset
from sca.contracts import Action, Judgment, PlanResult, finding_id
from sca.report.tables import _fmt, _table, clip
from sca.score.risk import Scored, vuln_sort_key

TICKET_DIR = OUT_DIR / "tickets"
REPORT_CACHE = CACHE_DIR / "report"
RESCAN_CMD = "python -m sca run"
# Decision fields (sca.contracts.Decision); adjust if the CLI flags differ.
FEEDBACK_CMD = ("python -m sca feedback add --service {service} --package {package} --vuln {vuln} "
                "--decision approve|reject --verdict affected|not_affected|uncertain "
                "--reason <not_reachable|platform|dev_only|false_positive|accepted_risk|fixed|confirmed> "
                "--note \"...\"")
MAX_PROMPT_VULNS = 20                  # highest-score first
VERDICT_KO = {"affected": "영향 있음", "not_affected": "영향 없음", "uncertain": "사람 검토"}

SYSTEM = (
    "You write the narrative part of a Korean remediation ticket for a software supply-chain "
    "vulnerability fix. Use only the facts in the input JSON. Do not invent CVE ids, versions, "
    "services, infrastructure or tools. Write in Korean, concise, factual, polite (합니다). "
    "summary: 1-2 sentences on what to do and which listed vulnerabilities the fix version "
    "resolves. impact: 1-3 sentences on what an attacker could do per the advisories, written "
    "conditionally (조건 충족 시 …할 수 있습니다); several findings are still under review. "
    "steps: 2-5 short work steps (change the dependency version, run tests, deploy). "
    "Do not number the steps. Do not include a rescan or verification step (added by code). "
    "Do not name tools (Snyk, Trivy, Docker, CI products) and do not use absolute claims "
    "(모든, 모두, 완전히, all attacks blocked). If major_version_bump is false, do not call the "
    "change a major version change. If python_runtime_upgrade_required is true, mention that the "
    "Python runtime must be upgraded first."
)
VERIFY_STEP = f"재스캔(`{RESCAN_CMD}`) 후 위 취약점이 `out/ranked.csv`에서 사라졌는지 확인"
_NUM = re.compile(r"^\s*(?:[-*•]\s*)?(?:\d+\s*[.)]\s*)+")
_TOOL = re.compile(r"snyk|trivy|grype|dependabot|renovate|docker|kubernetes|\bk8s\b|jenkins|github actions|"
                   r"sonarqube|owasp|스캐너|스캔|재검증|rescan|\bscan", re.I)
_ABSOLUTE = re.compile(r"모든|모두|완전|전부|시스템 전체|100\s*%|영구", re.I)
_SENT = re.compile(r"(?<=[.!?])\s+")


class TicketNarrative(BaseModel):
    summary: str
    impact: str
    steps: list[str] = Field(default_factory=list)


def _osv_record(osv: dict[str, dict], vid: str, aliases: list[str]) -> dict:
    for i in [vid, *aliases]:
        if osv.get(i):
            return osv[i]
    return {}


def _public_facts(action: Action, vulns: list[tuple[str, dict, str]]) -> dict:
    """Public-only prompt payload. vulns: (vuln_id, osv_record, advisory workaround)."""
    return {
        "action": action.kind,
        "ecosystem": action.ecosystem,
        "package": action.package,
        "fix_version": action.target_version or None,
        "major_version_bump": action.major_bump,
        "python_runtime_upgrade_required": action.runtime_upgrade,
        "total_vulnerabilities": len(vulns),
        "vulnerabilities": [{"id": vid, "summary": (rec.get("summary") or "")[:300],
                             "workaround": wa[:300]} for vid, rec, wa in vulns[:MAX_PROMPT_VULNS]],
    }


def _fallback(facts: dict) -> TicketNarrative:
    pkg = f"{facts['ecosystem']}:{facts['package']}"
    vs = [v["id"] for v in facts["vulnerabilities"]]
    more = facts["total_vulnerabilities"] - min(len(vs), 5)
    ids = ", ".join(vs[:5]) + (f" 외 {more}건" if more > 0 else "")
    n = facts["total_vulnerabilities"]
    if facts["action"] == "remove":
        summary = f"사용되지 않는 패키지 {pkg}를 삭제해 취약점 {n}건({ids})을 해소합니다."
        steps = [f"의존성 목록과 lock 파일에서 {facts['package']} 제거", "테스트 실행", "배포"]
    else:
        summary = f"{pkg}를 {facts['fix_version']} 이상으로 올려 취약점 {n}건({ids})을 해소합니다."
        steps = [f"{facts['package']} 버전을 {facts['fix_version']}로 변경하고 lock 파일 갱신",
                 "단위·통합 테스트 실행" + (" (메이저 버전 변경: 변경 내역 확인 필수)" if facts["major_version_bump"] else ""),
                 "배포"]
    sums = [v["summary"] for v in facts["vulnerabilities"] if v["summary"]]
    impact = ("권고문 요약: " + " / ".join(sums[:3])) if sums else "권고문 요약 없음."
    return TicketNarrative(summary=summary, impact=impact, steps=steps)


def _no_major(t: str) -> str:
    t = re.sub(r"\s*\(\s*메이저(?:\s*버전)?\s*\)", "", t)
    return re.sub(r"메이저\s*(?:버전\s*)?", "", t)


def _sentences(t: str, keep) -> str:
    return " ".join(x for x in _SENT.split(" ".join(t.split())) if x and keep(x))


def clean_narrative(nar: TicketNarrative, facts: dict) -> TicketNarrative:
    """Deterministic guard over LLM prose (see module doc). Empty summary/impact after the
    filter → template text. The verification step is always the fixed VERIFY_STEP."""
    fb = _fallback(facts)
    fix = (lambda t: t) if facts.get("major_version_bump") else _no_major
    summary = _sentences(fix(nar.summary), lambda x: not _ABSOLUTE.search(x)) or fb.summary
    impact = _sentences(fix(nar.impact), lambda x: not _ABSOLUTE.search(x)) or fb.impact
    impact = impact.replace("가능해집니다", "가능해질 수 있습니다")
    steps = []
    for st in nar.steps:
        st = fix(_NUM.sub("", " ".join(str(st).split()))).strip()
        if st and not _TOOL.search(st) and not _ABSOLUTE.search(st):
            steps.append(st)
    steps = (steps or fb.steps)[:5]
    return TicketNarrative(summary=summary, impact=impact, steps=steps)


_RUNTIME_STEP = re.compile(r"런타임|Python\s*3\.\d+\s*이상")


def _code_steps(facts: dict, action: Action, steps: list[str]) -> list[str]:
    """Code-owned steps around the narrative: runtime first (when needed), rescan last."""
    pre = ([f"Python 런타임 업그레이드 ({action.runtime_note})"]
           if action.runtime_upgrade and action.runtime_note else [])
    if pre:   # the code-owned runtime step replaces any runtime step the LLM wrote itself
        steps = [s for s in steps if not _RUNTIME_STEP.search(s)]
    return pre + steps + [VERIFY_STEP]


def narrative(facts: dict, llm=None, cache_dir: Path = REPORT_CACHE) -> tuple[TicketNarrative, str]:
    """(narrative, source) — source is the model name, 'cache:<model>' or 'template'.
    LLM/cached prose passes through clean_narrative; steps exclude the verification step."""
    if llm is None:
        return _fallback(facts), "template"
    user = json.dumps(facts, ensure_ascii=False, sort_keys=True)
    h = hashlib.sha256(f"{llm.name}\n{SYSTEM}\n{user}".encode()).hexdigest()[:24]
    p = Path(cache_dir) / f"{h}.txt"
    if p.exists():
        try:
            raw = TicketNarrative.model_validate_json(p.read_text(encoding="utf-8"))
            return clean_narrative(raw, facts), f"cache:{llm.name}"
        except ValueError:
            pass
    try:
        out = llm.structured(SYSTEM, user, TicketNarrative)
    except Exception:  # backend down / invalid output → deterministic template
        return _fallback(facts), "template"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(out.model_dump_json(), encoding="utf-8")       # raw LLM output; cleaned on read
    return clean_narrative(out, facts), llm.name


def compat_text(action: Action) -> str:
    """'호환성 위험' line: semver major and Python runtime are separate facts."""
    if action.kind == "remove":
        return "미참조 패키지 삭제 — import·런타임 사용 여부 재확인"
    parts = []
    if action.major_bump:
        parts.append(f"메이저 버전 변경({', '.join(action.from_versions)} → {action.target_version}) "
                     "— 변경 내역·테스트 확인 필요")
    if action.runtime_upgrade:
        parts.append(f"Python 런타임 업그레이드 필요({action.runtime_note})" if action.runtime_note
                     else "Python 런타임 업그레이드 필요")
    return " · ".join(parts) or "낮음 (메이저 버전 유지)"


def _one_line(s: str, n: int) -> str:
    return " ".join(str(s).split())[:n]


def _code(s: str) -> str:
    """Inline code span that survives backticks inside the text (CommonMark: longer fence)."""
    s = _one_line(s, 120)
    if "`" not in s:
        return f"`{s}`"
    return f"`` {s} ``"


def _hits(ev: dict) -> list[str]:
    """file:line only — service source text stays out of shareable artifacts (repos may be private)."""
    out = []
    for h in ev.get("code_hits", []) or []:
        if isinstance(h, dict):
            out.append(f"`{h.get('file')}:{h.get('line')}`")
        else:
            out.append(f"`{':'.join(str(h).split(':', 2)[:2])}`")
    return out


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")[:60]


def render_ticket(i: int, action: Action, plan: PlanResult, scored: dict[str, Scored],
                  judg: dict[str, Judgment], osv: dict[str, dict], assets: dict[str, Asset],
                  llm=None, cache_dir: Path = REPORT_CACHE) -> str:
    rows = [scored[fid] for fid in action.covers if fid in scored]
    rows.sort(key=lambda r: (-r.score, vuln_sort_key(r.finding.vuln_id), r.finding.service))
    vulns: dict[str, tuple[str, dict, str]] = {}
    for r in rows:
        f = r.finding
        j = judg.get(finding_id(f.service, f.package.key, f.vuln_id))
        if f.vuln_id not in vulns:
            vulns[f.vuln_id] = (f.vuln_id, _osv_record(osv, f.vuln_id, f.aliases), j.workaround if j else "")
    facts = _public_facts(action, list(vulns.values()))      # score order
    nar, src = narrative(facts, llm, cache_dir)

    pkg = f"{action.ecosystem}:{action.package}"
    what = (f"삭제 {pkg} ({', '.join(action.from_versions)})" if action.kind == "remove"
            else f"업그레이드 {pkg} {', '.join(action.from_versions)} → {action.target_version}")
    teams = sorted({assets[s].owner_team for s in action.services if s in assets})
    pct = 100 * action.risk_covered / plan.total_risk if plan.total_risk else 0.0

    vt = []
    for r in rows:
        f = r.finding
        j = judg.get(finding_id(f.service, f.package.key, f.vuln_id))
        vt.append([f.vuln_id, f.service, f"{f.package.name}@{f.package.version}", r.cvss,
                   _fmt(r.epss, 4) if r.epss is not None else "-", "Y" if r.kev else "",
                   f"{j.verdict} ({j.rule})" if j else "미판정", _fmt(r.score, 3)])
    vt = [[str(c).replace("|", "\\|") for c in row] for row in vt]

    ev_lines = []
    for r in rows:
        f = r.finding
        j = judg.get(finding_id(f.service, f.package.key, f.vuln_id))
        if not j:
            continue
        quote = (j.evidence or {}).get("advisory_quote", "")
        hits = _hits(j.evidence or {})
        if not quote and not hits and not j.check_in_code:
            continue
        ev_lines.append(f"- **{f.vuln_id}** · {f.service}")
        if quote:
            ev_lines.append(f"  - 권고문: \"{clip(quote, 300)}\"")
        if j.check_in_code:
            ev_lines.append(f"  - 코드 검색: {clip(j.check_in_code, 300)}")
        for h in hits[:5]:
            ev_lines.append(f"  - 코드: {h}")

    lines = [
        f"# [T{i:02d}] {what}",
        "",
        f"- 조치: **{what}**",
        f"- 대상 서비스: {', '.join(action.services)}",
        f"- 담당팀: {', '.join(teams) or '-'}",
        f"- 위험 감소량: {action.risk_covered:.3f} (전체 잔여 위험 {plan.total_risk:.3f} 중 {pct:.1f}%, "
        "앞선 티켓과 겹치는 행 제외)",
        f"- 호환성 위험: {compat_text(action)}",
        *( [f"- 비고: {action.note}"] if action.note else [] ),
        "",
        "## 요약",
        nar.summary,
        "",
        "## 영향 (권고문 기준, 조건 충족 시)",
        nar.impact,
        "",
        "## 작업 단계",
        *[f"{n}. {s}" for n, s in enumerate(_code_steps(facts, action, nar.steps), 1)],
        "",
        f"## 해소 취약점 ({len(rows)}건)",
        _table(["취약점", "서비스", "패키지", "CVSS", "EPSS", "KEV", "판정(규칙)", "점수"], vt) if vt else "(없음)",
        "",
        "## 근거",
        *(ev_lines or ["(판정 근거 없음)"]),
        "",
        "## 검증 방법",
        f"1. 조치 반영 후 `{RESCAN_CMD}` 재실행 (직전 실행 결과는 `out/history/`에 보관)",
        "2. 위 표의 취약점이 `out/ranked.csv`에서 사라졌는지 확인",
        "3. `--reason fixed`로 기록하면 다음 실행의 재스캔 검증이 해소 여부를 자동 대조",
        "",
        "## 승인/기각 기록",
        "판정이 맞으면 approve, 틀리면 reject와 올바른 verdict·사유를 남긴다. 다음 판정에 반영된다.",
        "",
        "```",
        *sorted({FEEDBACK_CMD.format(service=r.finding.service, package=pkg, vuln="<취약점 ID>")
                 for r in rows}),
        "```",
        "",
        "대상 취약점 ID: " + (" ".join(sorted({r.finding.vuln_id for r in rows}, key=vuln_sort_key)) or "-"),
        "",
        f"<sub>서술 생성: {src} (공개 권고문 정보만 입력) · 서비스·팀·점수·코드 근거는 코드가 채움</sub>",
    ]
    return "\n".join(lines) + "\n"


def write_tickets(plan: PlanResult, scored: list[Scored], judgments: list[Judgment], osv: dict[str, dict],
                  llm=None, out_dir: Path = TICKET_DIR, assets: dict[str, Asset] | None = None,
                  cache_dir: Path = REPORT_CACHE) -> list[Path]:
    """Write T01-…md per plan action (greedy order). Old T??-*.md files in out_dir are replaced."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("T[0-9][0-9]-*.md"):
        old.unlink()
    s_idx = {finding_id(s.finding.service, s.finding.package.key, s.finding.vuln_id): s for s in scored}
    j_idx = {finding_id(j.service, j.package, j.cve): j for j in judgments}
    paths = []
    for i, a in enumerate(plan.actions, 1):
        md = render_ticket(i, a, plan, s_idx, j_idx, osv, assets or {}, llm, cache_dir)
        p = out_dir / f"T{i:02d}-{a.kind}-{_slug(a.ecosystem + '-' + a.package)}.md"
        p.write_text(md, encoding="utf-8")
        paths.append(p)
    return paths
