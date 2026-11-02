"""Portfolio PDF (A4, 6 pages) built only from measured outputs, so a rerun after the human review
updates every number without edits.

Sources: out/metrics.json, out/plan.json, out/graph_summary.json, out/ranked.csv, out/graph_top_path.png,
out/vex.json, out/tickets/*.md, data/eval/human_timing.yaml, data/eval/ground_truth.public.yaml,
data/feedback/decisions.jsonl,
config/scoring.yaml, docs/verification.md (pre-fix v3 figures).

Usage: .venv/bin/python docs/portfolio/build.py [--video URL] [--root DIR] [--outdir DIR] [--allow-stale]
  --root         project root that holds out/ and data/ (default: this repo; use a temp copy to test)
  --outdir       where portfolio.html/pdf are written (default: docs/portfolio)
  --allow-stale  build even if out/metrics.json predates the current review state (otherwise abort)
"""
from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import re
import shutil
import statistics
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
MODE_NAME = {"proactive": "적극 모드", "conservative": "보수 모드"}
DEMO_BY = {"demo-reviewer"}
# hold category names from metrics → wording that does not claim the call graph already works
HOLD_CAT = {"콜그래프로 해소 가능": "콜그래프 필요(전이·의존 경로)"}
COND_TAG = {"input": "입력 조건", "api": "API 조건", "platform": "플랫폼 조건", "version": "버전 조건"}
RULE_KO = {"unconditional_version_match": "조건 없이 버전만 맞아 affected"}


# ---------- helpers ----------

def pct(x, nd=1):
    return "-" if x is None else f"{100 * x:.{nd}f}%"


def esc(s) -> str:
    return html.escape(str(s))


def frac(k, n, nd=1):
    """'53/174건 (30.5%)'"""
    return f"{k}/{n}건 ({pct(k / n, nd) if n else '-'})"


def table(headers, rows, cls="", widths=None):
    cols = "".join(f'<col style="width:{w}">' for w in widths) if widths else ""
    th = "".join(f"<th>{h}</th>" for h in headers)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="{cls}"><colgroup>{cols}</colgroup><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>'


def img64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode()


# ---------- data ----------

def _first(root: Path, rel: str) -> Path:
    """root/rel, falling back to this repo (a temp test copy may hold only out/ and data/)."""
    p = root / rel
    return p if p.exists() else REPO / rel


def load(root: Path) -> dict:
    out, ev = root / "out", root / "data" / "eval"
    d = {
        "g": json.loads((out / "graph_summary.json").read_text(encoding="utf-8")),
        "m": json.loads((out / "metrics.json").read_text(encoding="utf-8")),
        "plan": json.loads((out / "plan.json").read_text(encoding="utf-8")),
        "top_png": img64(out / "graph_top_path.png"),
        "cold": json.loads((ev / "cold_run.json").read_text(encoding="utf-8")) if (ev / "cold_run.json").exists() else None,
    }
    with (out / "ranked.csv").open(encoding="utf-8") as f:
        ranked = list(csv.DictReader(f))
    d["kev_hits"] = sum(r.get("kev") == "True" for r in ranked)
    d["findings_csv"] = len(ranked)
    d["top"] = ranked[0] if ranked else None
    d["ranked"] = ranked
    d["scoring"] = yaml.safe_load(_first(root, "config/scoring.yaml").read_text(encoding="utf-8"))

    # feedback decisions: who made them (demo records must be labelled as such)
    fpath = root / "data" / "feedback" / "decisions.jsonl"
    decs = [json.loads(l) for l in fpath.read_text(encoding="utf-8").splitlines() if l.strip()] if fpath.exists() else []
    n_demo = sum(x.get("by") in DEMO_BY for x in decs)
    d["fb_tag"] = "" if not n_demo else ("(데모)" if n_demo == len(decs) else "(데모 포함)")

    # pre-fix (v3) figures recorded in docs/verification.md
    vp = _first(root, "docs/verification.md")
    mv = re.search(r"v3:\s*정확도\s*(\d+)%,\s*판정 정밀도\s*(\d+/\d+),\s*놓친 affected\s*(\d+)건",
                   vp.read_text(encoding="utf-8")) if vp.exists() else None
    d["v3"] = {"acc": mv.group(1), "prec": mv.group(2), "missed": mv.group(3)} if mv else None

    # human timing: source of truth is the yaml written by `sca review import`
    tpath = ev / "human_timing.yaml"
    tdata = yaml.safe_load(tpath.read_text(encoding="utf-8")) if tpath.exists() else None
    mins = [float(it["minutes"]) for it in ((tdata or {}).get("items") or []) if it.get("minutes") is not None]
    d["human"] = {"n": len(mins), "mean": statistics.mean(mins) if mins else None,
                  "median": statistics.median(mins) if mins else None}

    gt = yaml.safe_load((ev / "ground_truth.public.yaml").read_text(encoding="utf-8")) or {}
    items = gt.get("items") or []
    core = [it for it in items if it.get("set") == "core"]
    d["gt"] = {
        "n": len(items), "core_n": len(core),
        "core_reviewed": sum(bool(it.get("reviewed")) for it in core),
        "reviewed": sum(bool(it.get("reviewed")) for it in items),
        "labels": {k: sum(it.get("label") == k for it in items) for k in ("affected", "not_affected", "uncertain")},
        "changed": sum(1 for it in items if it.get("ai_label") and it.get("ai_label") != it.get("label")),
    }
    d["gt_items"] = items

    vp_ = out / "vex.json"
    d["vex"] = json.loads(vp_.read_text(encoding="utf-8")) if vp_.exists() else None
    tickets = sorted((out / "tickets").glob("T*.md")) if (out / "tickets").exists() else []
    d["ticket"] = (tickets[0].name, tickets[0].read_text(encoding="utf-8")) if tickets else None
    return d


def stale_reasons(d: dict) -> list[str]:
    """metrics.json is only rewritten by `sca run`; flag it when the review files moved on since."""
    m, x = d["m"], d["m"]["extra"]
    why = []
    if x.get("core_reviewed") != d["gt"]["core_reviewed"]:
        why.append(f"reviewed core items: metrics {x.get('core_reviewed')} vs ground_truth {d['gt']['core_reviewed']}")
    if (m.get("human_minutes_per_item") or {}).get("n", 0) != d["human"]["n"]:
        why.append(f"human timing items: metrics {m['human_minutes_per_item'].get('n')} vs yaml {d['human']['n']}")
    return why


# ---------- style ----------

CSS = """
@page { size: A4; margin: 0; }
:root { --ink:#1b1f24; --muted:#56606c; --line:#d9dee5; --accent:#c8102e; --accent2:#2b5fab;
        --ok:#1f8a4c; --warn:#c98a00; --bg:#ffffff; --soft:#f3f5f8; }
* { box-sizing: border-box; }
body { margin:0; font-family: "Apple SD Gothic Neo", "Noto Sans KR", sans-serif; color:var(--ink);
       background:var(--bg); font-size:11.5pt; line-height:1.5; word-break:keep-all; }
.page { width:210mm; height:297mm; padding:14mm 15mm 17mm; page-break-after:always; position:relative;
        overflow:hidden; }
.page:last-child { page-break-after:auto; }
h1 { font-size:23pt; line-height:1.25; margin:0 0 3mm; letter-spacing:-0.5px; }
h2 { font-size:15pt; margin:0 0 3mm; padding-bottom:1.5mm; border-bottom:2px solid var(--ink); }
h3 { font-size:12.5pt; margin:4mm 0 1.5mm; }
p { margin:0 0 2mm; }
code { font-size:10pt; }
.muted { color:var(--muted); font-size:9.5pt; }
.kicker { color:var(--accent); font-weight:700; letter-spacing:1px; font-size:9.5pt; }
.foot { position:absolute; bottom:7mm; left:15mm; right:15mm; display:flex; justify-content:space-between;
        color:var(--muted); font-size:8.5pt; border-top:1px solid var(--line); padding-top:1.5mm; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:5mm; }
.grid4 { display:grid; grid-template-columns:1fr 1fr; gap:3mm; }
.card { background:var(--soft); border-radius:3mm; padding:3.5mm 4.5mm; border-left:4px solid var(--accent); }
.big { font-size:21pt; font-weight:800; line-height:1.15; }
.big small { font-size:11pt; font-weight:600; color:var(--muted); }
.card .muted { margin-top:1mm; }
table { width:100%; border-collapse:collapse; font-size:10pt; margin:1.5mm 0 2.5mm; table-layout:fixed; }
table.kpi td, table.kpi th { padding:1mm 1.8mm; }
th, td { border-bottom:1px solid var(--line); padding:1.3mm 1.8mm; text-align:left; vertical-align:top; }
th { background:var(--soft); font-weight:700; }
td.n { text-align:right; }
.flow { display:flex; gap:2mm; align-items:stretch; margin:2mm 0; }
.flow div { flex:1; border:1.5px solid var(--ink); border-radius:2mm; padding:2mm 2.4mm; font-size:9.6pt; line-height:1.4; }
.flow b { display:block; font-size:10.5pt; }
.tag { display:inline-block; font-size:8pt; font-weight:700; padding:0.2mm 1.5mm; border-radius:1mm;
       color:#fff; margin-right:1mm; }
.code { background:var(--accent2); } .llm { background:var(--accent); } .human { background:var(--ok); }
ul { margin:0 0 2mm; padding-left:5mm; } li { margin-bottom:0.8mm; }
img.fig { width:100%; border:1px solid var(--line); border-radius:2mm; display:block; }
.note { border-left:3px solid var(--warn); padding:1.5mm 3mm; background:#fff8e6; font-size:10pt; margin:2mm 0; }
.box { border:1.5px solid var(--ok); border-radius:2.5mm; padding:3mm 4mm; margin:2mm 0 3mm; background:#f2faf5; }
.box h3 { margin-top:0; color:var(--ok); }
.box dl { display:grid; grid-template-columns:27mm 1fr; gap:1mm 3mm; margin:0 0 1.5mm; font-size:10.5pt; }
.box dt { font-weight:700; color:var(--muted); } .box dd { margin:0; }
.quote { font-style:italic; }
pre { background:var(--soft); border-radius:2mm; padding:2mm 3mm; font-size:8.8pt; line-height:1.35; margin:1mm 0 1.5mm;
      white-space:pre-wrap; word-break:break-all; }
ul.tight li { margin-bottom:0.3mm; font-size:10.5pt; }
.est { display:inline-block; font-size:8.5pt; font-weight:700; padding:0.2mm 1.6mm; border-radius:1mm;
       background:var(--warn); color:#fff; margin-left:1mm; vertical-align:1px; }
"""

OVERFLOW_JS = """<script>
window.addEventListener('load', () => {
  const bad = [...document.querySelectorAll('.page')].map((p, i) => {
    const foot = p.querySelector('.foot'); const limit = foot.offsetTop - 2;
    let max = 0; for (const c of p.children) if (c !== foot) max = Math.max(max, c.offsetTop + c.offsetHeight);
    return [i + 1, max, limit];
  }).filter(([, max, limit]) => max > limit).map(([i, max, limit]) => `${i}:${max}>${limit}`);
  document.body.setAttribute('data-overflow', bad.join(','));
});
</script>"""


def page(n, total, body):
    return (f'<section class="page">{body}<div class="foot"><span>SW 공급망 스캐닝 AI 에이전트 · LOTTE AX Challenge 2026</span>'
            f"<span>{n} / {total}</span></div></section>")


# ---------- content ----------

def build(d: dict, video: str | None) -> str:
    g, m, plan = d["g"], d["m"], d["plan"]
    per = g["per_service"]
    tot = {k: sum(r[k] for r in per) for k in per[0] if k != "service"}
    ins, pf = m["insights"], m["plan_followups"]
    auto, hold, shared, show = ins["automation"], ins["hold"], ins["shared"], ins["showcase"]
    mc = m["mode_comparison"]
    x = m["extra"]
    c = g["comparison"]
    prov = g["provenance"]
    gt = d["gt"]
    cold = d.get("cold")
    agent_s = cold["agent_seconds_mean"] if cold else m["agent_seconds_per_item"]["mean"]
    hu = d["human"]
    measured = hu["mean"] is not None

    n_find = m["warning_reduction"]["scanner_findings"]
    n_after = n_find - x["agent_only_not_affected"]
    vuln_nd = tot["vulnerable_transitive"] + tot["vulnerable_unreferenced"]
    vuln_all = tot["vulnerable_packages"]
    # one review denominator everywhere: the user reviews the core (test) set only
    ev = m["eval"]
    n_rev, core_n = ev.get("n_reviewed", 0), x["core_n"]
    rev_txt = f"테스트셋 본인 검수 {n_rev}/{core_n}건" if n_rev else "테스트셋 본인 검수 진행 중"
    label_src = f"AI 초안 2회({gt['n']}건) + {rev_txt}, 튜닝셋 {gt['n'] - core_n}건은 AI 초안만"
    lab_short = f"AI 초안, {rev_txt}"
    fbt = d["fb_tag"]
    sc = d["scoring"]
    ew, cw = sc["exposure_weight"], sc["criticality_weight"]
    ast = m["agent_seconds_per_item"]
    if cold:
        time_basis = f"LLM 캐시 없이 재실행 실측, 중앙값 {cold['agent_seconds_median']:.1f}초"
        time_short = "LLM 캐시 없이 재실행한 실측"
    else:
        time_basis = (f"LLM 시간은 첫 실행 실측값(캐시 기록) 포함, {ast.get('llm_cached', 0)}/{ast['n']}건 캐시"
                      if ast.get("llm_cached") else "이번 실행 실측")
        time_short = "LLM 시간은 첫 실행 실측값 포함" if ast.get("llm_cached") else "이번 실행 실측"

    def mode_correct(v):
        return round(v["core_decided_precision"] * v["core_decided"]) if v.get("core_decided") else 0

    # ---- page 1: cover + headline + problem
    if measured:
        speed = hu["mean"] * 60 / agent_s
        time_card = (f'<div class="big">사람 {hu["mean"]:.1f}분 <small>vs</small> {agent_s:.1f}초</div>'
                     f'<div class="muted">건당 판정 시간 · 사람 {hu["n"]}건 실측 · 에이전트 {m["agent_seconds_per_item"]["n"]}건 평균 '
                     f'(약 {speed:.0f}배). {time_short}</div>')
    else:
        time_card = (f'<div class="big">{agent_s:.1f}<small> 초/건</small></div>'
                     f'<div class="muted">에이전트 건당 판정 시간 · {m["agent_seconds_per_item"]["n"]}건 평균 · '
                     f'{time_short}</div>')
    cards = f"""
<div class="grid4">
 <div class="card"><div class="big">{vuln_nd}<small> / {vuln_all} 취약 패키지</small></div>
  <div class="muted">서비스별 합계 중 직접 선언하지 않은 부품 (전이 {tot['vulnerable_transitive']} + 미참조 {tot['vulnerable_unreferenced']}).
  직접 선언은 {tot['vulnerable_direct']}개</div></div>
 <div class="card"><div class="big">{n_find} → {n_after}<small> 건</small></div>
  <div class="muted">스캐너 경고 → 에이전트가 근거와 함께 not_affected로 거른 뒤 (사람 피드백 제외)</div></div>
 <div class="card"><div class="big">{g['shared_packages_total']}<small> 공유 부품</small></div>
  <div class="muted">2개 이상 서비스가 함께 쓰는 패키지 · 한 번의 판단·조치를 여러 서비스에 적용</div></div>
 <div class="card">{time_card}</div>
</div>"""
    svc_rows = [[esc(r["service"]), f'<span class="n">{r["packages"]}</span>', r["direct"],
                 r["transitive"] + r["unreferenced"], r["vulnerable_packages"],
                 r["vulnerable_transitive"] + r["vulnerable_unreferenced"], r["findings"]] for r in per]
    svc_rows.append([f"<b>서비스별 합</b><br><span class=\"muted\">고유 {g['package_versions']}</span>", f"<b>{tot['packages']}</b>", f"<b>{tot['direct']}</b>",
                     f"<b>{tot['transitive'] + tot['unreferenced']}</b>", f"<b>{vuln_all}</b>",
                     f"<b>{vuln_nd}</b>", f"<b>{tot['findings']}</b>"])
    video_line = f'<p class="muted">데모 영상: {esc(video)}</p>' if video else ""
    gl = gt["labels"]
    p1 = f"""
<div class="kicker">LOTTE AX CHALLENGE 2026 · 롯데이노베이트 [인프라]</div>
<h1>SW 공급망 스캐닝 AI 에이전트<br><span style="font-weight:500;font-size:14pt">찾기 → 거르기 → 고치기 → 배우기</span></h1>
<p>SBOM과 취약점 스캔 결과를 팀–서비스–부품 그래프에 연결합니다. LLM은 공개 권고문을 조건으로 바꾸고,
코드가 그 조건이 서비스에 있는지 확인해 판정합니다. 업그레이드 조치안과 티켓을 만들고, 사람의 승인·기각으로 다음 판정을 고칩니다.</p>
{cards}
<h2 style="margin-top:5mm">1. 문제: 보이지 않는 부품, 걸러지지 않는 경고</h2>
{table(["서비스", "패키지", "직접", "전이·미참조", "취약 패키지", "그중 미선언", "경고"], svc_rows,
       widths=["26%", "12%", "10%", "14%", "13%", "13%", "12%"])}
<ul>
<li>서비스별 취약 패키지 {vuln_all}개 중 {vuln_nd}개는 서비스가 직접 선언하지 않은 부품입니다. 선언 파일만 보면 놓칩니다.
<span class="muted">미참조 = 설치돼 있으나 선언 의존성 트리에서 경로가 없는 부품.</span></li>
<li>CVSS 상위 10건과 종합 위험(EPSS·노출·업무 중요도) 상위 10건은 {c['overlap']}건만 겹쳤습니다.
종합 상위의 평균 EPSS가 {c['score']['mean_epss'] / max(c['severity']['mean_epss'], 1e-9):.1f}배 높습니다.</li>
<li>정답셋 {gt['n']}건({esc(lab_short)}) 중 affected는 {gl['affected']}건뿐입니다. 이를 찾으려면 {gt['n']}건 모두를 사람이 권고문과 코드로 확인해야 합니다.</li>
</ul>
<h3>그래서 순위는 코드로 다시 매김</h3>
<p><b>risk = 100 × 가능성 × 영향</b>. 가능성은 KEV 등재면 {sc['likelihood']['kev']:g}, 아니면 EPSS(없으면 실측 중앙값과 "정보 부족" 표시).
영향은 CVSS/10 × 노출(인터넷 {ew['internet']:g}, 내부 {ew['internal']:g}) × 업무 중요도({' / '.join(f"{cw[k]:g}" for k in sorted(cw))})
× 개발 전용 {sc['dev_weight']:g}입니다(가중치는 가정).</p>
<p class="muted">범위: 본인 레포 5개를 가상의 계열사 서비스로 둔 파일럿. 가중치는 가정(<code>config/scoring.yaml</code>).
정답셋 라벨: {esc(label_src)}. 재현: <code>python -m sca run</code>.
실행 {esc(prov['run_at'])} · syft {esc(prov['tools']['syft'])} · grype {esc(prov['tools']['grype'])} · KEV {esc(prov['kev'].get('catalogVersion'))} · LLM {esc(m.get('llm'))}</p>
{video_line}
"""

    # ---- page 2: architecture + top path figure
    top_caption = ""
    if d["top"]:
        t = d["top"]
        hops = [h.strip() for h in t["path"].split(">")]
        dep = {"direct": "직접 의존", "transitive": "전이 의존", "unreferenced": "미참조 부품"}.get(t["dependency"], t["dependency"])
        via = f" ({esc(hops[0])}가 선언한 <code>{esc(hops[1])}</code> 경유)" if len(hops) > 2 else ""
        scale = ("100점 만점. KEV 등재 0건이라 가능성에 EPSS 값(1위 "
                 f"{float(t['epss']):.3f})이 그대로 들어가 절대값이 작고, 순위 비교용입니다"
                 if d["kev_hits"] == 0 else "100점 만점, 순위 비교용")
        top_caption = (f"1위: <code>{esc(t['ecosystem'])}:{esc(t['package'])}@{esc(t['version'])}</code> · {esc(t['vuln_id'])} · "
                       f"점수 {esc(t['score'])}({scale}), {dep}{via}. ")
    p2 = f"""
<h2>2. 구조: 계산은 코드, 해석은 LLM, 결정은 사람</h2>
<div class="flow">
 <div><b>scan</b><span class="tag code">CODE</span>Syft SBOM (설치 상태) · Grype</div>
 <div><b>ingest</b><span class="tag code">CODE</span>공통 스키마 · 직접/전이/미참조 구분</div>
 <div><b>enrich</b><span class="tag code">CODE</span>OSV · EPSS · KEV (공개 ID만)</div>
 <div><b>graph·score</b><span class="tag code">CODE</span>팀–서비스–패키지–취약점, 위험 점수</div>
</div>
<div class="flow">
 <div><b>judge</b><span class="tag llm">LLM</span>권고문 → 조건 JSON<br><span class="tag code">CODE</span>버전 범위·코드 검색·판정 규칙</div>
 <div><b>plan</b><span class="tag code">CODE</span>가중 집합 덮개 Top-3 · 호환성 검사</div>
 <div><b>report</b><span class="tag llm">LLM</span>티켓 서술 (공개 정보만)<br><span class="tag code">CODE</span>CSV·리포트·VEX</div>
 <div><b>feedback·eval</b><span class="tag human">HUMAN</span>승인·기각 → 다음 판정, 재스캔, 정답셋</div>
</div>
<h3>최고 위험 경로 (이번 실행 1위)</h3>
<img class="fig" src="data:image/png;base64,{d['top_png']}">
<p class="muted" style="margin-top:1.5mm">{top_caption}경로·담당팀·점수 근거가 순위 CSV와 티켓에 같이 실립니다.</p>
<h3>내부 정보 보호와 교체 가능성</h3>
<ul>
<li>LLM 입력은 공개 권고문뿐입니다. 노출·중요도·담당팀과 소스 코드는 코드 안에서만 결합합니다.</li>
<li>OpenAI SDK + base_url 구조입니다. 로컬 모델과 OpenAI는 환경변수만 바꿔 씁니다. 사내 모델도 OpenAI 호환 API라면 같은 방식으로 바꿀 수 있습니다(아이멤버 연동은 미검증).</li>
<li>입력 형식이 바뀌면 ingest 파서만 바꿉니다. 나머지 단계는 공통 스키마만 봅니다.</li>
</ul>
<h3>운영 시점과 산출물</h3>
<p>기본은 주기 스캔 후 담당팀별 티켓 초안입니다. 산출물은 순위 CSV(점수·판정·경로·수정 버전), Markdown 리포트(KPI·모드 비교·검토 대기열),
티켓 초안(근거 file:line, 호환성 위험, 검증 명령), OpenVEX, KPI JSON입니다.</p>
"""

    # ---- page 3: judge + showcase + modes
    ev_list = ", ".join(f"<code>{esc(f)}</code>" for f in show["evidence_fileline"])
    more = show["import_hits_total"] - len(show["evidence_fileline"])
    ev_more = f" 외 {more}곳" if more > 0 else ""
    missing = ", ".join(f"<code>{esc(s)}</code>" for s in show["missing_symbols"])
    cond = re.sub(r"\s*\(symbols:.*\)$", "", show["condition"])
    mt = re.match(r"\[(\w+)\]\s*(.*)", cond)
    cond_html = (f"{COND_TAG.get(mt.group(1), esc(mt.group(1)))}: <span class=\"quote\">{esc(mt.group(2))}</span> "
                 f'<span class="muted">(LLM 추출, 영문)</span>' if mt else esc(cond))
    expl = re.sub(r"했다(\([^)]*\))?\.$", r"했습니다\1.", show["explanation"].strip())
    sgt = next((it for it in d["gt_items"] if it.get("service") == show["service"]
                and it.get("package") == show["package"] and it.get("vuln_id") == show["vuln_id"]), None)
    sgt_src = "본인 검수 완료" if sgt and sgt.get("reviewed") else "AI 초안, 본인 검수 진행 중"
    mode_rows = []
    for k in ("proactive", "conservative"):
        v = mc.get(k)
        if not v:
            continue
        name = MODE_NAME[k] + (" (기본)" if k == m.get("judge_mode") else "")
        mode_rows.append([name, f'{round(v["reduction_agent_only"] * n_find)}/{n_find}건 ({pct(v["reduction_agent_only"])})',
                          f'{round(v["human_review"] * n_find)}/{n_find}건 ({pct(v["human_review"])})',
                          f'{mode_correct(v)}/{v["core_decided"]}건', f'{v["core_false_not_affected"]}건'])
    rc = m["rule_counts"]["rule"]
    g04 = next((it for it in d["gt_items"] if it.get("id") == "G04"), None)
    v3 = d["v3"]
    v3_txt = ""
    if v3:
        miss = f"{esc(g04['id'])} <code>{esc(g04['package'])}</code>" if g04 else "affected"
        now = None
        if g04:
            pk, ver = g04["package"].rsplit("@", 1)
            now = next((r["verdict"] for r in d["ranked"] if r["service"] == g04["service"] and r["vuln_id"] == g04["vuln_id"]
                        and f"{r['ecosystem']}:{r['package']}" == pk and r["version"] == ver), None)
        now_ko = {"uncertain": "보류로 사람에게 갑니다", "affected": "affected로 잡힙니다",
                  "not_affected": "여전히 not_affected입니다"}.get(now)
        v3_ok, v3_dec = map(int, v3["prec"].split("/"))
        v3_txt = (f"수정 전(v3) 테스트셋: 정확도 {v3['acc']}%, 결정한 건 중 정답 {v3['prec']}건, 놓친 affected {v3['missed']}건"
                  f"({miss})" + (f". 이 건은 수정 후 {now_ko}." if now_ko else ".")
                  + f" 수정 후 정확도는 {pct(ev['accuracy'], 0)}로 낮아졌지만, 틀린 결정이 보류로 바뀐 결과입니다"
                  f"(오판 {v3_dec - v3_ok}→{x['core_decided'] - x['core_decided_correct']}건).")
    na_rules = {"api_not_referenced": "조건 API 미참조", "platform_excluded": "플랫폼 제외",
                "feedback_suppressed": f"사람 결정{fbt} 반영"}
    na_txt = ", ".join(f"{v} {rc[k]}건" for k, v in na_rules.items() if rc.get(k))
    p3 = f"""
<h2>3. 판정: 근거로 걸러내고, 애매하면 사람에게</h2>
<p>LLM은 권고문에서 "어떤 API를, 어떤 입력으로, 어떤 플랫폼에서 써야 터지는가"만 뽑습니다. 권고문에 없는 함수명은 버리고, 인용은 원문과 일치하는지 검사합니다.
코드는 <b>그 패키지를 import하는 파일</b>에서만 조건 API를 찾습니다. 서비스 코드와, 그 패키지를 쓰는 의존 패키지의 설치 소스까지 봅니다.</p>
<p>not_affected 근거 규칙: {na_txt}. 조건 API가 코드에 있거나 조건 없이 버전만 맞으면 affected, 결정할 근거가 없으면 보류(사람 검토)입니다.</p>
<div class="box">
<h3>CVSS 높지만 근거와 함께 not_affected로 걸러진 실제 사례</h3>
<dl>
<dt>대상</dt><dd>{esc(show['service'])} · <code>{esc(show['package'])}</code> · {esc(show['vuln_id'])} · <b>CVSS {show['cvss']}</b></dd>
<dt>권고문 인용</dt><dd><span class="quote">"{esc(show['advisory_quote'])}"</span> ({esc(show['advisory_id'])})</dd>
<dt>추출한 조건</dt><dd>{cond_html}</dd>
<dt>코드 확인</dt><dd>import {show['import_hits_total']}곳: {ev_list}{ev_more}. 조건 심볼 {missing} 참조 0건</dd>
<dt>판정</dt><dd>{esc(expl)} 정답셋 라벨({sgt_src})도 {esc(show['gt_label'])}입니다.</dd>
</dl>
</div>
<h3>운영 모드 (같은 입력)</h3>
{table(["모드", "경고 감소", "사람 검토", f"결정한 건 중 정답<br>(테스트셋 {x['core_n']}건)",
        "놓친 위험 (테스트셋)"], mode_rows, widths=["18%", "21%", "21%", "20%", "20%"])}
<ul>
<li><b>적극 모드</b>: 필수 API나 입력 조건 하나만 코드에 없어도 걸러냅니다. 기본값입니다.</li>
<li><b>보수 모드</b>: 검색이 완전하고 어떤 조건 API도 없을 때만 not_affected를 냅니다. 놓침 비용이 큰 서비스용입니다.</li>
</ul>
<div class="note">개발 중 교차 검증(구현과 분리된 AI 리뷰 에이전트)에서 오판 경로 6가지(import 이름 불일치, 번들 미검색 등)를 고쳤습니다.
{v3_txt}</div>
<h3>개선 루프: 사람의 판단이 다음 판정이 됨</h3>
<div class="grid2"><ul>
<li><b>기록</b>: 승인·기각과 사유를 저장</li>
<li><b>억제</b>: 같은 패키지·취약점은 다음 실행에서 자동 정리, <code>--scope all_services</code>로 전 서비스 적용</li>
<li><b>예시</b>: 사유를 few-shot으로 사용(사내·로컬 모델만)</li>
</ul><ul>
<li><b>검증</b>: 조치 후 재스캔으로 해당 경고가 사라졌는지 확인(실행별 스냅샷)</li>
<li><b>공유</b>: OpenVEX v0.2.0으로 판정과 근거 내보내기</li>
<li><b>정답셋</b>: 검수 시트에 판정·소요 시간을 적으면 정답셋과 지표가 다시 계산됨</li>
</ul></div>
"""

    # ---- page 4: results KPI + top-3
    af, afw = auto["misjudged"], auto["misjudged_with_feedback"]
    fb = shared["feedback"]
    time_row = (["처리 시간", f"사람 {hu['mean']:.1f}분 vs {agent_s:.1f}초",
                 f"사람 {hu['n']}건 실측(검수 시트), 에이전트 {ast['n']}건 평균. {time_basis}"]
                if measured else
                ["처리 시간 (에이전트)", f"{agent_s:.1f}초/건", f"{ast['n']}건 평균, {esc(m.get('llm', ''))}. {time_basis}"])
    # extended (tuning) set: decided = predicted affected/not_affected
    ee = m.get("eval_extended") or {}
    mx = (ee.get("confusion") or {}).get("matrix") or {}
    ext_row = None
    if mx:
        dec_cls = ("affected", "not_affected")
        e_dec = sum(mx[l][v] for l in mx for v in dec_cls if v in mx[l])
        e_ok = sum(mx[v][v] for v in dec_cls if v in mx)
        wrong = [w for w in ee.get("mismatches", []) if w["verdict"] in dec_cls]
        why = {}
        for w in wrong:
            why.setdefault((w["rule"], w["package"].split("@")[0], w["vuln_id"]), set()).add(w["service"])
        why_txt = "; ".join(f"{RULE_KO.get(r, r)}(<code>{esc(pk)}</code>, {len(sv)}개 서비스)"
                            for (r, pk, v), sv in why.items())
        c_dec, c_ok = x["core_decided"], x["core_decided_correct"]
        ext_row = ["오판 (튜닝셋)", f"{e_dec - e_ok}/{e_dec}건",
                   f"튜닝셋 {ee.get('n')}건 중 결정 {e_dec}건" + (f". {why_txt}" if why_txt else "")
                   + f". 전체 {x['core_n'] + ee.get('n', 0)}건 기준 정답 {c_ok + e_ok}/{c_dec + e_dec}건"]
    abst_ok = ev["correct"] - x["core_decided_correct"]
    v3 = d["v3"]
    acc_row = ["정답 일치 (테스트셋)", frac(ev["correct"], ev["n"], 0),
               f"결정 {x['core_decided']}건 중 정답 {x['core_decided_correct']}건 + 보류 {x['core_abstain']}건"
               + (f"(그중 {abst_ok}건은 정답도 uncertain)" if abst_ok else "")
               + (f". 수정 전 v3는 {v3['acc']}%였지만 affected {v3['missed']}건을 놓침" if v3 else "")]
    kpi = [
        acc_row,
        ["자동 처리율", frac(auto["auto_decided"], auto["total"]), "에이전트가 affected·not_affected로 결정한 비율"],
        [f"자동 처리율 ({fbt.strip('()') + ' ' if fbt else ''}결정 반영)", frac(auto["auto_decided_with_feedback"], auto["total"]),
         f"공유 피드백{fbt}으로 정리된 건 포함"],
        ["오판 (테스트셋)", f"{af['text']}건", f"결정한 {af['decided']}건 중 정답과 다른 건 · 피드백 반영 후 {afw['text']}건"],
        *([ext_row] if ext_row else []),
        ["보류율 (사람 검토)", frac(auto["uncertain"], auto["total"]), "근거와 함께 검토 대기열로"],
        ["경고 수", f"{n_find} → {n_after}건", f"에이전트 단독 not_affected {x['agent_only_not_affected']}건 제외"],
        ["공유 판정", f"판정 {shared['judgments_saved']}회로 경고 {shared['shared_findings']}건",
         "여러 서비스가 같은 패키지@버전×취약점을 공유, 판정 결과 일치"],
        [f"그룹 공유 결정{fbt}", f"{fb['decisions_all_services']}건 → {len(fb['services'])}개 서비스 {fb['rows_resolved']}건",
         f"전 서비스 범위 결정이 다른 서비스 {fb['rows_other_services']}건까지 해소"
         + (" · 시연용 기록" if fbt == "(데모)" else "")],
        ["Top-3 위험 커버율", pct(m["top3_risk_coverage"]["coverage"]), "not_affected 제외 잔여 위험 대비"],
        time_row,
        *([["재현성 (캐시 없이)", f"{cold['verdict_same']}/{cold['verdict_compared']}건 일치 ({cold['verdict_same'] / cold['verdict_compared'] * 100:.1f}%)",
            "차이는 LLM 조건 추출 차이. 운영은 조건 캐시로 재현"]] if cold else []),
    ]
    alts = {a["package"]: a for a in pf["alternatives"]}
    shr = {s["package"]: s for s in pf["shared"]["top3"]}
    acts = []
    for i, a in enumerate(plan["actions"]):
        alt = alts.get(a["package"], {})
        alt_txt = (f"<b>{esc(alt['target'])}</b>" if alt.get("target") else
                   f'<span class="muted">없음: {esc(alt.get("reason", "-"))}</span>')
        sh = shr.get(a["package"], {})
        sh_txt = ("<b>예</b> " if sh.get("shared") else "아니오. ") + f'<span class="muted">{esc(sh.get("reason", ""))}</span>'
        fmaj, tmaj = a["from_versions"][0].split(".")[0], a["target_version"].split(".")[0]
        note = esc(a.get("note", "").split(": ", 1)[-1])
        compat = " ".join(t for t in (f"메이저 변경({fmaj}→{tmaj})." if fmaj != tmaj else "", note) if t)
        if not compat and a["major_bump"]:
            compat = "호환성 위험 표시됨"
        acts.append([i + 1, f"<code>{esc(a['package'])}</code><br>{esc(', '.join(a['from_versions']))} → <b>{esc(a['target_version'])}</b>",
                     pct(a["risk_covered"] / plan["total_risk"]), compat or "-", alt_txt, sh_txt])
    bs = (pf["shared"].get("best_shared") or [None])[0]
    best_line = ""
    if bs:
        best_line = (f"<p><b>여러 서비스에 한 번에 효과가 있는 조치</b>: <code>{esc(bs['ecosystem'])}:{esc(bs['package'])}</code> → "
                     f"{esc(bs['target_version'])} 하나로 {', '.join(map(esc, bs['services_cleared']))} "
                     f"{len(bs['services_cleared'])}개 서비스의 경고 {bs['findings']}건이 해소됩니다(전체 잔여 위험의 {pct(bs['risk_share'])}, "
                     f"계획 순위 {bs['rank']}위{', 메이저 변경 없음' if not bs['major_bump'] else ''}).</p>")
    p4 = f"""
<h2>4. 결과 (파일럿 측정값)</h2>
{table(["지표", "값", "근거"], kpi, widths=["24%", "21%", "55%"], cls="kpi")}
<p>{esc(auto['baseline']['text'])}. 이 에이전트는 확신할 때만 결정하고 나머지는 보류합니다.</p>
<h3>조치안: 업그레이드 Top-3 (가중 집합 덮개)</h3>
{table(["#", "조치", "위험 감소", "호환성 위험", "호환성 위험 없는 대안", "다서비스 공유"], acts,
       widths=["4%", "16%", "9%", "23%", "28%", "20%"])}
{best_line}
"""

    # ---- page 5: hold breakdown + loop + outputs
    est = hold["estimate"]
    cg = next((c_ for c_ in hold["categories"] if "콜그래프" in c_["category"]), hold["categories"][0])
    cg_name = HOLD_CAT.get(cg["category"], cg["category"])
    ub, gr = est["upper_bound"], est["grounded"]
    hold_rows = [[esc(HOLD_CAT.get(cat["category"], cat["category"])), f'{cat["count"]}건', pct(cat["share"]),
                  ", ".join(f"<code>{esc(k)}</code> {v}" for k, v in cat["rules"].items())] for cat in hold["categories"]]
    p5 = f"""
<h2>5. 보류의 원인과 줄이는 방법</h2>
<p>보류 {hold['uncertain']}/{hold['total']}건({pct(hold['review_rate'])})을 원인별로 나눴습니다. 비율은 전체 경고 대비입니다.</p>
{table(["원인", "건수", "전체 대비", "판정 규칙"], hold_rows, widths=["27%", "11%", "12%", "50%"])}
<div class="grid2">
 <div class="card" style="border-left-color:var(--warn)"><div class="big">{pct(gr['review_rate'])}<small> 검토율</small><span class="est">추정</span></div>
  <div class="muted">콜그래프 연동 시 근거 추정 (현재 {pct(hold['review_rate'])})</div></div>
 <div class="card" style="border-left-color:var(--warn)"><div class="big">{pct(ub['review_rate'])}<small> 검토율</small><span class="est">추정</span></div>
  <div class="muted">최선의 경우 검토율 하한 (해당 범주 전부 결정 가정)</div></div>
</div>
<p class="muted" style="margin-top:1.5mm">가정: 콜그래프는 위 {cg['count']}건만 결정. 근거 추정은 정답셋 결정 가능 비율 {gr['gt_decidable']}/{gr['gt_items']} 적용({esc(lab_short)}).</p>
"""

    # ---- page 6: lotte, finals, roadmap, limits
    rule_ko = {"reachable_via_dependency": "의존 패키지 경유", "transitive_needs_callgraph": "전이",
               "code_unavailable": "검색할 코드 없음"}
    rule_split = ", ".join(f"{rule_ko.get(k, k)} {v}" for k, v in cg["rules"].items())
    p5 += f"""
<h2 style="margin-top:6mm">6. 롯데 맥락과 본선 계획</h2>
<h3>그룹 SI에서의 가치</h3>
<ul>
<li>계열사마다 다른 스택을 하나의 서비스–부품 그래프로 봅니다. 공유 부품 {g['shared_packages_total']}개처럼 겹치는 부품은 판단과 조치를 한 번에 냅니다.</li>
<li>내부 자산 정보(노출·중요도·담당팀·소스 코드)는 처음부터 LLM에 보내지 않습니다. LLM을 사내 모델(예: 아이멤버, 연동 미검증)로 바꾸면 공개 권고문 처리도 사내에 남습니다.</li>
<li>판정 근거를 OpenVEX로 표준화해, 그룹에서 검증한 뒤 고객사·협력사와 공유합니다.</li>
<li>EU CRA 보고 의무(2026.09 적용, 전면 2027.12)처럼 SBOM과 대응 이력을 요구하는 규제에 재스캔·VEX 기록으로 대응합니다.</li>
</ul>
"""
    finals = [
        ["1일차 오전", "현장 데이터에 맞춰 ingest 파서 교체, 노출·중요도·담당팀 설정 파일 입력", "공통 스키마 로드 성공"],
        ["1일차 오후", "환경변수로 OpenAI 모델 연결 후 전체 실행, 표본 정답 라벨링", "8단계 실행 완료, 표본 라벨"],
        ["2일차 오전", "표본으로 정확도·보류율 측정, 판정 규칙 조정", "조정 전후 측정값 기록"],
        ["2일차 오후", "순위·조치안·티켓 시연", "담당팀별 티켓과 리포트 생성"],
    ]
    p5 += f"""
<h3>본선(1박 2일) 적용 계획</h3>
{table(["시간", "할 일", "완료 기준"], finals, widths=["16%", "56%", "28%"])}
<h3>로드맵</h3>
<ul>
<li>콜그래프 연동: 전이 의존 보류 건 해소</li>
<li>PR 게이트: 새 위험만 코멘트·차단</li>
<li>샌드박스 테스트 후 자동 PR, 펌웨어·HBOM</li>
</ul>
"""
    # sample outputs: code-filled ticket header + the showcase item's VEX statement
    tk_html = ""
    if d["ticket"]:
        name, txt = d["ticket"]
        title = next((l[2:] for l in txt.splitlines() if l.startswith("# ")), name)
        heads = []
        for l in txt.splitlines():
            if l.startswith("## "):
                break
            if l.startswith("- "):
                heads.append(re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", esc(l[2:])))
        tk_html = (f"<h3>티켓 초안 예시 <span class=\"muted\">(out/tickets/{esc(name)} 머리말)</span></h3>"
                   f"<p><b>{esc(title)}</b></p><ul class=\"tight\">" + "".join(f"<li>{h}</li>" for h in heads) + "</ul>"
                   "<p class=\"muted\">이어서 요약·영향·작업 단계(LLM 서술), 해소 취약점 표, 근거(권고문 인용·file:line), 검증 명령, 승인·기각 명령이 붙습니다.</p>")
    vx_html = ""
    if d["vex"]:
        pkg, ver = show["package"].split(":", 1)[-1].rsplit("@", 1)
        st = next((s_ for s_ in d["vex"]["statements"] if s_["vulnerability"]["name"] == show["vuln_id"]
                   and any(p_["@id"].endswith(f"/{pkg}@{ver}") for p_ in s_["products"])), None)
        if st:
            cnt = {}
            for s_ in d["vex"]["statements"]:
                cnt[s_["status"]] = cnt.get(s_["status"], 0) + 1
            cnt_txt = ", ".join(f"{k} {v}" for k, v in sorted(cnt.items(), key=lambda kv: -kv[1]))
            vx_html = (f"<h3>OpenVEX 예시 <span class=\"muted\">(out/vex.json, 3쪽 사례)</span></h3>"
                       f"<pre>{esc(chr(10).join(json.dumps({k: v}, ensure_ascii=False)[1:-1] + ',' for k, v in st.items()).rstrip(','))}</pre>"
                       f"<p class=\"muted\">전체 {len(d['vex']['statements'])}건: {esc(cnt_txt)}.</p>")
    video_html = f"<p><b>데모 영상</b>: {esc(video)}</p>" if video else ""
    rounds = [
        ["1차", "scan·ingest·graph·score", "174행 점수·순위 독립 재계산 일치, 분류·중복 결함 4건 수정"],
        ["2차", "judge·plan·feedback·report·eval", "모듈별 리뷰 에이전트가 버그 13건 수정, 주요 4건 회귀 테스트"],
        ["3차", "KPI·판정 안전성·조치·유출·문구", "not_affected 오판 경로 6가지 수정(규칙 v4), 런타임 호환성 검사 추가"],
        ["4차", "제출물 전체(심사·사실·공개·코드)", "비평 71건(high 13) 반영, 재검증 지적 6건 수정, 캐시 없이 재실행"],
    ]
    cold_html = (f'<p class="muted">재현성: LLM 캐시를 지우고 전체를 다시 돌리면 판정 {cold["verdict_same"]}/{cold["verdict_compared"]}건이 같았습니다.</p>'
                 if cold else "")
    p6 = f"""
<h2>7. 산출물 예시와 한계</h2>
{tk_html}
{vx_html}
<h3>개발·검증 방식</h3>
<p>구현은 Claude Code로 했고, 구현과 분리된 검증 에이전트가 네 차례 원시 데이터에서 숫자를 다시 계산하고 코드·제출물을 감사했습니다(docs/verification.md). 검증 에이전트도 AI이므로 독립된 제3자 검증은 아닙니다.</p>
{table(["회차", "대상", "찾고 고친 것"], rounds, widths=["10%", "34%", "56%"])}
{cold_html}
<h3>한계</h3>
<ul>
<li>파일럿은 본인 레포 5개입니다. KEV 등재 경고가 {d['kev_hits']}건이라 KEV 가중의 효과는 이번 데이터에서 드러나지 않았습니다.</li>
<li>정답셋 {gt['n']}건 중 affected가 {gl['affected']}건으로 클래스 균형이 맞지 않습니다. 라벨은 {esc(label_src)}입니다.</li>
<li>보류율이 {pct(auto['hold_rate'])}로 높습니다. 그중 {cg['count']}건이 {esc(cg_name)} 범주({rule_split})라 콜그래프 연동이 다음 과제입니다.</li>
<li>테스트셋에서 놓친 위험은 {mc.get('proactive', {}).get('core_false_not_affected', 0)}건이지만 표본이 작아 놓칠 가능성을 배제하지 못합니다. 그래서 보수 모드를 실행 옵션으로 둡니다.</li>
</ul>
{video_html}
"""
    bodies = [p1, p2, p3, p4, p5, p6]
    pages = "".join(page(i + 1, len(bodies), b) for i, b in enumerate(bodies))
    return (f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>SW 공급망 스캐닝 에이전트</title>'
            f"<style>{CSS}</style></head><body>{pages}{OVERFLOW_JS}</body></html>")


def check_overflow(html_path: Path) -> str:
    r = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--window-size=1000,1400",
                        "--virtual-time-budget=3000", "--dump-dom", html_path.as_uri()],
                       capture_output=True, text=True)
    mm = re.search(r'data-overflow="([^"]*)"', r.stdout)
    return mm.group(1) if mm else "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--video", default=None, help="demo video URL; omitted → no video line")
    ap.add_argument("--root", type=Path, default=REPO)
    ap.add_argument("--outdir", type=Path, default=HERE)
    ap.add_argument("--allow-stale", action="store_true", help="build even if metrics.json predates the review files")
    a = ap.parse_args()
    d = load(a.root)
    why = stale_reasons(d)
    if why:
        msg = ("out/metrics.json is stale (" + "; ".join(why) + "). "
               "Run `.venv/bin/python -m sca run --skip-scan --offline` first.")
        if not a.allow_stale:
            raise SystemExit("ERROR: " + msg)
        print("WARNING:", msg)
    a.outdir.mkdir(parents=True, exist_ok=True)
    html_path = a.outdir / "portfolio.html"
    html_path.write_text(build(d, a.video), encoding="utf-8")
    pdf = a.outdir / "portfolio.pdf"
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={pdf}", html_path.as_uri()], check=True, capture_output=True)
    ov = check_overflow(html_path)
    pages = ""
    if shutil.which("pdfinfo"):
        info = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout
        pages = re.search(r"Pages:\s+(\d+)", info).group(1)
    print(pdf, f"pages={pages}", f"overflow={ov or 'none'}")


if __name__ == "__main__":
    main()
