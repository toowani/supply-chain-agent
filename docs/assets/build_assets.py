"""Render README figures: static PNGs and GIFs from HTML frames (headless Chrome + ffmpeg).

Usage: .venv/bin/python docs/assets/build_assets.py
Numbers come from out/metrics.json and the committed showcase case; the demo GIF replays
the stage lines of a real `sca run --skip-scan --offline` (2026-11-02, 140 s) with time compressed.
"""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Noto Sans KR',sans-serif;color:#1f2328;background:transparent}
.mono{font-family:Menlo,monospace}
.card{background:#fff;border:1px solid #d0d7de;border-radius:18px;padding:28px 32px}
.code{background:#e3f2fd;border-color:#1e88e5;color:#0d47a1}
.llm{background:#f3e5f5;border-color:#8e24aa;color:#4a148c}
.human{background:#fff3e0;border-color:#fb8c00;color:#e65100}
.io{background:#f6f8fa;border-color:#afb8c1;color:#1f2328}
.ok{background:#e8f5e9;border-color:#43a047;color:#1b5e20}
.bad{background:#ffebee;border-color:#e53935;color:#b71c1c}
"""


def shot(html: str, out: Path, w: int, h: int, scale: int = 2, transparent: bool = True):
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "f.html"
        f.write_text(f"<!doctype html><meta charset=utf-8><style>{CSS}</style>{html}", encoding="utf-8")
        args = [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--window-size={w},{h}",
                f"--force-device-scale-factor={scale}", f"--screenshot={out}", f.as_uri()]
        if transparent:
            args.insert(3, "--default-background-color=00000000")
        subprocess.run(args, check=True, capture_output=True)


def gif(frames: list[tuple[str, float]], out: Path, w: int, h: int):
    """frames: (html, seconds). Rendered at 1x on an opaque background, palette-optimised."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        lst = []
        for i, (html, sec) in enumerate(frames):
            png = td / f"{i:03d}.png"
            shot(html, png, w, h, scale=1, transparent=False)
            lst.append(f"file '{png}'\nduration {sec}")
        lst.append(f"file '{td / f'{len(frames) - 1:03d}.png'}'")
        (td / "list.txt").write_text("\n".join(lst))
        vf = "split[a][b];[a]palettegen=max_colors=128:stats_mode=full[p];[b][p]paletteuse=dither=none"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", td / "list.txt",
                        "-vf", vf, "-loop", "0", out], check=True)


# ── static: architecture ──────────────────────────────────────────────────────────
def box(cls, title, sub=""):
    s = f"<div style='font-size:13px;opacity:.85;margin-top:3px'>{sub}</div>" if sub else ""
    return (f"<div class='card {cls}' style='padding:12px 14px;border-radius:12px;border-width:1.5px;"
            f"text-align:center;flex:1'><div style='font-weight:700;font-size:16px'>{title}</div>{s}</div>")


def lane(label, items, note="", arrows=True):
    arrow = "<div style='align-self:center;color:#8c959f;font-size:20px'>→</div>" if arrows else ""
    return (f"<div style='display:flex;gap:14px;align-items:stretch'>"
            f"<div style='width:120px;align-self:center;font-weight:700;color:#57606a;font-size:14px'>{label}"
            f"<div style='font-weight:400;font-size:12px'>{note}</div></div>"
            f"<div style='flex:1;display:flex;gap:10px'>{arrow.join(items)}</div></div>")


def architecture():
    down = "<div style='margin-left:134px;color:#8c959f;font-size:18px;line-height:1'>↓</div>"
    rows = [
        lane("입력", [box("io", "Syft SBOM", "실제 설치 상태"), box("io", "Grype / Trivy", "스캔 결과"),
                      box("io", "assets.yaml", "노출·중요도·담당팀")], arrows=False),
        lane("분석", [box("code", "① ingest", "공통 스키마"), box("code", "② enrich", "OSV·EPSS·KEV"),
                      box("code", "③ 그래프", "서비스·패키지·CVE"), box("code", "④ 위험 점수", "KEV·EPSS·노출")],
             "영향도·우선순위"),
        lane("판정·조치", [box("llm", "⑤ 판정", "조건 추출 + 코드 확인"), box("code", "⑥ 조치 계획", "가중 집합 덮개"),
                          box("llm", "⑦ 리포트·티켓", "근거·호환성"), box("human", "⑧ 사람", "승인·기각")]),
        lane("산출물", [box("io", "순위 CSV · 리포트"), box("io", "담당팀별 티켓"), box("io", "OpenVEX · KPI")], arrows=False),
    ]
    loop = ("<div style='margin:-2px 0 2px 134px;font-size:13px;color:#e65100'>↺ ⑧의 승인·기각 사유는 다음 실행의 ⑤ 판정에 반영 "
            "(같은 패키지·취약점 경고 자동 정리, 재스캔으로 조치 확인)</div>")
    rows.insert(3, loop)
    legend = ("<div style='display:flex;gap:18px;font-size:13px;color:#57606a;margin-top:12px;margin-left:134px'>"
              "<span><b style='color:#1e88e5'>■</b> 결정적 코드</span><span><b style='color:#8e24aa'>■</b> LLM 일부 담당</span>"
              "<span><b style='color:#fb8c00'>■</b> 사람</span></div>")
    html = (f"<div class='card' style='width:1000px'>"
            f"<div style='font-size:22px;font-weight:800;margin-bottom:18px'>계산은 코드, 해석은 LLM, 결정은 사람</div>"
            f"<div style='display:flex;flex-direction:column;gap:6px'>{down.join(rows[:3])}{rows[3]}{down}{rows[4]}</div>{legend}</div>")
    shot(html, HERE / "architecture.png", 1000, 520)


# ── static: where the 174 warnings went ──────────────────────────────────────────
def warnings():
    m = json.loads((REPO / "out/metrics.json").read_text(encoding="utf-8"))
    vc = m["verdict_counts"]
    demo = m["warning_reduction"]["demo_feedback_rows"]
    agent_na = vc["not_affected"] - demo
    total = sum(vc.values())
    holds = [("의존 패키지 내부 호출 여부<br>(콜그래프 필요)", 87, "#8e24aa"), ("공격자 입력인지<br>판단 필요", 25, "#fb8c00"),
             ("코드로 확인<br>불가", 5, "#8c959f")]
    assert sum(n for _, n, _ in holds) == vc["uncertain"]
    segs = [("근거와 함께 제외<br>(에이전트)", agent_na, "#1e88e5"), ("제외<br>(데모 피드백)", demo, "#90caf9"),
            ("영향 있음", vc["affected"], "#e53935"), ("사람 검토 대기", vc["uncertain"], "#fb8c00")]

    def bar(parts, tot, width):
        cells = "".join(f"<div style='width:{n / tot * width:.1f}px;background:{c};color:#fff;font-weight:800;"
                        f"display:flex;align-items:center;justify-content:center;font-size:18px'>{n if n / tot > .04 else ''}</div>"
                        for _, n, c in parts)
        legend = "".join(f"<span style='white-space:nowrap'><b style='color:{c}'>■</b> {l.replace('<br>', ' ')} <b>{n}</b></span>"
                         for l, n, c in parts)
        return (f"<div style='display:flex;height:46px;border-radius:10px;overflow:hidden;width:{width}px'>{cells}</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:4px 18px;font-size:14px;color:#57606a;margin-top:8px'>{legend}</div>")
    W = 980
    hold_w = vc["uncertain"] / total * W
    html = (f"<div class='card' style='width:1060px'>"
            f"<div style='font-size:22px;font-weight:800'>스캐너 경고 {total}건은 어디로 갔나</div>"
            f"<div style='font-size:14px;color:#57606a;margin:4px 0 16px'>본인 레포 5개 파일럿 · 적극 모드 · 에이전트 단독 경고 감소 {agent_na / total:.1%}</div>"
            f"{bar(segs, total, W)}"
            f"<div style='margin:18px 0 6px {W - hold_w:.0f}px;font-size:14px;color:#e65100;font-weight:700'>"
            f"↓ 사람 검토 {vc['uncertain']}건의 원인</div>"
            f"<div style='margin-left:{W - hold_w:.0f}px'>{bar(holds, vc['uncertain'], hold_w)}</div>"
            f"<div style='font-size:13px;color:#57606a;margin-top:14px'>콜그래프를 붙이면 검토율이 67.2%에서 약 19%로 줄 것으로 추정 (추정치)</div></div>")
    shot(html, HERE / "warnings.png", 1060, 356)


# ── gif: judge walk-through on the real showcase case ────────────────────────────
JUDGE_STEPS = [
    ("스캐너", "rembg 2.0.61 이 취약 버전 범위에 들어감 → <b>경고</b>", "bad",
     "버전만 보면 CVSS 8.6 경고. 실제로 위험한가?"),
    ("① 공개 권고문", "<i>“The public <span class=mono>/api/remove</span> endpoint accepts attacker-controlled "
     "<span class=mono>extras.sam_model</span> …”</i><br><span style='font-size:13px'>GHSA-qr6x-7v33-6qmg (공개 정보만 외부 LLM에 보냄)</span>", "io",
     "권고문 원문을 읽는다"),
    ("② LLM: 발동 조건 추출", "<span class=mono style='font-size:14px'>{ \"type\": \"input\",<br>&nbsp;&nbsp;\"api\": \"extras.sam_model\",<br>"
     "&nbsp;&nbsp;\"quote\": \"The attacker must supply … extras.sam_model …\" }</span>", "llm",
     "LLM은 조건만 뽑는다 (structured output)"),
    ("③ 코드: 원문 대조", "추출한 이름 <span class=mono>extras.sam_model</span> 이 권고문에 실제로 있음 ✓<br>"
     "<span style='font-size:13px'>권고문에 없는 함수명은 버린다</span>", "code", "LLM 출력을 그대로 믿지 않는다"),
    ("④ 코드: 서비스 소스 검색", "<span class=mono style='font-size:14px'>import rembg → 8곳<br>"
     "&nbsp;&nbsp;pipeline/ahn_tag_headaware.py:56, :84, :91, :147<br>&nbsp;&nbsp;pipeline/clearance_v7.py:10 외 3곳<br>"
     "extras.sam_model → <b>0곳</b></span>", "code", "패키지는 쓰지만 발동 조건은 없다"),
    ("⑤ 판정", "<b>not_affected</b> · 근거 file:line 과 OpenVEX 기록 → 경고에서 제외<br>"
     "<span style='font-size:13px'>확신이 없으면 uncertain → 사람에게 넘김</span>", "ok", "근거와 함께 거르고, 되돌릴 수 있게 남긴다"),
]


LOOP_STEPS = [
    ("1차 실행", "<span class=mono style='font-size:14px'>podcast4life · pillow@11.3.0 · CVE-2026-112893</span><br>"
     "폰트를 공격자 데이터에서 읽는지는 코드로 판단 불가 → <b>uncertain</b>, 사람 검토 대기열로", "human",
     "에이전트가 확신하지 못한 건은 사람에게"),
    ("담당자 결정 (예시)", "<span class=mono style='font-size:13px'>sca feedback add --decision reject --verdict not_affected<br>"
     "&nbsp;&nbsp;--reason not_reachable --note \"폰트는 고정 경로\" --by &lt;담당자&gt;</span>", "io",
     "기각 사유를 구조화해 저장 (data/feedback/decisions.jsonl)"),
    ("2차 실행", "같은 패키지·취약점 → 판정 규칙 R0이 저장된 결정을 먼저 적용 → <b>not_affected</b><br>"
     "<span style='font-size:13px'>다른 서비스에도 적용하려면 --scope all_services</span>", "code",
     "같은 경고를 다시 보지 않는다"),
    ("공유", "OpenVEX에 <span class=mono>not_affected</span> + 사유(<span class=mono>vulnerable_code_not_in_execute_path</span>) 기록",
     "ok", "판정 근거를 표준 형식으로 그룹과 공유"),
    ("조치 후 재스캔", "업그레이드한 서비스를 다시 스캔해 이전 실행과 비교 → 사라진 경고만 <b>해소 확인</b>", "code",
     "고쳤다는 보고가 아니라 재스캔으로 닫는다"),
]


def step_frame(steps, k, title, h):
    rows = []
    for i, (t, body, cls, _) in enumerate(steps):
        vis = "1" if i <= k else "0.0"
        cur = "box-shadow:0 0 0 3px rgba(9,105,218,.25);" if i == k else ""
        rows.append(f"<div class='card {cls}' style='opacity:{vis};padding:10px 16px;border-radius:12px;border-width:1.5px;"
                    f"display:flex;gap:16px;align-items:center;{cur}'><div style='width:170px;font-weight:800;font-size:15px'>{t}</div>"
                    f"<div style='flex:1;font-size:15px;line-height:1.45'>{body}</div></div>")
    cap = steps[k][3]
    return (f"<div style='width:960px;height:{h}px;background:#fff;padding:22px 28px;display:flex;flex-direction:column;gap:8px'>"
            f"<div style='display:flex;justify-content:space-between;align-items:baseline'><div style='font-size:20px;font-weight:800'>"
            f"{title}</div><div style='font-size:13px;color:#57606a'>"
            f"{k + 1}/{len(steps)}</div></div><div style='font-size:15px;color:#0969da;font-weight:700;margin-bottom:4px'>"
            f"{cap}</div>{''.join(rows)}</div>")


def steps_gif(steps, title, out, h):
    frames = [(step_frame(steps, k, title, h), 2.2 if k < len(steps) - 1 else 4.0) for k in range(len(steps))]
    gif(frames, HERE / out, 960, h)


def judge_gif():
    steps_gif(JUDGE_STEPS, "판정 예시 · podcast4life · rembg@2.0.61 · CVE-2026-115924", "judge.gif", 600)


def loop_gif():
    steps_gif(LOOP_STEPS, "개선 루프 · 사람의 결정이 다음 판정이 된다 (동작 예시)", "loop.gif", 450)


# ── gif: terminal replay of a real run ────────────────────────────────────────────
STAGES = ["[1/8] scan (syft → grype)", "[2/8] ingest", "[3/8] enrich (OSV aliases · EPSS · KEV)", "[4/8] graph + score",
          "[5/8] judge (LLM: advisory → conditions · CODE: range/search/rules)"]
TAIL = ["[6/8] plan (greedy weighted set cover)", "[7/8] report", "[8/8] feedback · eval"]
TICKETS = ["T01-upgrade-pypi-pillow.md", "T02-upgrade-pypi-aiohttp.md", "T03-upgrade-pypi-urllib3.md"]


def term(lines, cursor=True):
    body = "<br>".join(lines) + ("<span style='background:#c9d1d9'>&nbsp;</span>" if cursor else "")
    return (f"<div style='width:960px;height:540px;background:#0d1117;padding:0'>"
            f"<div style='height:34px;background:#161b22;display:flex;align-items:center;gap:8px;padding:0 14px'>"
            f"<span style='width:12px;height:12px;border-radius:6px;background:#ff5f56'></span>"
            f"<span style='width:12px;height:12px;border-radius:6px;background:#ffbd2e'></span>"
            f"<span style='width:12px;height:12px;border-radius:6px;background:#27c93f'></span>"
            f"<span style='margin-left:auto;color:#8b949e;font-size:12px'>실제 실행 출력 · 140초 → 12초로 압축</span></div>"
            f"<div class=mono style='color:#c9d1d9;font-size:15px;line-height:1.6;padding:16px 20px'>{body}</div></div>")


def demo_gif():
    p = "<span style='color:#7ee787'>$</span> "
    cmd = ".venv/bin/python -m sca run --skip-scan --offline"
    frames = []
    for n in (8, 24, len(cmd)):
        frames.append((term([p + cmd[:n]]), 0.35))
    done = [p + cmd]
    for s in STAGES[:-1]:
        done = done + [s]
        frames.append((term(done), 0.35))
    done = done + [STAGES[-1]]
    for n in (10, 40, 80, 120, 150, 174):  # the real run prints "judge N/174" every 10 items
        frames.append((term(done + [f"&nbsp;&nbsp;judge {n}/174"]), 0.5))
    done = done + ["&nbsp;&nbsp;judge 174/174"]
    for s in TAIL:
        done = done + [s]
        frames.append((term(done), 0.45))
    done = done + ["", p + "ls out/tickets"]
    frames.append((term(done), 0.8))
    done = done + [f"<span style='color:#79c0ff'>{t}</span>" for t in TICKETS]
    frames.append((term(done), 4.0))
    gif(frames, HERE / "demo.gif", 960, 540)


if __name__ == "__main__":
    assert shutil.which("ffmpeg"), "ffmpeg required"
    architecture()
    warnings()
    judge_gif()
    demo_gif()
    loop_gif()
    for f in ("architecture.png", "warnings.png", "judge.gif", "demo.gif", "loop.gif"):
        print(f, (HERE / f).stat().st_size // 1024, "KB")
