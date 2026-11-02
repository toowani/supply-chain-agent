"""One static PNG of the Team → Service → Package → Vuln graph for the top-N findings.
Layered, deterministic layout (no force simulation), so reruns give identical images."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

from sca.config import OUT_DIR  # noqa: E402
from sca.contracts import Judgment, finding_id  # noqa: E402
from sca.score.risk import Scored, rank_by_score  # noqa: E402

KIND_COLOR = {"team": "#6b7280", "service": "#2563eb", "package": "#d97706"}
VERDICT_COLOR = {"affected": "#dc2626", "uncertain": "#eab308", "not_affected": "#16a34a",
                 "unjudged": "#9ca3af"}
VERDICT_ORDER = ["affected", "uncertain", "not_affected", "unjudged"]   # worst first
FONTS = ["AppleGothic", "Apple SD Gothic Neo", "NanumGothic", "Malgun Gothic", "Noto Sans CJK KR"]


def _font() -> str:
    have = {f.name for f in font_manager.fontManager.ttflist}
    return next((f for f in FONTS if f in have), "DejaVu Sans")


def _subgraph(g: nx.DiGraph, top: list[Scored], judg: dict[str, Judgment]) -> tuple[nx.DiGraph, dict]:
    h = nx.DiGraph()
    vverdict: dict[str, str] = {}
    vscore: dict[str, float] = {}
    for r in top:
        f = r.finding
        s, p, v = f"svc:{f.service}", f"pkg:{f.package.key}", f"vuln:{f.vuln_id}"
        teams = [u for u in g.predecessors(s) if g.nodes[u].get("kind") == "team"] if s in g else []
        for t in teams:
            h.add_edge(t, s)
        dep = g.edges[s, p].get("dependency", "") if g.has_edge(s, p) else ""
        h.add_edge(s, p, dependency=dep)
        h.add_edge(p, v)
        j = judg.get(finding_id(f.service, f.package.key, f.vuln_id))
        vd = j.verdict if j else "unjudged"
        prev = vverdict.get(v)
        vverdict[v] = vd if prev is None else min(prev, vd, key=VERDICT_ORDER.index)
        vscore[v] = max(vscore.get(v, 0.0), r.score)
    for n in h.nodes:
        h.nodes[n]["kind"] = n.split(":", 1)[0].replace("svc", "service").replace("pkg", "package")
    return h, {"verdict": vverdict, "score": vscore}


def _layers(h: nx.DiGraph, weight: dict[str, float] | None = None) -> dict[str, tuple[float, float]]:
    """x = layer; y order follows parents (barycenter of parent ranks) to limit crossings."""
    layer = {"team": 0, "service": 1, "package": 2, "vuln": 3}
    cols: dict[int, list[str]] = {i: [] for i in range(4)}
    for n in sorted(h.nodes):
        cols[layer[h.nodes[n]["kind"]]].append(n)
    order: dict[str, float] = {}
    for i in range(4):
        def key(n: str) -> tuple:
            ps = [order[p] for p in h.predecessors(n) if p in order]
            return (sum(ps) / len(ps) if ps else 0.0, -(weight or {}).get(n, 0.0), n)
        cols[i].sort(key=key)
        for k, n in enumerate(cols[i]):
            order[n] = k
    pos = {}
    for i, ns in cols.items():
        m = len(ns)
        for k, n in enumerate(ns):
            pos[n] = (float(i), 1.0 - (k + 0.5) / m if m else 0.5)
    return pos


def pick_top(scored: list[Scored], top_n: int, per_service: int | None) -> list[Scored]:
    """Highest scores first; at most `per_service` findings per service so the picture shows
    breadth across services (None = plain top_n)."""
    out, seen = [], {}
    for r in rank_by_score(scored):
        s = r.finding.service
        if per_service is not None and seen.get(s, 0) >= per_service:
            continue
        seen[s] = seen.get(s, 0) + 1
        out.append(r)
        if len(out) == top_n:
            break
    return out


def draw_graph(g: nx.DiGraph, scored: list[Scored], judgments: list[Judgment],
               path: Path = OUT_DIR / "graph.png", top_n: int = 12, per_service: int | None = 4) -> Path:
    """Render the top_n findings by score (with their packages, services, teams) to a PNG."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    judg = {finding_id(j.service, j.package, j.cve): j for j in judgments}
    top = pick_top(scored, top_n, per_service)
    h, meta = _subgraph(g, top, judg)
    pos = _layers(h, meta["score"])

    with plt.rc_context({"font.family": _font(), "axes.unicode_minus": False}):
        _draw(h, meta, pos, path, len(top), per_service)
    return path


def _draw(h: nx.DiGraph, meta: dict, pos: dict, path: Path, n_top: int, per_service: int | None) -> None:
    fig, ax = plt.subplots(figsize=(16, 10), dpi=100)
    ax.set_axis_off()
    ax.set_xlim(-0.45, 3.6)
    ax.set_ylim(-0.04, 1.06)

    for u, v, d in h.edges(data=True):
        style = "--" if d.get("dependency") in ("transitive", "unreferenced") else "-"
        ax.annotate("", xy=pos[v], xytext=pos[u],
                    arrowprops=dict(arrowstyle="-|>", color="#94a3b8", lw=1.0, linestyle=style,
                                    shrinkA=12, shrinkB=12))
    for n, (x, y) in pos.items():
        kind = h.nodes[n]["kind"]
        name = n.split(":", 1)[1]
        if kind == "vuln":
            color = VERDICT_COLOR[meta["verdict"][n]]
            label = f"{name}\nscore {meta['score'][n]:.2f}"
        else:
            color = KIND_COLOR[kind]
            label = name.split(":", 1)[1] if kind == "package" else name
        ax.scatter([x], [y], s=260, c=color, zorder=3, edgecolors="white", linewidths=1.5)
        ax.text(x + 0.05, y, label, fontsize=9, va="center", ha="left", zorder=4,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.8))

    for i, t in enumerate(["팀", "서비스", "패키지", f"취약점 (점수 상위 {n_top}건" + (f", 서비스당 ≤{per_service})" if per_service else ")")]):
        ax.text(i, 1.04, t, fontsize=13, ha="center")
    handles = [Line2D([], [], marker="o", ls="", color=KIND_COLOR[k], label=lbl, markersize=10)
               for k, lbl in [("team", "팀"), ("service", "서비스"), ("package", "패키지")]]
    handles += [Line2D([], [], marker="o", ls="", color=VERDICT_COLOR[v], label=f"취약점: {v}", markersize=10)
                for v in VERDICT_ORDER]
    handles += [Line2D([], [], color="#94a3b8", ls="--", label="전이/미참조 의존성")]
    ax.legend(handles=handles, loc="lower left", fontsize=9, frameon=False)
    fig.suptitle("SW 공급망 영향 그래프 — 팀 → 서비스 → 패키지 → 취약점", fontsize=14)
    fig.savefig(path, dpi=100, metadata={"Software": None})
    plt.close(fig)


# ── enlarged single top-risk chain (portfolio figure) ───────────────────────────────────
VERDICT_KO = {"affected": "영향 있음", "uncertain": "보류(사람 검토)", "not_affected": "영향 없음",
              "unjudged": "미판정"}
VERDICT_TEXT = {"affected": "white", "uncertain": "#1f2937", "not_affected": "white", "unjudged": "white"}
EDGE_KO = {"owns": "담당", "direct": "직접 의존", "transitive": "전이 의존", "unreferenced": "미참조"}


def _split_key(key: str) -> tuple[str, str, str]:
    """'npm:@scope/name@1.2.3' → ('npm', '@scope/name', '1.2.3')."""
    eco, rest = key.split(":", 1)
    name, ver = rest.rsplit("@", 1)
    return eco, name, ver


def top_path(g: nx.DiGraph, ranked: list[Scored], judgments: list[Judgment], max_vulns: int = 4) -> dict:
    """Highest-score finding's chain. Returns {service, team, package, chain, vulns, more, top}:
    chain = [{kind, label, sub, edge}] Team → Service → … → vulnerable package (edge = label of the
    edge INTO that node, '' for the first); vulns = top `max_vulns` findings of that (service,
    package) by score as {id, score, cvss, epss, epss_percentile, kev, verdict}; more = remaining
    count; top = the first of vulns."""
    from sca.graph.build import explain_path
    rows = rank_by_score(ranked)
    if not rows:
        raise ValueError("no scored findings")
    f0 = rows[0].finding
    service, pkg = f0.service, f0.package.key
    s = f"svc:{service}"
    teams = sorted(u.removeprefix("team:") for u in g.predecessors(s)
                   if g.nodes[u].get("kind") == "team") if s in g else []
    chain: list[dict] = []
    if teams:
        chain.append({"kind": "team", "label": teams[0], "sub": "팀", "edge": ""})
    chain.append({"kind": "service", "label": service, "sub": "서비스", "edge": "owns" if teams else ""})
    hops = explain_path(g, service, pkg)[1:]
    unref = len(hops) == 2 and hops[0].startswith("(unreferenced")
    for i, k in enumerate([pkg] if unref else hops):
        eco, name, ver = _split_key(k)
        last = k == pkg
        edge = "unreferenced" if unref else ("direct" if i == 0 else "transitive")
        sub = "취약 패키지" if last else ("직접 의존" if i == 0 else "전이 의존")
        chain.append({"kind": "package", "label": name, "sub": sub, "version": ver, "edge": edge, "ecosystem": eco,
                      "vulnerable": last})
    judg = {finding_id(j.service, j.package, j.cve): j for j in judgments}
    mine = [r for r in rows if r.finding.service == service and r.finding.package.key == pkg]
    vulns = []
    for r in mine[:max_vulns]:
        j = judg.get(finding_id(service, pkg, r.finding.vuln_id))
        vulns.append({"id": r.finding.vuln_id, "score": r.score, "cvss": r.cvss, "epss": r.epss,
                      "epss_percentile": r.epss_percentile, "kev": r.kev,
                      "verdict": j.verdict if j else "unjudged"})
    return {"service": service, "team": teams[0] if teams else "", "package": pkg, "chain": chain,
            "vulns": vulns, "more": max(0, len(mine) - max_vulns), "top": vulns[0]}


def _wrap_name(name: str, width: int = 14) -> str:
    if any("\uac00" <= c <= "\ud7a3" for c in name) and len(name) > 5:   # Hangul: split in half
        h = (len(name) + 1) // 2 - (1 if name.endswith("팀") and len(name) % 2 else 0)
        return f"{name[:h]}\n{name[h:]}"
    if len(name) <= width:
        return name
    if "/" in name:                                    # npm scope
        a, b = name.split("/", 1)
        return f"{a}/\n{b}"
    cut = max((i for i, c in enumerate(name[:width + 1]) if c in "-_."), default=width)
    return f"{name[:cut + 1]}\n{name[cut + 1:]}"


def draw_top_path(g: nx.DiGraph, ranked: list[Scored], judgments: list[Judgment],
                  out_path: Path = OUT_DIR / "graph_top_path.png", max_vulns: int = 4) -> Path:
    """Render only the single highest-risk chain, left to right, sized for ~170 mm print width."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tp = top_path(g, ranked, judgments, max_vulns)
    with plt.rc_context({"font.family": _font(), "axes.unicode_minus": False}):
        _draw_top(tp, out_path)
    return out_path


def _text_w(fig, renderer, text: str, size: float, bold: bool = False) -> float:
    """Rendered width of `text` in inches (multi-line → widest line)."""
    t = fig.text(0, 0, text, fontsize=size, fontweight="bold" if bold else "normal")
    w = t.get_window_extent(renderer).width / fig.dpi
    t.remove()
    return w


def _draw_top(tp: dict, path: Path) -> None:
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    fs, small = 16, 15                                 # pt at figure size; ~9.5 in wide → ×0.7 at 170 mm
    pad, gap, bh = 0.14, 0.62, 1.0                     # inches
    vh, vgap = 0.8, 0.12
    chain, vulns = tp["chain"], tp["vulns"]
    probe = plt.figure(figsize=(4, 2), dpi=100)
    rnd = probe.canvas.get_renderer()
    labels, widths = [], []
    for n in chain:
        lab = _wrap_name(n["label"]) + (f"\n{n['version']}" if n["kind"] == "package" else "")
        labels.append(lab)
        widths.append(max(_text_w(probe, rnd, lab, fs, True), _text_w(probe, rnd, n["sub"], small)) + 2 * pad)
    vlines = [(v["id"], f"점수 {v['score']:.2f} · CVSS {v['cvss']:.1f}") for v in vulns]
    vw = max(max(_text_w(probe, rnd, a, fs, True), _text_w(probe, rnd, b, small)) for a, b in vlines) + 2 * pad
    t = tp["top"]
    eco, name, ver = _split_key(tp["package"])
    title = f"최고 위험 경로: {tp['service']} → {name} {ver} ({eco})"
    epss = "EPSS 없음" if t["epss"] is None else (
        f"EPSS {t['epss']:.3f}" + (f" (백분위 {t['epss_percentile'] * 100:.0f})" if t["epss_percentile"] is not None else ""))
    sub = f"1위 {t['id']} · 위험 점수 {t['score']:.2f} · CVSS {t['cvss']:.1f} · {epss} · KEV {'등재' if t['kev'] else '미등재'}"
    min_w = max(_text_w(probe, rnd, title, fs + 3, True), _text_w(probe, rnd, sub, small), 7.4)   # 7.4 ≈ legend
    plt.close(probe)

    nv = len(vulns)
    stack_h = nv * vh + (nv - 1) * vgap + (0.45 if tp["more"] else 0)
    body_h = max(stack_h, bh + 0.5)
    top_m, bot_m, side = 1.05, 0.5, 0.12
    H = body_h + top_m + bot_m
    W = side * 2 + max(sum(widths) + gap * len(chain) + vw, min_w)
    fig = plt.figure(figsize=(W, H), dpi=200)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.set_axis_off()
    cy = bot_m + body_h / 2

    def arrow(p, q, dashed=False, color="#64748b"):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=18, lw=1.8, color=color,
                                     linestyle=(0, (4, 3)) if dashed else "-", zorder=1))

    x = side
    for i, (n, lab, bw) in enumerate(zip(chain, labels, widths)):
        if n["kind"] == "package":
            fc, ec, tc = ("#fef3c7", "#d97706", "#111827") if n.get("vulnerable") else ("#fff7ed", "#fdba74", "#111827")
        else:
            fc = KIND_COLOR[n["kind"]]
            ec, tc = fc, "white"
        ax.add_patch(FancyBboxPatch((x, cy - bh / 2), bw, bh, boxstyle="round,pad=0,rounding_size=0.1",
                                    fc=fc, ec=ec, lw=2.4 if n.get("vulnerable") else 1.4, zorder=2))
        ax.text(x + bw / 2, cy, lab, ha="center", va="center", fontsize=fs if lab.count("\n") < 2 else fs - 2,
                color=tc, zorder=3, linespacing=1.15,
                fontweight="bold" if n["kind"] != "package" or n.get("vulnerable") else "normal")
        ax.text(x + bw / 2, cy + bh / 2 + 0.08, n["sub"], ha="center", va="bottom", fontsize=small,
                color="#475569")
        if i:
            arrow((x - gap + 0.04, cy), (x - 0.04, cy), dashed=n["edge"] in ("transitive", "unreferenced"))
            ax.text(x - gap / 2, cy - 0.1, EDGE_KO[n["edge"]].split()[0], ha="center", va="top",
                    fontsize=small, color="#334155")
        x += bw + gap
    pkg_right = x - gap
    vx = x
    y = cy + stack_h / 2
    for v, (a, b) in zip(vulns, vlines):
        yc = y - vh / 2
        color = VERDICT_COLOR[v["verdict"]]
        tc = VERDICT_TEXT[v["verdict"]]
        ax.add_patch(FancyBboxPatch((vx, y - vh), vw, vh, boxstyle="round,pad=0,rounding_size=0.08",
                                    fc=color, ec=color, zorder=2))
        ax.text(vx + pad, yc + 0.16, a, ha="left", va="center", fontsize=fs, color=tc, fontweight="bold", zorder=3)
        ax.text(vx + pad, yc - 0.19, b, ha="left", va="center", fontsize=small, color=tc, zorder=3)
        arrow((pkg_right + 0.04, cy), (vx - 0.04, yc), color="#94a3b8")
        y -= vh + vgap
    if tp["more"]:
        ax.text(vx + vw / 2, y + vgap - 0.05, f"+{tp['more']}건 더 (같은 패키지)", ha="center", va="top",
                fontsize=small, color="#475569")
    ax.text(side, H - 0.12, title, ha="left", va="top",
            fontsize=fs + 3, fontweight="bold", color="#0f172a")
    ax.text(side, H - 0.56, sub, ha="left", va="top", fontsize=small, color="#334155")
    handles = [Line2D([], [], marker="s", ls="", color=VERDICT_COLOR[v], label=VERDICT_KO[v], markersize=12)
               for v in ("affected", "uncertain", "not_affected")]
    handles += [Line2D([], [], color="#64748b", ls="--", label="전이 의존")]
    ax.legend(handles=handles, loc="lower left", bbox_to_anchor=(side / W, 0.0), ncol=4, fontsize=small,
              frameon=False, handletextpad=0.4, columnspacing=1.0, borderaxespad=0.2)
    fig.savefig(path, dpi=200, metadata={"Software": None})
    plt.close(fig)
