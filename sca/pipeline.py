"""scan → ingest → enrich → graph → score → judge → plan → report → feedback/eval.
CODE computes, LLM (judge conditions, ticket prose) reads public advisories only, HUMAN decides."""
from __future__ import annotations

import datetime as dt
import json
import subprocess
import time
from pathlib import Path

from sca.config import CACHE_DIR, OUT_DIR, ROOT, load_assets, load_scoring, load_services
from sca.enrich.aliases import advisory_ids, apply_osv_aliases
from sca.enrich.feeds import epss_meta, fetch_epss, fetch_kev, fetch_osv, kev_meta
from sca.graph.build import build_graph, summary
from sca.ingest.inventory import build_inventory
from sca.ingest.scan import require_tools, scan_all
from sca.contracts import finding_id
from sca.eval.groundtruth import load_ground_truth
from sca.eval.metrics import evaluate, kpis, write_metrics
from sca.feedback.history import latest_snapshot, rescan_verify, snapshot
from sca.feedback.store import FeedbackStore
from sca.feedback.vex import write_openvex
from sca.ingest.inventory import dependency_class
from sca.judge.run import judge_findings, rule_counts
from sca.plan.alternatives import analyze_plan
from sca.plan.greedy import plan_actions
from sca.report.graph_png import draw_graph, draw_top_path
from sca.report.insights import automation_kpis, hold_breakdown, shared_judgment_kpis, showcase_not_affected
from sca.report.render import write_report
from sca.report.tables import _table, build_rows, compare_top10, write_csv
from sca.report.tickets import write_tickets
from sca.score.risk import epss_prior, rank_by_score, rank_by_severity, score_finding


def _grype_db_built() -> str:
    import shutil
    if not shutil.which("grype"):
        return "?"
    try:
        out = subprocess.run(["grype", "db", "status"], text=True, capture_output=True).stdout
        return next((l.split(None, 1)[1] for l in out.splitlines() if l.startswith("Built")), "?")
    except OSError:
        return "?"


def _mode_row(js, gt_core, gt_ext) -> dict:
    x = _extra_kpis(js, gt_core, gt_ext, {})
    n = len(js) or 1
    return {"reduction_agent_only": round(x["agent_only_reduction"], 4),
            "human_review": round(sum(j.verdict == "uncertain" for j in js) / n, 4),
            "core_accuracy": x["core_correct"] / x["core_n"] if x["core_n"] else None,
            "core_decided_precision": x["core_decided_precision"], "core_decided": x["core_decided"],
            "core_false_not_affected": sum(1 for g in gt_core for j in js
                                           if (j.service, j.package, j.cve) == g.key
                                           and j.verdict == "not_affected" and g.label == "affected"),
            "ext_accuracy": x["ext_accuracy"]}


def _extra_kpis(judgments, gt_core, gt_ext, metrics) -> dict:
    """Held-out (core) precision/abstention, majority baseline, tuning-set accuracy, agent-only
    warning reduction (feedback-decided rows excluded from the numerator)."""
    import yaml

    from sca.eval.groundtruth import GT_PATH
    jx = {(j.service, j.package, j.cve): j for j in judgments}

    def score(items):
        pairs = [(g, jx.get(g.key)) for g in items if jx.get(g.key)]
        dec = [(g, j) for g, j in pairs if j.verdict != "uncertain"]
        return pairs, dec
    pairs, dec = score(gt_core)
    reviewed = 0
    if GT_PATH.exists():
        raw = (yaml.safe_load(GT_PATH.read_text(encoding="utf-8")) or {}).get("items", [])
        keys = {g.key for g in gt_core}
        reviewed = sum(bool(i.get("reviewed")) for i in raw if (i["service"], i["package"], i["vuln_id"]) in keys)
    epairs, _ = score(gt_ext)
    fb = [j for j in judgments if j.decided_by == "feedback"]
    na_agent = sum(j.verdict == "not_affected" and j.decided_by != "feedback" for j in judgments)
    n = len(judgments) or 1
    from collections import Counter
    maj = Counter(g.label for g, _ in pairs).most_common(1)
    return {
        "core_n": len(pairs), "core_correct": sum(j.verdict == g.label for g, j in pairs),
        "core_reviewed": reviewed,
        "core_decided": len(dec), "core_decided_correct": sum(j.verdict == g.label for g, j in dec),
        "core_decided_precision": (sum(j.verdict == g.label for g, j in dec) / len(dec)) if dec else None,
        "core_abstain": len(pairs) - len(dec),
        "core_baseline": (maj[0][1] / len(pairs)) if pairs else None,
        "core_affected_recall": (lambda a: sum(j.verdict == "affected" for g, j in a) / len(a) if a else None)(
            [(g, j) for g, j in pairs if g.label == "affected"]),
        "ext_n": len(epairs), "ext_accuracy": (sum(j.verdict == g.label for g, j in epairs) / len(epairs)) if epairs else None,
        "feedback_rows": len(fb), "agent_only_not_affected": na_agent, "agent_only_reduction": na_agent / n,
    }


def _core_keys() -> set[tuple[str, str, str]]:
    """Ground-truth items marked set: core (the reviewed ~20); others are the extended set."""
    import yaml
    from sca.eval.groundtruth import GT_PATH
    if not GT_PATH.exists():
        return set()
    items = (yaml.safe_load(GT_PATH.read_text(encoding="utf-8")) or {}).get("items", [])
    return {(i["service"], i["package"], i["vuln_id"]) for i in items if i.get("set") == "core"}


def make_dependents(invs, services, max_depth: int = 3):
    """(service, pkg_key) → [(label, installed source dir)] of packages in that service that
    require pkg_key, nearest first (≤max_depth hops). pypi: reverse Requires-Dist of EVERY
    installed distribution (not only those reachable from declared deps — undeclared imports
    like rembg count). npm: lockfile edges, resolved to the copy of the exact version."""
    from collections import deque

    from sca.ingest.manifests import norm_npm, norm_pypi
    from sca.judge.code_search import installed_requires, python_import_names
    from sca.judge.run import service_venvs
    svc_by = {s.name: s for s in services}
    npm_parents = {inv.service: {} for inv in invs}
    for inv in invs:
        for e in inv.edges:
            if e.child.startswith("npm:"):
                npm_parents[inv.service].setdefault(e.child, []).append(e.parent)

    def npm_dirs(service: str, key: str) -> list[Path]:
        svc = svc_by[service]
        name, ver = key[4:].rsplit("@", 1)
        out = []
        for c in svc.components:
            if c.kind != "npm-lock":
                continue
            base = svc.repo_path / c.path
            lock = json.loads((base / "package-lock.json").read_text(encoding="utf-8"))
            for path, ent in lock.get("packages", {}).items():
                if path and ent.get("version") == ver and norm_npm(path.rsplit("node_modules/", 1)[-1]) == name:
                    if (base / path).is_dir():
                        out.append(base / path)
        return out

    def py_dependents(service: str, name: str) -> list[tuple[str, Path, int]]:
        out = []
        for v in service_venvs(svc_by[service]):
            req = installed_requires(v)
            rev: dict[str, list[str]] = {}
            for d, rs in req.items():
                for r in rs:
                    rev.setdefault(r, []).append(d)
            seen, q = {name}, deque([(name, 0)])
            while q:
                n, depth = q.popleft()
                if depth >= max_depth:
                    continue
                for par in sorted(rev.get(n, [])):
                    if par in seen:
                        continue
                    seen.add(par)
                    for site in v.glob("lib/python*/site-packages"):
                        out += [(par, site / m, depth + 1) for m in python_import_names(par, v)
                                if (site / m).is_dir()]
                    q.append((par, depth + 1))
        return out

    def dependents(service: str, pkg_key: str) -> list[tuple[str, Path, int]]:
        if pkg_key.startswith("pypi:"):
            return py_dependents(service, norm_pypi(pkg_key[5:].rsplit("@", 1)[0]))
        seen, out, q = {pkg_key}, [], deque([(pkg_key, 0)])
        while q:
            k, d = q.popleft()
            if d >= max_depth:
                continue
            for par in sorted(npm_parents[service].get(k, [])):
                if par in seen:
                    continue
                seen.add(par)
                out += [(par.split(":", 1)[1], p, d + 1) for p in npm_dirs(service, par)]
                q.append((par, d + 1))
        return out
    return dependents


def runtime_check(plan, services, offline: bool = False) -> None:
    """Flag upgrade targets whose Requires-Python excludes the service's interpreter (a plain
    `pip install` would fail → runtime upgrade is part of the work). Sets Action.runtime_upgrade /
    runtime_note and appends to note; major_bump stays the semver result. Services whose venv is
    missing or unreadable are skipped (runtime unknown)."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet

    from sca.enrich.feeds import fetch_pypi_release
    from sca.plan.alternatives import service_pythons
    pys = service_pythons([s for s in services if any(s.name in a.services for a in plan.actions)])
    for a in plan.actions:
        if a.kind != "upgrade" or a.ecosystem != "pypi":
            continue
        spec = fetch_pypi_release(a.package, a.target_version, offline).get("requires_python", "")
        if not spec:
            continue
        try:
            ss = SpecifierSet(spec)
        except InvalidSpecifier:
            continue
        bad = []
        for s in a.services:
            for py in pys.get(s, []):
                if py not in ss:
                    a.note = (a.note + "; " if a.note else "") + (
                        f"{s}: 목표 버전은 Python {spec} 필요, 서비스는 {py} → 런타임 업그레이드 필요")
                    bad.append(py)
        if bad:
            a.runtime_upgrade = True
            a.runtime_note = f"Python {', '.join(sorted(set(bad)))} → {spec}"


INSTALLER_TOOLS = {"pip", "setuptools", "wheel", "distribute"}


def refine_unreferenced(dep_class: dict, invs, services) -> dict[str, dict[str, str]]:
    """'unreferenced' = not reachable from declared deps. Before proposing removal, split off
    packages the service code imports anyway (undeclared → declare, don't delete) and venv
    installer tooling (rebuild venv instead). Mutates dep_class; returns {service: {key: new}}."""
    from sca.judge.code_search import direct_import_hits
    from sca.judge.run import service_venvs
    svc_by = {s.name: s for s in services}
    changed: dict[str, dict[str, str]] = {}
    for inv in invs:
        svc = svc_by[inv.service]
        venvs = service_venvs(svc)
        for p in inv.packages:
            if dep_class[inv.service].get(p.key) != "unreferenced":
                continue
            if p.ecosystem == "pypi" and p.name in INSTALLER_TOOLS:
                new = "tooling"
            elif direct_import_hits(svc.repo_path, p.ecosystem, p.name, venvs[0] if venvs else None):
                new = "undeclared"
            else:
                continue
            dep_class[inv.service][p.key] = new
            changed.setdefault(inv.service, {})[p.key] = new
    return changed


def _llm(no_llm: bool):
    """LLM client, or None with --no-llm. Backend down → cache-only client: cached condition
    extractions and ticket prose are still served, nothing new is requested."""
    if no_llm:
        return None
    from sca.llm import LLM
    llm = LLM()
    try:
        llm.client.models.list()
    except Exception as e:
        print(f"  LLM backend unreachable ({llm.base_url}): {type(e).__name__}; using cached LLM output only")
        llm.cache_only = True
    return llm


def _guard_llm_unavailable(llm, judgments) -> None:
    """Backend down and some rows needed new LLM output → stop before out/ is overwritten with
    collapsed numbers. --no-llm runs that way on purpose."""
    if llm is None or not getattr(llm, "cache_only", False):
        return
    n = sum(j.rule == "llm_unavailable" for j in judgments)
    if n:
        raise SystemExit(f"LLM 백엔드({getattr(llm, 'base_url', llm.name)})에 연결할 수 없고 캐시에 없는 조건 추출이 {n}건입니다. "
                         "지표가 바뀌므로 out/을 덮어쓰지 않고 중단합니다. LLM을 켜거나 --no-llm으로 명시 실행하세요.")


def run(skip_scan: bool = False, offline: bool = False, refresh_venv: bool = False,
        top_k: int = 10, k: int = 3, no_llm: bool = False, judge_mode: str = "proactive") -> dict:
    t0 = time.perf_counter()
    services, assets, cfg = load_services(), load_assets(), load_scoring()
    missing = [s.name for s in services if s.name not in assets]
    if missing:
        raise SystemExit(f"assets.yaml missing services: {missing}")
    # --skip-scan reuses out/raw: tool versions are recorded when installed, never required
    tools = require_tools(services, strict=not skip_scan)

    print("[1/8] scan (syft → grype)")
    if not skip_scan:
        scan_all(services, refresh_venv=refresh_venv)
    t_scan = time.perf_counter()

    print("[2/8] ingest")
    invs = [build_inventory(s) for s in services]
    findings = [f for inv in invs for f in inv.findings]

    print("[3/8] enrich (OSV aliases · EPSS · KEV)")
    osv = fetch_osv(advisory_ids(findings), offline=offline)
    findings, alias_filled = apply_osv_aliases(findings, osv)
    for inv in invs:
        inv.findings = [f for f in findings if f.service == inv.service]
    cves = sorted({c for f in findings for c in f.cve_ids})
    epss = fetch_epss(cves, offline=offline)
    kev = fetch_kev(offline=offline)
    if offline and (not kev or (cves and not epss)):
        raise SystemExit("--offline but data/cache has no KEV/EPSS; run once online first")

    print("[4/8] graph + score")
    g = build_graph(invs, assets)
    gsum = summary(g, invs)
    prior = epss_prior(cfg, epss)
    scored = [score_finding(f, assets[f.service], epss, kev, cfg, prior) for f in findings]
    ranked, by_sev = rank_by_score(scored), rank_by_severity(scored)

    print("[5/8] judge (LLM: advisory → conditions · CODE: range/search/rules)")
    t_judge0 = time.perf_counter()
    llm = _llm(no_llm)
    store = FeedbackStore()
    deps = make_dependents(invs, services)
    judgments = judge_findings(ranked, services, osv, llm,
                               suppression=lambda s, p, v: store.suppression(s, p, v),
                               examples=lambda p, v: store.examples_for(p, v),
                               dependents=deps, mode=judge_mode)
    t_judge = time.perf_counter() - t_judge0
    _guard_llm_unavailable(llm, judgments)
    other = "proactive" if judge_mode == "conservative" else "conservative"
    alt = judge_findings(ranked, services, osv, llm,
                         suppression=lambda s, p, v: store.suppression(s, p, v),
                         examples=lambda p, v: store.examples_for(p, v),
                         dependents=deps, mode=other, verbose=False)
    j_idx = {finding_id(j.service, j.package, j.cve): j for j in judgments}

    print("[6/8] plan (greedy weighted set cover)")
    dep_class = {inv.service: dependency_class(inv) for inv in invs}
    refined = refine_unreferenced(dep_class, invs, services)
    plan = plan_actions(ranked, judgments, dep_class, k=k)
    runtime_check(plan, services, offline=offline)
    followups = analyze_plan(plan, ranked, judgments, dep_class, services, invs=invs, offline=offline)

    print("[7/8] report")
    rows = build_rows(ranked, by_sev, invs, assets, g)
    for r, s in zip(rows, ranked):
        r["dependency"] = dep_class[s.finding.service].get(s.finding.package.key, r["dependency"])
        j = j_idx.get(finding_id(s.finding.service, s.finding.package.key, s.finding.vuln_id))
        r["verdict"], r["rule"] = (j.verdict, j.rule) if j else ("", "")
    write_csv(rows, OUT_DIR / "ranked.csv")
    cmp_md, cmp_stats = compare_top10(ranked, by_sev, assets, k=top_k)
    (OUT_DIR / "judgments.json").write_text(
        json.dumps([j.model_dump() for j in judgments], ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT_DIR / "plan.json").write_text(plan.model_dump_json(indent=1), encoding="utf-8")
    tickets = write_tickets(plan, ranked, judgments, osv, llm, assets=assets)
    draw_graph(g, ranked, judgments)
    draw_top_path(g, ranked, judgments)
    run_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_openvex(judgments, OUT_DIR / "vex.json", author="supply-chain-agent PoC", timestamp=run_at)

    print("[8/8] feedback · eval")
    prev = latest_snapshot(before=run_at)
    rescan = rescan_verify(prev, rows, judgments, store, scanned_services=[s.name for s in services])
    snapshot(run_at, rows, judgments)
    gt = load_ground_truth()
    core_keys = _core_keys()
    gt_core = [g for g in gt if g.key in core_keys] if gt else None
    gt_eval = evaluate(judgments, gt_core or gt)
    metrics = kpis(ranked, judgments, plan, gt_eval)
    metrics["eval"] = gt_eval
    gt_ext = [g for g in gt if g.key not in core_keys] if gt_core else []
    metrics["eval_extended"] = evaluate(judgments, gt_ext) if gt_ext else None
    metrics["extra"] = _extra_kpis(judgments, gt_core or gt or [], gt_ext, metrics)
    metrics["judge_mode"] = judge_mode
    metrics["mode_comparison"] = {
        judge_mode: _mode_row(judgments, gt_core or gt or [], gt_ext),
        other: _mode_row(alt, gt_core or gt or [], gt_ext)}
    if rescan.get("prev_snapshot"):
        rescan["prev_snapshot"] = Path(rescan["prev_snapshot"]).name
    metrics["rescan"] = rescan
    metrics["judge_stage_seconds"] = round(t_judge, 1)
    metrics["llm"] = llm.name if llm else "none"
    metrics["rule_counts"] = rule_counts(judgments)
    metrics["plan_followups"] = followups
    metrics["insights"] = {
        "hold": hold_breakdown(judgments, gt),
        "automation": automation_kpis(judgments, gt_core or gt or []),
        "showcase": showcase_not_affected(judgments, CACHE_DIR / "osv", ranked, gt=gt, core_keys=core_keys),
        "shared": shared_judgment_kpis(judgments, ROOT / "data" / "feedback" / "decisions.jsonl"),
    }
    write_metrics(metrics)
    elapsed = time.perf_counter() - t0

    prov = {
        "run_at": run_at, "llm": llm.name if llm else "none",
        "tools": tools, "grype_db_built": _grype_db_built(),
        "kev": kev_meta(), "epss": epss_meta(),
        "cves": len(cves), "cves_with_epss": len(epss),
        "osv_records": sum(bool(v) for v in osv.values()), "osv_queried": len(osv),
        "cve_aliases_from_osv": alias_filled, "epss_prior": round(prior, 5),
        "seconds_total": round(elapsed, 1), "seconds_scan": round(t_scan - t0, 1),
        "notes": {inv.service: inv.notes for inv in invs if inv.notes},
    }
    gsum["comparison"] = cmp_stats
    gsum["provenance"] = prov
    (OUT_DIR / "graph_summary.json").write_text(json.dumps(gsum, ensure_ascii=False, indent=1),
                                                encoding="utf-8")
    md = render_summary(gsum, cmp_md, rows)
    (OUT_DIR / "summary.md").write_text(md, encoding="utf-8")
    write_report(OUT_DIR / "report.md", gsum=gsum, rows=rows, scored=ranked, judgments=judgments,
                 plan=plan, metrics=metrics, llm_name=llm.name if llm else "none", tickets=tickets)
    print()
    print(md)
    return gsum


def render_summary(s: dict, cmp_md: str, rows: list[dict]) -> str:
    p = s["provenance"]
    per = s["per_service"]
    tot = {k: sum(r[k] for r in per) for k in ("packages", "direct", "transitive", "unreferenced",
                                                  "findings", "vulnerable_packages",
                                                  "vulnerable_direct", "vulnerable_transitive",
                                                  "vulnerable_unreferenced")}
    kev_rows = [r for r in rows if r["kev"]]
    c = s["comparison"]
    parts = [
        f"# 스캔 요약 (본인 레포 {s['services']}개 파일럿)",
        f"실행 {p['run_at']} · syft {p['tools'].get('syft', '-')} · grype {p['tools'].get('grype', '-')} "
        f"(DB 빌드 {p['grype_db_built']}) · KEV 카탈로그 {p['kev'].get('catalogVersion')} · "
        f"EPSS 수집 {p['epss'].get('fetched_at')} · 소요 {p['seconds_total']}s (스캔 {p['seconds_scan']}s)",
        "",
        "## 그래프 요약",
        _table(["서비스", "팀", "패키지(name@ver, 고유)", "패키지(name, 고유)", "취약점(고유 ID)",
                "탐지 행(서비스×패키지×취약점)", "서비스 간 공유 패키지"],
               [[s["services"], s["teams"], s["package_versions"], s["package_names"],
                 s["vulnerabilities"], tot["findings"], s["shared_packages_total"]]]),
        "",
        "## 직접 vs 전이 의존성 (서비스별, 고유 name@version)",
        _table(["서비스", "전체", "직접", "전이", "미참조*", "dev 전용", "탐지 행",
                "취약 패키지", "└ 직접", "└ 전이", "└ 미참조"],
               [[r["service"], r["packages"], r["direct"], r["transitive"], r["unreferenced"],
                 r["dev_only"], r["findings"], r["vulnerable_packages"], r["vulnerable_direct"],
                 r["vulnerable_transitive"], r["vulnerable_unreferenced"]] for r in per]
               + [["**합계**", tot["packages"], tot["direct"], tot["transitive"], tot["unreferenced"],
                   sum(r["dev_only"] for r in per), tot["findings"], tot["vulnerable_packages"],
                   tot["vulnerable_direct"], tot["vulnerable_transitive"],
                   tot["vulnerable_unreferenced"]]]),
        "",
        "\\* 미참조: 설치돼 있지만 직접 의존성에서 도달하지 않음 (venv의 pip/setuptools, 이전 설치 잔여물 등)",
        "",
        "## 서비스 간 공유 패키지 상위 10",
        _table(["#", "생태계", "패키지", "서비스 수", "서비스", "버전"],
               [[i + 1, r["ecosystem"], r["package"], r["services"], ", ".join(r["service_names"]),
                 ", ".join(r["versions"])] for i, r in enumerate(s["shared_top10"])]),
        "",
        f"## 심각도 단독 정렬 vs 종합 점수 정렬 (Top {c['k']})",
        cmp_md,
        "",
        _table(["지표", "심각도 Top10", "종합 Top10"],
               [["겹치는 항목", c["overlap"], c["overlap"]],
                ["KEV 포함", c["severity"]["kev"], c["score"]["kev"]],
                ["인터넷 노출 서비스", c["severity"]["internet"], c["score"]["internet"]],
                ["EPSS 보유 / 정보 부족(prior)", f'{c["severity"]["with_epss"]} / {c["severity"]["prior"]}',
                 f'{c["score"]["with_epss"]} / {c["score"]["prior"]}'],
                ["평균 EPSS (보유 행만)", c["severity"]["mean_epss"], c["score"]["mean_epss"]],
                ["최대 EPSS", c["severity"]["max_epss"], c["score"]["max_epss"]],
                ["수정 버전 있음", c["severity"]["fixable"], c["score"]["fixable"]],
                ["관련 서비스 수", c["severity"]["services"], c["score"]["services"]]]),
        "",
        f"KEV 해당 행: {len(kev_rows)}"
        + (" — " + ", ".join(sorted({f"{r['vuln_id']}({r['package']})" for r in kev_rows})) if kev_rows else ""),
        f"EPSS 보유 CVE: {p['cves_with_epss']}/{p['cves']} · OSV 권고문 캐시: {p['osv_records']}/{p['osv_queried']}"
        f" · OSV alias로 CVE 보강: {p['cve_aliases_from_osv']}행",
    ]
    return "\n".join(parts) + "\n"
