import json

import networkx as nx
import pytest

from sca.config import Asset
from sca.contracts import Action, Judgment, PlanResult, finding_id
from sca.eval.groundtruth import GTItem, load_ground_truth
from sca.eval.metrics import evaluate, kpis, write_metrics
from sca.ingest.schema import Finding, Package
from sca.report import tickets as tk
from sca.report.graph_png import draw_graph
from sca.report.render import write_report
from sca.score.risk import Scored


def _scored(service, name, ver, vid, score, kev=False, epss=0.1):
    p = Package(ecosystem="pypi", name=name, version=ver, purl=f"pkg:pypi/{name}@{ver}", direct=True)
    f = Finding(service=service, package=p, vuln_id=vid, fix_versions=["9.9.9"], severity="High")
    return Scored(finding=f, cvss=7.5, cvss_version="3.1", cvss_source="nvd", epss=epss, epss_percentile=0.5,
                  epss_source="first.org", kev=kev, likelihood=epss, impact=1.0, score=score)


def _j(s: Scored, verdict, rule="r", seconds=1.0, hits=None):
    f = s.finding
    return Judgment(service=f.service, cve=f.vuln_id, package=f.package.key, verdict=verdict, rule=rule,
                    seconds=seconds, conditions=["uses ImageFont"] if verdict == "uncertain" else [],
                    evidence={"advisory_quote": "only when X is enabled", "code_hits": hits or []},
                    workaround="disable X")


@pytest.fixture
def world():
    sc = [_scored("svc-a", "pillow", "11.3.0", "CVE-2025-0001", 5.0, kev=True),
          _scored("svc-b", "pillow", "11.3.0", "CVE-2025-0001", 3.0),
          _scored("svc-a", "urllib3", "1.26.20", "CVE-2025-0002", 2.0),
          _scored("svc-b", "jinja2", "3.1.0", "GHSA-xxxx-yyyy-zzzz", 1.0)]
    js = [_j(sc[0], "affected", "in_range_unconditional", hits=[{"file": "app.py", "line": 3, "text": "import PIL",
                                                                  "symbol": "PIL"}]),
          _j(sc[1], "not_affected", "condition_absent", seconds=0.0),
          _j(sc[2], "uncertain", "condition_unknown"),
          _j(sc[3], "not_affected", "out_of_range", seconds=0.0)]
    fid = lambda s: finding_id(s.finding.service, s.finding.package.key, s.finding.vuln_id)  # noqa: E731
    plan = PlanResult(k=3, total_risk=7.0, covered_risk=7.0, coverage=1.0, actions=[
        Action(kind="upgrade", ecosystem="pypi", package="pillow", target_version="12.0.0",
               services=["svc-a", "svc-b"], from_versions=["11.3.0"], covers=[fid(sc[0]), fid(sc[1])],
               risk_covered=5.0, major_bump=True),
        Action(kind="remove", ecosystem="pypi", package="urllib3", services=["svc-a"],
               from_versions=["1.26.20"], covers=[fid(sc[2])], risk_covered=2.0)])
    assets = {"svc-a": Asset(exposure="internet", criticality=3, owner_team="인증플랫폼팀"),
              "svc-b": Asset(exposure="internal", criticality=1, owner_team="데이터분석팀")}
    osv = {"CVE-2025-0001": {"summary": "Pillow overflow in X"}}
    return sc, js, plan, assets, osv


class FakeLLM:
    is_local = False
    name = "fake@remote"

    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def structured(self, system, user, schema):
        self.calls.append(user)
        if self.fail:
            raise RuntimeError("down")
        return schema(summary="LLM 요약", impact="LLM 영향", steps=["a", "b"])


def test_ground_truth_missing_and_list(tmp_path):
    assert load_ground_truth(tmp_path / "nope.yaml") is None
    p = tmp_path / "gt.yaml"
    p.write_text("items:\n- {service: s, package: 'pypi:x@1', vuln_id: CVE-1, label: affected, reviewed: true}\n")
    gt = load_ground_truth(p)
    assert gt[0].key == ("s", "pypi:x@1", "CVE-1") and gt[0].reviewed


def test_evaluate_confusion(world):
    sc, js, *_ = world
    gt = [GTItem(service="svc-a", package="pypi:pillow@11.3.0", vuln_id="CVE-2025-0001", label="affected", reviewed=True),
          GTItem(service="svc-b", package="pypi:pillow@11.3.0", vuln_id="CVE-2025-0001", label="affected"),
          GTItem(service="svc-a", package="pypi:urllib3@1.26.20", vuln_id="CVE-2025-0002", label="uncertain",
                 reviewed=True),
          GTItem(service="zzz", package="pypi:q@1", vuln_id="CVE-9", label="affected")]
    ev = evaluate(js, gt)
    assert ev["matched"] == 3 and ev["accuracy"] == pytest.approx(2 / 3, abs=1e-3)
    assert ev["accuracy_reviewed_only"] == 1.0
    assert ev["confusion"]["matrix"]["affected"]["not_affected"] == 1
    assert ev["per_class"]["affected"]["recall"] == 0.5 and ev["per_class"]["affected"]["precision"] == 1.0
    assert len(ev["mismatches"]) == 1 and len(ev["missing"]) == 1
    assert evaluate(js, None)["available"] is False


def test_kpis(world, tmp_path):
    sc, js, plan, *_ = world
    m = kpis(sc, js, plan, evaluate(js, None), human_timing_path=tmp_path / "none.yaml")
    assert m["warning_reduction"]["by_finding"] == 0.5
    # CVE-2025-0001 is affected in svc-a → not counted as removed by unique vuln; GHSA is
    assert m["warning_reduction"]["by_unique_vuln"] == pytest.approx(1 / 3, abs=1e-3)
    # top-3 actions cover sc0 (5) + sc2 (2); sc1 is not_affected → excluded
    assert m["top3_risk_coverage"]["coverage"] == 1.0
    assert m["human_review_ratio"]["ratio"] == 0.25
    assert m["human_minutes_per_item"]["note"] == "미측정" and m["speedup"] is None
    assert m["agent_seconds_per_item"]["under_threshold"] == 2
    assert m["agent_seconds_per_item"]["cached_like"] == 0
    t = tmp_path / "h.yaml"
    t.write_text("items:\n- {id: a, minutes: 10}\n- {id: b, minutes: 20}\n")
    m2 = kpis(sc, js, plan, None, human_timing_path=t)
    assert m2["human_minutes_per_item"]["mean"] == 15 and m2["speedup"] == pytest.approx(15 * 60 / 0.5)
    p = write_metrics(m2, tmp_path / "m.json")
    assert json.loads(p.read_text())["speedup"] == m2["speedup"]


def test_tickets_public_only_and_cache(world, tmp_path):
    sc, js, plan, assets, osv = world
    llm = FakeLLM()
    paths = tk.write_tickets(plan, sc, js, osv, llm, out_dir=tmp_path / "t", assets=assets, cache_dir=tmp_path / "c")
    assert [p.name for p in paths] == ["T01-upgrade-pypi-pillow.md", "T02-remove-pypi-urllib3.md"]
    prompt = "\n".join(llm.calls)
    for internal in ("svc-a", "svc-b", "인증플랫폼팀", "app.py", "5.0", "only when X"):
        assert internal not in prompt
    assert "CVE-2025-0001" in prompt and "Pillow overflow in X" in prompt
    md = paths[0].read_text()
    for s in ("LLM 요약", "svc-a, svc-b", "인증플랫폼팀", "app.py:3", "메이저 버전 변경", "python -m sca run",
              "python -m sca feedback add", "affected (in_range_unconditional)", "11.3.0 → 12.0.0"):
        assert s in md
    assert "삭제 pypi:urllib3" in paths[1].read_text()
    n = len(llm.calls)
    tk.write_tickets(plan, sc, js, osv, llm, out_dir=tmp_path / "t", assets=assets, cache_dir=tmp_path / "c")
    assert len(llm.calls) == n                      # served from cache


def test_tickets_fallback(world, tmp_path):
    sc, js, plan, assets, osv = world
    for llm in (None, FakeLLM(fail=True)):
        paths = tk.write_tickets(plan, sc, js, osv, llm, out_dir=tmp_path / "t", assets=assets,
                                 cache_dir=tmp_path / "c")
        md = paths[0].read_text()
        assert "12.0.0 이상으로 올려" in md and "서술 생성: template" in md
    assert not (tmp_path / "c").exists()          # failures are not cached


def test_graph_png_and_report(world, tmp_path):
    sc, js, plan, assets, osv = world
    g = nx.DiGraph()
    for s, a in assets.items():
        g.add_edge(f"team:{a.owner_team}", f"svc:{s}")
        g.nodes[f"team:{a.owner_team}"]["kind"] = "team"
    for r in sc:
        g.add_edge(f"svc:{r.finding.service}", f"pkg:{r.finding.package.key}", dependency="direct")
        g.add_edge(f"pkg:{r.finding.package.key}", f"vuln:{r.finding.vuln_id}")
    png = draw_graph(g, sc, js, path=tmp_path / "graph.png", top_n=3)
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    from PIL import Image
    assert Image.open(png).size == (1600, 1000)
    first = png.read_bytes()
    draw_graph(g, sc, js, path=png, top_n=3)
    assert png.read_bytes() == first                # deterministic

    tickets = tk.write_tickets(plan, sc, js, osv, None, out_dir=tmp_path / "tickets", assets=assets)
    rows = [{"rank": i + 1, "service": r.finding.service, "owner_team": assets[r.finding.service].owner_team,
             "ecosystem": "pypi", "package": r.finding.package.name, "version": r.finding.package.version,
             "dependency": "direct", "vuln_id": r.finding.vuln_id, "cvss": r.cvss, "epss": "0.1", "kev": r.kev,
             "score": r.score, "fix_version": "9.9.9"} for i, r in enumerate(sc)]
    m = kpis(sc, js, plan, None, human_timing_path=tmp_path / "x.yaml")
    rep = write_report(tmp_path / "report.md", gsum={"services": 2}, rows=rows, scored=sc, judgments=js,
                       plan=plan, metrics=m, llm_name="fake", tickets=tickets)
    md = rep.read_text()
    for s in ("경고 감소율", "50.0%", "사람 검토 대기열 (1건)", "condition_unknown", "![graph](graph.png)",
              "tickets/T01-upgrade-pypi-pillow.md", "| condition_absent | 0 | 1 | 0 | 1 |"):
        assert s in md


# ── reviewer regressions ─────────────────────────────────────────────────────────────
def test_evaluate_loose_match_alias_and_duplicates(world):
    sc, js, *_ = world
    js[3].evidence = {**js[3].evidence, "advisory_id": "GHSA-real-alias"}
    gt = [GTItem(service="svc-a", package="PyPI:Pillow@11.3", vuln_id="CVE-2025-0001", label="affected"),
          GTItem(service="svc-b", package="pypi:jinja2@3.1.0", vuln_id="GHSA-real-alias", label="not_affected"),
          GTItem(service="svc-b", package="pypi:jinja2@3.1.0", vuln_id="GHSA-real-alias", label="affected"),
          GTItem(service="svc-a", package="pypi:pillow@11.3.1", vuln_id="CVE-2025-0001", label="affected")]
    ev = evaluate(js, gt)
    assert ev["n"] == 3 and len(ev["duplicates"]) == 1
    assert ev["matched"] == 2 and ev["accuracy"] == 1.0          # 11.3 == 11.3.0; GHSA alias found
    assert ev["missing"] == [{"service": "svc-a", "package": "pypi:pillow@11.3.1", "vuln_id": "CVE-2025-0001"}]


def test_kpis_cache_flags(world, tmp_path):
    sc, js, plan, *_ = world
    js[0].evidence = {**js[0].evidence, "judgment_cache": "hit"}     # keeps original seconds (1.0)
    a = kpis(sc, js, plan, None, human_timing_path=tmp_path / "n")["agent_seconds_per_item"]
    assert a["judgment_cache_hits"] == 1 and a["cached_like"] == 1 and a["under_threshold"] == 2


def test_markdown_safety(world, tmp_path):
    sc, js, plan, assets, osv = world
    js[2].conditions = ["uses a|b\nand more"]
    js[0].evidence = {"advisory_quote": "line1\nline2", "code_hits": [{"file": "a.py", "line": 1,
                                                                      "text": "x = `y`", "symbol": "y"}]}
    paths = tk.write_tickets(plan, sc, js, osv, None, out_dir=tmp_path / "tickets", assets=assets)
    md = paths[0].read_text()
    assert "\"line1 line2\"" in md and "x = `y`" not in md  # code text redacted, file:line only
    (tmp_path / "tickets" / "T09-stale.md").write_text("x")
    m = kpis(sc, js, plan, None, human_timing_path=tmp_path / "n")
    rep = write_report(tmp_path / "report.md", gsum={}, rows=[], scored=sc, judgments=js, plan=plan,
                       metrics=m, llm_name="x", tickets=[]).read_text()
    assert "uses a\\|b and more" in rep and "T09-stale" not in rep and "조치 티켓 (0건)" in rep
