"""draw_top_path / top_path: single highest-risk chain figure."""
import networkx as nx
from PIL import Image

from sca.contracts import Judgment
from sca.ingest.schema import Finding, Package
from sca.report.graph_png import _split_key, _wrap_name, draw_top_path, top_path
from sca.score.risk import Scored


def _s(svc, eco, name, ver, vid, score, cvss=7.5):
    p = Package(ecosystem=eco, name=name, version=ver, purl=f"pkg:{eco}/{name}@{ver}")
    f = Finding(service=svc, package=p, vuln_id=vid)
    return Scored(finding=f, cvss=cvss, cvss_version="3.1", cvss_source="nvd", epss=0.02, epss_percentile=0.8,
                  epss_source="first.org", kev=False, likelihood=0.02, impact=1.0, score=score)


def _graph():
    g = nx.DiGraph()
    g.add_node("team:웹플랫폼팀", kind="team")
    for s in ("web", "api"):
        g.add_node(f"svc:{s}", kind="service")
        g.add_edge("team:웹플랫폼팀", f"svc:{s}", rel="owns")
    # web: direct npm dep → transitive scoped vulnerable package
    g.add_edge("svc:web", "pkg:npm:next@14.0.0", rel="uses", dependency="direct")
    g.add_edge("svc:web", "pkg:npm:@scope/vuln-lib@1.2.3", rel="uses", dependency="transitive")
    g.add_edge("pkg:npm:next@14.0.0", "pkg:npm:@scope/vuln-lib@1.2.3", rel="depends_on", services={"web"})
    # api: vulnerable package is itself direct
    g.add_edge("svc:api", "pkg:pypi:pillow@10.0.0", rel="uses", dependency="direct")
    return g


def _j(s, verdict):
    f = s.finding
    return Judgment(service=f.service, cve=f.vuln_id, package=f.package.key, verdict=verdict, rule="r")


def test_split_and_wrap():
    assert _split_key("npm:@scope/vuln-lib@1.2.3") == ("npm", "@scope/vuln-lib", "1.2.3")
    assert _wrap_name("@scope/very-long-package") == "@scope/\nvery-long-package"
    assert "\n" in _wrap_name("미디어서비스팀")
    assert _wrap_name("requests") == "requests"


def test_transitive_npm_chain_with_more(tmp_path):
    rows = [_s("web", "npm", "@scope/vuln-lib", "1.2.3", f"CVE-2026-{i}", 2.0 - i * 0.1) for i in range(6)]
    rows.append(_s("api", "pypi", "pillow", "10.0.0", "CVE-2026-99", 0.5))
    js = [_j(rows[0], "affected"), _j(rows[1], "not_affected")]
    tp = top_path(_graph(), rows, js)
    assert [c["label"] for c in tp["chain"]] == ["웹플랫폼팀", "web", "next", "@scope/vuln-lib"]
    assert [c["edge"] for c in tp["chain"]] == ["", "owns", "direct", "transitive"]
    assert [v["verdict"] for v in tp["vulns"]] == ["affected", "not_affected", "unjudged", "unjudged"]
    assert tp["more"] == 2 and tp["top"]["id"] == "CVE-2026-0"
    out = draw_top_path(_graph(), rows, js, out_path=tmp_path / "t.png")
    w, h = Image.open(out).size
    assert w > h > 0


def test_direct_vulnerable_package_chain_of_three(tmp_path):
    rows = [_s("api", "pypi", "pillow", "10.0.0", "CVE-2026-99", 3.0, cvss=9.8)]
    tp = top_path(_graph(), rows, [_j(rows[0], "uncertain")])
    assert [c["kind"] for c in tp["chain"]] == ["team", "service", "package"]
    assert tp["chain"][-1]["edge"] == "direct" and tp["chain"][-1]["vulnerable"]
    assert tp["more"] == 0 and len(tp["vulns"]) == 1
    assert draw_top_path(_graph(), rows, [], out_path=tmp_path / "d.png").exists()


def test_unreferenced_package():
    g = _graph()
    g.add_edge("svc:api", "pkg:pypi:orphan@1.0", rel="uses", dependency="unreferenced")
    rows = [_s("api", "pypi", "orphan", "1.0", "CVE-1", 9.0)]
    tp = top_path(g, rows, [])
    assert tp["chain"][-1]["edge"] == "unreferenced" and tp["chain"][-1]["label"] == "orphan"
