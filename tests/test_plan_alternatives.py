from types import SimpleNamespace

from sca.contracts import Judgment, finding_id
from sca.ingest.schema import Finding, Package
from sca.plan.alternatives import analyze_plan, compat_alternative, fetch_pypi_index, shared_upgrades
from sca.plan.greedy import candidate_actions, plan_actions
from sca.score.risk import Scored


def S(svc, name, ver, vid, score, fixes=(), eco="pypi"):
    p = Package(ecosystem=eco, name=name, version=ver, purl=f"pkg:{eco}/{name}@{ver}")
    f = Finding(service=svc, package=p, vuln_id=vid, fix_versions=list(fixes))
    return Scored(finding=f, cvss=5, cvss_version="3.1", cvss_source="x", epss=None, epss_percentile=None,
                  epss_source="prior", kev=False, likelihood=0.1, impact=0.5, score=score)


def J(s, verdict, ranges=()):
    f = s.finding
    return Judgment(service=f.service, cve=f.vuln_id, package=f.package.key, verdict=verdict, rule="x",
                    affected_ranges=[list(r) for r in ranges])


def R(**kw):
    return {v: {"requires_python": rp, "yanked": y} for v, (rp, y) in kw.items()}


REL = {"1.0.0": ("", False), "1.2.0": ("", False), "1.3.0": ("", True), "1.4.0": (">=3.12", False),
       "1.2.5": ("", False), "1.5.0rc1": ("", False), "2.0.0": (">=3.10", False)}


def _setup(ranges_a=(("0", "1.2.5"),), ranges_b=(("0", "2.0.0"),)):
    a = S("svc", "lib", "1.0.0", "CVE-1", 3.0, ["1.2.5"])
    b = S("svc", "lib", "1.0.0", "CVE-2", 1.0, ["2.0.0"])
    js = [J(a, "uncertain", ranges_a), J(b, "affected", ranges_b)]
    plan = plan_actions([a, b], js, {}, k=1)
    _, w, _ = candidate_actions([a, b], js, {})
    return a, b, js, plan, w


def test_partial_alternative_same_major_runtime_ok():
    a, b, js, plan, w = _setup()
    act = plan.actions[0]
    assert act.target_version == "2.0.0"
    rels = {v: {"requires_python": rp, "yanked": y} for v, (rp, y) in REL.items()}
    out = compat_alternative(act, [a, b], js, w, {"svc": ["3.9.6"]}, rels)
    # 1.3.0 yanked, 1.4.0 needs 3.12, 1.5.0rc1 prerelease, 2.0.0 major → 1.2.5
    assert out["target"] == "1.2.5"
    assert out["fixes_findings"] == [finding_id("svc", "pypi:lib@1.0.0", "CVE-1")]
    assert out["risk_covered"] == 3.0 and out["risk_share_of_action"] == 0.75
    assert "1/2" in out["note"]


def test_no_alternative_reasons():
    a, b, js, plan, w = _setup(ranges_a=(("0", "2.0.0"),))
    rels = {v: {"requires_python": rp, "yanked": y} for v, (rp, y) in REL.items()}
    out = compat_alternative(plan.actions[0], [a, b], js, w, {"svc": ["3.9.6"]}, rels)
    assert out["target"] is None and out["best_compatible"] == "1.2.5"
    assert "1.x 계열 최신 1.2.5에도 수정 없음" in out["reason"] and "2.0.0" in out["reason"]
    # only same-line release needs newer Python
    rels2 = R(**{"1.4.0": (">=3.12", False), "2.0.0": (">=3.10", False)})
    out2 = compat_alternative(plan.actions[0], [a, b], js, w, {"svc": ["3.9.6"]}, rels2)
    assert out2["target"] is None and "Python >=3.12" in out2["reason"]
    # nothing newer in the line
    out3 = compat_alternative(plan.actions[0], [a, b], js, w, {"svc": ["3.9.6"]},
                              R(**{"2.0.0": (">=3.10", False)}))
    assert "마지막 릴리스가 현재 1.0.0" in out3["reason"] and "(Python >=3.10)" in out3["reason"]


def test_not_affected_excluded_and_version_not_string_compared():
    a = S("svc", "lib", "1.9.0", "CVE-1", 2.0, ["1.10.0"])
    n = S("svc", "lib", "1.9.0", "CVE-N", 9.0, ["1.10.0"])
    js = [J(a, "uncertain", [("0", "1.10.0")]), J(n, "not_affected", [("0", "1.10.0")])]
    plan = plan_actions([a, n], js, {}, k=1)
    _, w, _ = candidate_actions([a, n], js, {})
    out = compat_alternative(plan.actions[0], [a, n], js, w, {}, R(**{"1.10.0": ("", False)}))
    assert out["target"] == "1.10.0" and out["open_count"] == 1 and out["risk_share_of_action"] == 1.0


def test_npm_uses_fix_versions_major_only():
    a = S("x", "undici", "7.29.0", "CVE-1", 1.0, ["7.29.1", "8.10.2"], eco="npm")
    js = [J(a, "uncertain", [("7.0.0", "7.29.1"), ("8.0.0", "8.10.2")])]
    plan = plan_actions([a], js, {}, k=1)
    _, w, _ = candidate_actions([a], js, {})
    out = compat_alternative(plan.actions[0], [a], js, w, {}, None)
    assert out["target"] == "7.29.1" and out["fixes_count"] == 1


def test_shared_upgrades_and_top3_reasons():
    p1 = S("a", "lib", "1.0.0", "CVE-1", 5.0, ["1.1.0"])
    u1 = S("a", "dep", "2.0.0", "CVE-2", 1.0, ["2.1.0"])
    u2 = S("b", "dep", "2.0.0", "CVE-2", 1.0, ["2.1.0"])
    js = [J(p1, "affected"), J(u1, "uncertain"), J(u2, "uncertain")]
    plan = plan_actions([p1, u1, u2], js, {}, k=1)
    invs = [SimpleNamespace(service="a", packages=[p1.finding.package]),
            SimpleNamespace(service="b", packages=[Package(ecosystem="pypi", name="lib", version="1.1.0",
                                                           purl="pkg:pypi/lib@1.1.0")])]
    out = shared_upgrades(plan, [p1, u1, u2], js, {}, invs)
    top = out["top3"][0]
    assert top["package"] == "lib" and not top["shared"] and top["installed_in"] == ["a", "b"]
    assert "b(1.1.0)는 스캔 경고 없음" in top["reason"]
    best = out["best_shared"][0]
    assert best["package"] == "dep" and best["rank"] == 2 and best["services"] == ["a", "b"]
    assert best["services_cleared"] == ["a", "b"] and best["findings"] == 2
    assert best["risk_total"] == 2.0 and best["risk_share"] == round(2 / 7, 4)
    assert out["shared_count"] == 1 and out["candidate_count"] == 2
    out2 = shared_upgrades(plan, [p1, u1, u2], js, {}, None)
    assert out2["top3"][0]["reason"] == "lib는 a에만 설치됨"


def test_analyze_plan_injected():
    a, b, js, plan, _ = _setup()
    rels = {v: {"requires_python": rp, "yanked": y} for v, (rp, y) in REL.items()}
    res = analyze_plan(plan, [a, b], js, {}, [], offline=True, pythons={"svc": ["3.9.6"]},
                       index=lambda n, off: rels)
    assert set(res) == {"alternatives", "shared"}
    assert res["alternatives"][0]["target"] == "1.2.5"
    assert set(res["shared"]) == {"top3", "best_shared", "shared_count", "candidate_count"}


def test_fetch_index_offline_missing(tmp_path, monkeypatch):
    import sca.enrich.feeds as feeds
    monkeypatch.setattr(feeds, "CACHE_DIR", tmp_path)
    assert fetch_pypi_index("nonexistent-pkg", offline=True) == {}


def test_last_affected_falls_back_to_fix_versions():
    # OSV last_affected 1.1.0 is stored open-ended as [0, ""]; fix 1.2.0 must still count
    a = S("svc", "lib", "1.0.0", "CVE-9", 2.0, ["1.2.0"])
    j = J(a, "uncertain", (("0", ""),))
    j.evidence["last_affected"] = ["1.1.0"]
    plan = plan_actions([a], [j], {}, k=1)
    _, w, _ = candidate_actions([a], [j], {})
    out = compat_alternative(plan.actions[0], [a], [j], w, {"svc": ["3.9.6"]},
                             R(**{"1.2.0": ("", False), "1.3.0": ("", False)}))
    assert out["target"] == "1.3.0" and out["fixes_count"] == 1


def test_no_downgrade_for_newest_installed():
    a = S("s1", "lib", "1.0.0", "CVE-1", 1.0, ["1.6.0"])
    b = S("s2", "lib", "1.5.0", "CVE-1", 1.0, ["1.6.0"])
    js = [J(a, "uncertain"), J(b, "uncertain")]
    plan = plan_actions([a, b], js, {}, k=1)
    _, w, _ = candidate_actions([a, b], js, {})
    out = compat_alternative(plan.actions[0], [a, b], js, w, {},
                             R(**{"1.2.0": ("", False)}))
    assert out["target"] is None   # 1.2.0 would downgrade s2 (1.5.0)
