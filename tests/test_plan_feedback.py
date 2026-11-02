import json

from sca.contracts import Decision, Judgment, finding_id
from sca.feedback.cli import add_decision_from_args
from sca.feedback.history import latest_snapshot, rescan_verify, snapshot
from sca.feedback.store import FeedbackStore, pkg_name_key
from sca.feedback.vex import build_openvex, purl_of, write_openvex
from sca.ingest.schema import Finding, Package
from sca.plan.greedy import is_major_bump, plan_actions, rank_all_actions
from sca.score.risk import Scored


def S(svc, name, ver, vid, score, fixes=(), eco="pypi"):
    p = Package(ecosystem=eco, name=name, version=ver, purl=f"pkg:{eco}/{name}@{ver}")
    f = Finding(service=svc, package=p, vuln_id=vid, fix_versions=list(fixes))
    return Scored(finding=f, cvss=5, cvss_version="3.1", cvss_source="x", epss=None, epss_percentile=None,
                  epss_source="prior", kev=False, likelihood=0.1, impact=0.5, score=score)


def J(s, verdict, rule="x"):
    f = s.finding
    return Judgment(service=f.service, cve=f.vuln_id, package=f.package.key, verdict=verdict, rule=rule)


def fid(s):
    return finding_id(s.finding.service, s.finding.package.key, s.finding.vuln_id)


def test_major_bump():
    assert is_major_bump("pypi", "1.26.20", "2.6.3")
    assert not is_major_bump("pypi", "2.1.0", "2.10.0")
    assert is_major_bump("npm", "0.3.1", "0.4.0")
    assert not is_major_bump("npm", "0.3.1", "0.3.9")
    assert not is_major_bump("npm", "garbage", "1.0.0")


def test_upgrade_target_is_numeric_max_and_covers():
    a = S("svc1", "urllib3", "2.0.0", "CVE-1", 3.0, ["2.9.0"])
    b = S("svc2", "urllib3", "1.26.0", "CVE-2", 2.0, ["2.10.0"])
    r = plan_actions([a, b], [], {}, k=3)
    assert len(r.actions) == 1
    act = r.actions[0]
    assert act.target_version == "2.10.0"           # not "2.9.0" (string compare)
    assert act.services == ["svc1", "svc2"] and act.from_versions == ["1.26.0", "2.0.0"]
    assert act.major_bump and r.coverage == 1.0


def test_not_affected_excluded_and_greedy_order():
    a = S("s1", "pillow", "10.0", "CVE-A", 5.0, ["10.3"])
    b = S("s1", "jinja2", "3.0", "CVE-B", 4.0, ["3.1.5"])
    c = S("s2", "jinja2", "3.0", "CVE-C", 4.0, ["3.1.4"])
    d = S("s1", "pillow", "10.0", "CVE-D", 100.0, ["11.0"])
    r = plan_actions([a, b, c, d], [J(d, "not_affected"), J(a, "uncertain")], {}, k=1)
    assert r.total_risk == 13.0
    assert r.actions[0].package == "jinja2" and r.actions[0].target_version == "3.1.5"
    assert r.covered_risk == 8.0
    full = rank_all_actions([a, b, c, d], [J(d, "not_affected")], {})
    assert [x.package for x in full.actions] == ["jinja2", "pillow"] and full.coverage == 1.0
    assert abs(sum(x.risk_covered for x in full.actions) - full.covered_risk) < 1e-9


def test_remove_unreferenced_covers_unfixable():
    a = S("s1", "setuptools", "58.0.4", "CVE-S", 6.0, [])        # no fix
    b = S("s1", "nofix", "1.0", "CVE-N", 1.0, [])
    dep = {"s1": {"pypi:setuptools@58.0.4": "unreferenced", "pypi:nofix@1.0": "transitive"}}
    r = plan_actions([a, b], [], dep, k=3)
    assert r.actions[0].kind == "remove" and r.actions[0].services == ["s1"]
    assert "uninstall" in r.actions[0].note
    assert r.unfixable == [fid(b)]


def test_tie_break_fewer_services():
    a = S("s1", "bbb", "1.0", "CVE-1", 2.0, ["1.1"])
    b = S("s1", "aaa", "1.0", "CVE-2", 1.0, ["1.1"])
    c = S("s2", "aaa", "1.0", "CVE-3", 1.0, ["1.1"])
    r = plan_actions([a, b, c], [], {}, k=1)
    assert r.actions[0].package == "bbb"


def test_store_suppression_and_examples(tmp_path):
    st = FeedbackStore(tmp_path / "d.jsonl")
    add_decision_from_args("s1", "pypi:pillow@11.3.0", "CVE-1", "reject", "not_affected",
                           "not_reachable", "no ImageMath", store=st)
    assert st.suppression("s1", "pypi:pillow", "CVE-1").reason == "not_reachable"
    assert st.suppression("s2", "pypi:pillow", "CVE-1") is None
    st.add(Decision(service="s1", package="pypi:pillow", vuln_id="CVE-1", decision="approve",
                    verdict="affected", reason="fixed", at="2999-01-01T00:00:00Z"))
    assert st.suppression("s1", "pypi:pillow", "CVE-1") is None          # fixed never suppresses
    st.add(Decision(service="s9", package="pypi:pillow", vuln_id="CVE-2", decision="reject",
                    verdict="not_affected", reason="platform", scope="all_services",
                    at="2026-01-01T00:00:00Z"))
    assert st.suppression("s1", "pypi:pillow@1.0", "CVE-2").reason == "platform"
    st2 = FeedbackStore(tmp_path / "d.jsonl")                           # reload from disk
    assert len(st2.decisions()) == 3
    ex = st2.examples_for("pypi:pillow", "CVE-1", n=2)
    assert len(ex) == 2 and ex[0].startswith("pypi:pillow CVE-1")
    assert any("no ImageMath" in e for e in st2.examples_for("pypi:pillow", "CVE-1"))


def test_pkg_name_key():
    assert pkg_name_key("npm:@scope/x@1.2.3") == "npm:@scope/x"
    assert pkg_name_key("npm:@scope/x") == "npm:@scope/x"
    assert pkg_name_key("pypi:pillow@11.3.0") == "pypi:pillow"


def test_openvex(tmp_path):
    a = S("s1", "pillow", "11.3.0", "CVE-1", 1.0)
    b = S("s2", "pillow", "11.3.0", "CVE-1", 1.0)
    c = S("s1", "x", "1.0", "CVE-2", 1.0)
    js = [J(a, "not_affected", "api_not_referenced"), J(b, "not_affected", "version_out_of_range"),
          J(c, "uncertain")]
    doc = write_openvex(js, tmp_path / "v.json", "sca", timestamp="2026-11-01T00:00:00Z")
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0" and doc["@id"].startswith("urn:uuid:")
    assert json.loads((tmp_path / "v.json").read_text())["@id"] == doc["@id"]
    s1 = doc["statements"][0]
    assert s1["products"] == [{"@id": "pkg:pypi/pillow@11.3.0"}] and s1["status"] == "not_affected"
    assert s1["justification"] in {"vulnerable_code_not_in_execute_path", "vulnerable_code_not_present"}
    assert doc["statements"][1]["status"] == "under_investigation"
    assert "s1" not in json.dumps(doc)                                   # no service names
    assert build_openvex(js, "sca", "2026-11-02T00:00:00Z")["@id"] == doc["@id"]   # content-derived
    assert purl_of("npm:@a/b@1.0.0") == "pkg:npm/%40a/b@1.0.0"


def test_history_rescan(tmp_path):
    def row(svc, pkg, ver, vid, score):
        return {"service": svc, "ecosystem": "pypi", "package": pkg, "version": ver, "vuln_id": vid,
                "aliases": "", "score": score}
    prev = [row("s1", "pillow", "10.0", "CVE-1", 5.0), row("s1", "jinja2", "3.0", "CVE-2", 2.0)]
    snapshot("2026-11-01T00:00:00Z", prev, [], out_dir=tmp_path)
    assert latest_snapshot("2026-11-02T00:00:00Z", out_dir=tmp_path) is not None
    assert latest_snapshot("2026-11-01T00:00:00Z", out_dir=tmp_path) is None
    st = FeedbackStore(tmp_path / "d.jsonl")
    for pkg, vid in (("pypi:pillow", "CVE-1"), ("pypi:jinja2", "CVE-2")):
        add_decision_from_args("s1", pkg, vid, "approve", "affected", "fixed", store=st)
    cur = [row("s1", "jinja2", "3.0", "CVE-2", 2.0), row("s2", "x", "1", "CVE-3", 1.0)]
    res = rescan_verify(latest_snapshot(out_dir=tmp_path), cur, [], st)
    assert res["resolved"] == ["s1|pypi:pillow@10.0|CVE-1"] and len(res["new"]) == 1
    assert res["fixed_verified"] == 1 and res["fixed_not_verified"] == 1
    assert res["before"]["rows"] == 2 and res["before"]["score"] == 7.0 and res["after"]["score"] == 3.0


# ── reviewer regressions ─────────────────────────────────────────────────────────────
def test_backport_fix_versions_use_lowest_newer_fix():
    a = S("s1", "lib", "2.2.0", "CVE-1", 5.0, ["1.2.5", "2.3.1"])     # 1.2.5 is an older-branch fix
    b = S("s2", "lib", "1.2.0", "CVE-1", 3.0, ["1.2.5", "2.3.1"])
    r = rank_all_actions([a, b], [], {})
    assert r.unfixable == [] and r.coverage == 1.0
    assert r.actions[0].target_version == "2.3.1" and sorted(r.actions[0].covers) == sorted([fid(a), fid(b)])
    only_a = rank_all_actions([a], [], {})
    assert only_a.actions[0].target_version == "2.3.1" and not only_a.actions[0].major_bump


def test_suppression_latest_by_parsed_time_and_alias(tmp_path):
    st = FeedbackStore(tmp_path / "d.jsonl")
    base = dict(service="s1", package="pypi:p", decision="reject", scope="service")
    # 10:00+09:00 == 01:00Z is EARLIER than 02:00Z, though the string sorts later
    st.add(Decision(**base, vuln_id="GHSA-x", verdict="affected", reason="confirmed", at="2026-11-01T02:00:00Z"))
    st.add(Decision(**base, vuln_id="GHSA-x", verdict="not_affected", reason="platform",
                    at="2026-11-01T10:00:00+09:00"))
    assert st.suppression("s1", "pypi:p@1", "CVE-9", aliases=["GHSA-x"]).reason == "confirmed"
    assert st.suppression("s1", "pypi:p@1", "CVE-9") is None


def test_openvex_feedback_reason_and_accepted_risk():
    a = S("s1", "p", "1.0", "CVE-1", 1.0)
    b = S("s2", "p", "1.0", "CVE-1", 1.0)
    c = S("s1", "q", "1.0", "CVE-2", 1.0)
    ja = J(a, "not_affected", "feedback_suppressed")
    ja.decided_by, ja.evidence = "feedback", {"note": "reject by r at t (reason=accepted_risk, scope=service)"}
    jb = J(b, "not_affected", "version_out_of_range")
    jc = J(c, "not_affected", "feedback_suppressed")
    jc.decided_by, jc.evidence = "feedback", {"note": "reject by r at t (reason=dev_only, scope=service)"}
    st = {s["vulnerability"]["name"]: s for s in build_openvex([jb, ja, jc], "sca", "t")["statements"]}
    assert st["CVE-1"]["status"] == "affected"                       # accepted risk is not not_affected
    assert st["CVE-2"]["justification"] == "vulnerable_code_cannot_be_controlled_by_adversary"


def test_openvex_every_not_affected_rule_has_justification():
    """Every judge rule / reviewer reason that yields not_affected maps to an OpenVEX
    justification (a renamed rule once fell through to the generic fallback text)."""
    from sca.feedback.store import EFFECTIVE_REASONS
    from sca.judge.rules import RULE_ORDER
    na_rules = ["version_out_of_range", "platform_excluded", "api_not_referenced"]
    assert set(na_rules) <= set(RULE_ORDER)
    js = []
    for i, r in enumerate(na_rules):
        js.append(J(S("s1", f"p{i}", "1.0", f"CVE-{i}", 1.0), "not_affected", r))
    for i, reason in enumerate(sorted(EFFECTIVE_REASONS - {"accepted_risk", "confirmed"})):
        j = J(S("s1", f"q{i}", "1.0", f"CVE-9{i}", 1.0), "not_affected", "feedback_suppressed")
        j.decided_by, j.evidence = "feedback", {"note": f"reject by r at t (reason={reason}, scope=service)"}
        js.append(j)
    sts = build_openvex(js, "sca", "t")["statements"]
    assert len(sts) == len(js)
    for st in sts:
        assert st["status"] == "not_affected" and st.get("justification"), st
        assert "Determined not affected by rule" not in st["impact_statement"]


def test_openvex_marks_demo_feedback():
    j = J(S("s1", "p", "1.0", "CVE-1", 1.0), "not_affected", "feedback_suppressed")
    j.decided_by, j.evidence = "feedback", {"note": "reject by demo-reviewer at t (reason=dev_only, scope=all_services)"}
    st = build_openvex([j], "sca", "t")["statements"][0]
    assert "not a real review" in st["status_notes"]
    j.evidence = {"note": "x", "feedback_by": "kim"}
    assert "status_notes" not in build_openvex([j], "sca", "t")["statements"][0]


def test_rescan_fixed_needs_service_rescanned(tmp_path):
    st = FeedbackStore(tmp_path / "d.jsonl")
    add_decision_from_args("s1", "pypi:p", "CVE-1", "approve", "affected", "fixed", store=st)
    assert rescan_verify(None, [], [], st)["fixed_verified"] == 1
    res = rescan_verify(None, [], [], st, scanned_services=["s2"])
    assert res["fixed_not_verified"] == 1 and res["fixed_decisions"][0]["service_not_in_rescan"]
    assert rescan_verify(None, [], [], st, scanned_services=["s1"])["fixed_verified"] == 1
