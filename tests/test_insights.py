import json

from sca.contracts import Decision, Judgment
from sca.eval.groundtruth import GTItem
from sca.report import insights as ins


def _j(svc, pkg, vid, verdict, rule, by="code", **ev):
    return Judgment(service=svc, cve=vid, package=pkg, verdict=verdict, rule=rule, decided_by=by,
                    evidence={"advisory_quote": "", "code_hits": [], **ev})


def _gt(svc, pkg, vid, label):
    return GTItem(service=svc, package=pkg, vuln_id=vid, label=label)


JS = [
    _j("a", "pypi:x@1.0", "V1", "uncertain", "reachable_via_dependency"),
    _j("a", "pypi:x@1.0", "V2", "uncertain", "transitive_needs_callgraph"),
    _j("a", "pypi:y@2.0", "V3", "uncertain", "input_trust_needs_human"),
    _j("a", "pypi:y@2.0", "V4", "uncertain", "condition_not_checkable"),
    _j("a", "pypi:y@2.0", "V5", "uncertain", "llm_unavailable"),
    _j("a", "pypi:z@3.0", "V6", "not_affected", "api_not_referenced"),
    _j("b", "pypi:z@3.0", "V6", "not_affected", "api_not_referenced"),
    _j("b", "npm:u@7.0", "V7", "not_affected", "feedback_suppressed", by="feedback"),
    _j("a", "npm:u@7.0", "V7", "not_affected", "feedback_suppressed", by="feedback"),
    _j("b", "pypi:w@1.0", "V8", "affected", "unconditional_version_match"),
]


def test_hold_breakdown_categories_and_estimate():
    gt = [_gt("a", "pypi:x@1.0", "V1", "not_affected"), _gt("a", "pypi:x@1.0", "V2", "uncertain")]
    r = ins.hold_breakdown(JS, gt)
    assert r["total"] == 10 and r["uncertain"] == 5
    cats = {c["category"]: c for c in r["categories"]}
    assert cats[ins.CALLGRAPH]["count"] == 2
    assert cats[ins.INPUT_TRUST]["rules"] == {"input_trust_needs_human": 1}
    # unknown rule kept, not dropped
    assert cats[ins.NOT_CHECKABLE]["rules"] == {"condition_not_checkable": 1, "llm_unavailable": 1}
    assert sum(c["count"] for c in r["categories"]) == 5
    est = r["estimate"]
    assert est["label"] == "추정"
    assert est["upper_bound"]["uncertain_after"] == 3 and est["upper_bound"]["review_rate"] == 0.3
    g = est["grounded"]
    assert (g["gt_items"], g["gt_decidable"]) == (2, 1)
    assert g["uncertain_after"] == 4.0 and g["review_rate"] == 0.4
    assert ins.hold_breakdown(JS)["estimate"]["grounded"] is None


def test_automation_kpis():
    core = [_gt("b", "pypi:w@1.0", "V8", "affected"), _gt("a", "pypi:z@3.0", "V6", "affected"),
            _gt("b", "npm:u@7.0", "V7", "not_affected"), _gt("a", "pypi:x@1.0", "V1", "not_affected")]
    k = ins.automation_kpis(JS, core)
    assert k["auto_decided"] == 3 and k["auto_rate"] == 0.3
    assert k["auto_decided_with_feedback"] == 5 and k["hold_rate"] == 0.5
    assert k["misjudged"]["text"] == "1/2"
    assert k["misjudged"]["wrong_keys"] == ["a|pypi:z@3.0|V6"]
    assert k["misjudged_with_feedback"]["text"] == "1/3"
    assert k["baseline"]["accuracy"] == 0.5 and k["test_n"] == 4


def test_fileline_strips_code():
    assert ins.fileline("pkg/a.py:12: from x import y") == "pkg/a.py:12"
    assert ins.fileline("[dep] mod/b.py:3: code") == "mod/b.py:3"
    assert ins.fileline("garbage") is None


def test_showcase_not_affected(tmp_path):
    quote = "Only   apps calling Foo.bar are affected."
    (tmp_path / "GHSA-1.json").write_text(json.dumps(
        {"summary": "s", "details": "Intro. Only apps calling Foo.bar\nare affected. More."}))
    hi = Judgment(service="a", cve="V9", package="pypi:p@1.0", verdict="not_affected",
                  rule="api_not_referenced", conditions=["[api] must call Foo.bar (symbols: Foo.bar)"],
                  check_in_code="direct import of p: 3 hit(s); searched: service code (2 file(s) importing p)",
                  evidence={"advisory_quote": quote, "advisory_id": "GHSA-1", "quote_verified": True,
                            "import_hits": ["src/m.py:4: import p", "src/n.py:9: from p import q"],
                            "note": "[proactive] required API not referenced: ['Foo.bar']"})
    lo = _j("a", "pypi:q@1.0", "V10", "not_affected", "api_not_referenced")
    fb = _j("a", "pypi:r@1.0", "V11", "not_affected", "feedback_suppressed", by="feedback")
    rows = [{"service": "a", "ecosystem": "pypi", "package": n, "version": "1.0", "vuln_id": v, "cvss": c}
            for n, v, c in [("p", "V9", "8.1"), ("q", "V10", "5.0"), ("r", "V11", "9.9")]]
    r = ins.showcase_not_affected([lo, hi, fb], tmp_path, rows,
                                  gt=[_gt("a", "pypi:p@1.0", "V9", "not_affected")],
                                  core_keys={("a", "pypi:p@1.0", "V9")})
    assert r["vuln_id"] == "V9" and r["cvss"] == 8.1 and r["quote_in_osv"]
    assert r["evidence_fileline"] == ["src/m.py:4", "src/n.py:9"]
    assert all("import" not in x for x in r["evidence_fileline"])
    assert r["files_importing"] == 2 and r["import_hits_total"] == 3
    assert r["missing_symbols"] == ["Foo.bar"] and r["gt_set"] == "core"
    assert len(r["advisory_quote"]) <= 220 and "Foo.bar" in r["explanation"]
    assert ins.showcase_not_affected([fb], tmp_path, rows) is None


def test_clip_is_verbatim_prefix():
    q = "word " * 100
    c = ins._clip(q)
    assert len(c) <= 220 and c.endswith("…") and q.startswith(c[:-1])


def test_shared_judgment_kpis(tmp_path):
    fb = tmp_path / "d.jsonl"
    fb.write_text(Decision(service="a", package="npm:u", vuln_id="V7", decision="reject",
                           verdict="not_affected", reason="dev_only", scope="all_services",
                           at="2026-10-31T00:00:00Z").model_dump_json() + "\n")
    k = ins.shared_judgment_kpis(JS, fb)
    assert k["shared_pairs"] == 2 and k["shared_findings"] == 4 and k["shared_consistent"] == 2
    assert k["unique_pairs"] == 8 and k["judgments_saved"] == 2
    f = k["feedback"]
    assert f["decisions_all_services"] == 1 and f["rows_resolved"] == 2
    assert f["rows_other_services"] == 1 and f["services"] == ["a", "b"]
    assert ins.shared_judgment_kpis(JS, tmp_path / "missing.jsonl")["feedback"]["decisions_all_services"] == 0


def test_shared_feedback_counts_only_all_services_rows(tmp_path):
    p = tmp_path / "d.jsonl"
    rows = [Decision(service="a", package="npm:u", vuln_id="V7", decision="reject", verdict="not_affected",
                     reason="dev_only", scope="service", at="2026-01-01T00:00:00Z")]
    p.write_text("\n".join(r.model_dump_json() for r in rows) + "\n", encoding="utf-8")
    fb = ins.shared_judgment_kpis(JS, p)["feedback"]
    assert fb["decisions_all_services"] == 0 and fb["rows_resolved"] == 0 and fb["services"] == []
