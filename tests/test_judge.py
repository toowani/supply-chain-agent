from pathlib import Path

import pytest

import sca.judge.conditions as C
import sca.judge.run as R
from sca.config import ComponentSpec, ServiceSpec
from sca.contracts import AdvisoryConditions, CodeHit, Condition, Decision
from sca.ingest.schema import Finding, Package
from sca.judge import code_search as cs
from sca.judge.osv_ranges import range_info, resolve
from sca.judge.rules import RuleInput, decide
from sca.score.risk import Scored


# ── fixtures ────────────────────────────────────────────────────────────────────────
def rec(eco="PyPI", name="Pillow", events=None, versions=None, rid="GHSA-x"):
    return {"id": rid, "summary": "Pillow: crash in ImageFont.truetype on Windows",
            "details": "Calling `ImageFont.truetype` with a crafted font crashes. Only Windows.",
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": events or
                                      [{"introduced": "0"}, {"fixed": "10.2.0"}]}],
                          "versions": versions or []}]}


class FakeLLM:
    def __init__(self, out=None, local=True, fail=False):
        self.out, self.is_local, self.fail, self.calls, self.system = out, local, fail, 0, ""

    @property
    def name(self):
        return "fake@local" if self.is_local else "fake@remote"

    def structured(self, system, user, schema):
        self.calls += 1
        self.system, self.user = system, user
        if self.fail:
            raise ConnectionError("refused")
        return self.out.model_copy(deep=True)


def cond(kind, symbols=(), platforms=()):
    return Condition(kind=kind, description=kind, symbols=list(symbols), platforms=list(platforms))


def ac(*conds, unconditional=False):
    return AdvisoryConditions(vuln_id="V", package="p", unconditional=unconditional,
                              conditions=list(conds), advisory_quote="Only Windows.")


# ── ranges ──────────────────────────────────────────────────────────────────────────
def test_range_numeric_not_string():
    aff = rec(events=[{"introduced": "2.0"}, {"fixed": "2.10.0"}])["affected"]
    ri = range_info("A", aff, "pypi", "2.9.0")
    assert ri.ranges == [["2.0", "2.10.0"]] and ri.in_range is True
    assert range_info("A", aff, "pypi", "2.10.0").in_range is False
    assert range_info("A", aff, "pypi", "1.9").in_range is False


def test_range_last_affected_and_open_and_semver():
    aff = rec(eco="npm", name="Foo", events=[{"introduced": "1.0.0"}, {"last_affected": "1.2.0"},
                                             {"introduced": "2.0.0-beta.1"}])["affected"]
    ri = range_info("A", aff, "npm", "1.2.0")
    assert ri.in_range is True and ri.last_affected == ["1.2.0"]
    assert ["2.0.0-beta.1", ""] in ri.ranges
    assert range_info("A", aff, "npm", "1.3.0").in_range is False
    assert range_info("A", aff, "npm", "3.0.0").in_range is True


def test_range_explicit_versions_and_none():
    aff = [{"package": {"ecosystem": "PyPI", "name": "x"}, "versions": ["1.0", "1.1"]}]
    assert range_info("A", aff, "pypi", "1.1").in_range is True
    assert range_info("A", aff, "pypi", "1.2").in_range is False
    assert range_info("A", [{"package": {}}], "pypi", "1.2").in_range is None


def test_resolve_picks_alias_matching_package():
    osv = {"GHSA-a": rec(name="other"), "GHSA-b": rec(name="pillow", rid="GHSA-b")}
    ri, r = resolve(osv, ["CVE-1", "GHSA-a", "GHSA-b"], "pypi", "pillow", "10.0.0")
    assert ri.advisory_id == "GHSA-b" and ri.in_range is True and r["id"] == "GHSA-b"
    ri, r = resolve(osv, ["CVE-1"], "pypi", "pillow", "10.0.0")
    assert ri.in_range is None and r == {}
    # npm ecosystem must not match a PyPI record of the same name
    assert resolve({"G": rec(name="pillow")}, ["G"], "npm", "pillow", "1.0.0")[0].in_range is None


# ── code search ─────────────────────────────────────────────────────────────────────
@pytest.fixture
def repo(tmp_path):
    cs.clear_cache()
    (tmp_path / "app.py").write_text("import os, PIL.Image as I\nfrom yaml import safe_load\n"
                                     "x = I.open(p)\nfont = ImageFont.truetype(f)\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "a.ts").write_text("import { z } from 'zod/v4';\nconst q = require(\"qs\");\n"
                                           "await import('@scope/pkg');\nimport 'side-effect';\n"
                                           "a.download = 1; parse_qs(x)\n")
    (tmp_path / "package-lock.json").write_text('{"truetype": 1}')
    (tmp_path / "node_modules" / "zod").mkdir(parents=True)
    (tmp_path / "node_modules" / "zod" / "i.js").write_text("require('qs')")
    (tmp_path / "bin.py").write_bytes(b"import yaml\0\0")
    venv = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    (venv / "PyYAML-6.0.dist-info").mkdir(parents=True)
    (venv / "PyYAML-6.0.dist-info" / "top_level.txt").write_text("_yaml\nyaml\n")
    (venv / "Pillow-10.0.dist-info").mkdir()
    (venv / "Pillow-10.0.dist-info" / "RECORD").write_text(
        "PIL/__init__.py,,\nPIL/Image.py,,\nPillow-10.0.dist-info/METADATA,,\n../../bin/x,,\n")
    yield tmp_path
    cs.clear_cache()


def test_python_import_names_from_dist_info(repo):
    v = repo / ".venv"
    assert cs.python_import_names("pyyaml", v) == ["_yaml", "yaml"]
    assert cs.python_import_names("pillow", v) == ["PIL"]
    assert cs.python_import_names("typing-extensions", v) == ["typing_extensions"]


def test_direct_import_python(repo):
    v = repo / ".venv"
    assert [(h.file, h.line) for h in cs.direct_import_hits(repo, "pypi", "pillow", v)] == [("app.py", 1)]
    assert [(h.file, h.line) for h in cs.direct_import_hits(repo, "pypi", "pyyaml", v)] == [("app.py", 2)]
    assert cs.direct_import_hits(repo, "pypi", "requests", v) == []


def test_direct_import_npm(repo):
    for name, line in [("zod", 1), ("qs", 2), ("@scope/pkg", 3), ("side-effect", 4)]:
        hits = cs.direct_import_hits(repo, "npm", name)
        assert [(h.file, h.line) for h in hits] == [("web/a.ts", line)], name   # node_modules skipped
    assert cs.direct_import_hits(repo, "npm", "zo") == []


def test_symbol_hits_boundaries_locks_and_language(repo):
    hits = cs.symbol_hits(repo, ["ImageFont.truetype()", "PackageIndex.download", "parse_qs", "trueType"])
    got = {(h.symbol, h.file, h.line) for h in hits}
    assert ("ImageFont.truetype()", "app.py", 4) in got          # lock file not searched
    assert not any(h.symbol == "PackageIndex.download" for h in hits)  # 'download' too generic
    assert not any(h.symbol == "trueType" for h in hits)          # case-sensitive word match
    assert ("parse_qs", "web/a.ts", 5) in got
    assert not cs.symbol_hits(repo, ["parse_qs"], ecosystem="pypi")   # JS file skipped for PyPI
    assert all(len(h.text) <= 200 for h in hits)


# ── rules ───────────────────────────────────────────────────────────────────────────
HIT = CodeHit(file="a.py", line=3, text="x()", symbol="x")
DEC = Decision(service="s", package="pypi:p", vuln_id="V", decision="reject", verdict="not_affected",
               reason="not_reachable", at="2026-11-01T00:00:00Z")


@pytest.mark.parametrize("x,verdict,rule", [
    (RuleInput(True, ac(cond("api", ["x"])), True, [HIT], decision=DEC), "not_affected", "feedback_suppressed"),
    (RuleInput(False, None, None), "not_affected", "version_out_of_range"),
    (RuleInput(True, None, True), "uncertain", "llm_unavailable"),
    (RuleInput(True, ac(unconditional=True), False), "affected", "unconditional_version_match"),
    (RuleInput(None, ac(), False), "affected", "unconditional_version_match"),          # no condition stated
    (RuleInput(True, ac(cond("platform", platforms=["linux"])), False), "affected", "unconditional_version_match"),
    (RuleInput(True, ac(cond("platform", platforms=["Windows"]), cond("api", ["x"])), True, [HIT]),
     "not_affected", "platform_excluded"),
    (RuleInput(True, ac(cond("api", ["x"]), cond("config")), False, [HIT], searched=True),
     "affected", "condition_symbol_in_code"),
    (RuleInput(True, ac(cond("api", ["x"]), cond("platform", platforms=["darwin"])), True, searched=True,
               complete=True), "not_affected", "api_not_referenced"),
    # incomplete search or unverified quote never yields not_affected
    (RuleInput(True, ac(cond("api", ["x"])), True, searched=True, complete=False),
     "uncertain", "reachable_via_dependency"),
    (RuleInput(True, ac(cond("api", ["x"])), True, searched=True, complete=True, quote_verified=False),
     "uncertain", "reachable_via_dependency"),
    # conservative: one condition referenced, another not → not proof of absence
    (RuleInput(True, ac(cond("api", ["x"]), cond("api", ["y"])), True, [HIT], searched=True, complete=True),
     "uncertain", "reachable_via_dependency"),
    # negated platform text is not read as an OS restriction
    (RuleInput(True, ac(Condition(kind="platform", description="Affects all platforms except Windows.")), True),
     "uncertain", "condition_not_checkable"),
    # alternatives inside one condition: any symbol satisfies it
    (RuleInput(True, ac(cond("api", ["y", "x"])), True, [HIT], searched=True), "affected", "condition_symbol_in_code"),
    (RuleInput(True, ac(cond("api", ["x"]), cond("input")), True, [HIT], searched=True),
     "uncertain", "input_trust_needs_human"),
    (RuleInput(True, ac(cond("api", ["x"])), False, [], [HIT], searched=True),
     "uncertain", "reachable_via_dependency"),
    (RuleInput(True, ac(cond("api", ["x"])), False), "uncertain", "transitive_needs_callgraph"),
    (RuleInput(True, ac(cond("api", ["x"])), None), "uncertain", "code_unavailable"),   # no code to search
    (RuleInput(True, ac(cond("api", ["x"]), cond("input")), True), "uncertain", "condition_not_checkable"),
    (RuleInput(True, ac(cond("api")), True), "uncertain", "condition_not_checkable"),
])
def test_rules(x, verdict, rule):
    r = decide(x)
    assert (r.verdict, r.rule) == (verdict, rule)
    assert r.decided_by == ("feedback" if rule == "feedback_suppressed" else "code")


def test_platform_runtime_override():
    x = RuleInput(True, ac(cond("platform", platforms=["windows"])), False, runtime=["windows"])
    assert decide(x).rule == "unconditional_version_match"


# ── conditions ──────────────────────────────────────────────────────────────────────
def test_conditions_public_only_sanitize_and_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "COND_CACHE", tmp_path)
    out = ac(cond("api", ["ImageFont.truetype()", "invented_fn"]), cond("platform", platforms=[" Windows "]))
    llm = FakeLLM(out, local=False)
    r = rec()
    c, meta = C.extract_conditions("V", "pypi", "pillow", [["0", "10.2.0"]], r, llm,
                                   examples=["INTERNAL reviewer note"])
    assert "INTERNAL" not in llm.system                       # remote → no few-shot internals
    assert c.conditions[0].symbols == ["ImageFont.truetype"] and meta["dropped_symbols"] == ["invented_fn"]
    assert c.conditions[1].platforms == ["windows"] and meta["quote_verified"] is True
    assert c.model == "fake@remote" and c.vuln_id == "V"
    c2, meta2 = C.extract_conditions("V", "pypi", "pillow", [], r, llm)
    assert llm.calls == 1 and meta2["cached"] and c2 == c
    local = FakeLLM(out, local=True)
    C.extract_conditions("V", "pypi", "pillow", [], r, local, examples=["EX1"], use_cache=False)
    assert "EX1" in local.system


def test_conditions_llm_failure_and_no_text(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "COND_CACHE", tmp_path)
    c, meta = C.extract_conditions("V", "pypi", "p", [], rec(), FakeLLM(fail=True))
    assert c is None and "ConnectionError" in meta["error"] and not list(tmp_path.iterdir())
    c, _ = C.extract_conditions("V", "pypi", "p", [], {}, FakeLLM(fail=True))
    assert c.unconditional and c.model == "rule"


# ── end to end ──────────────────────────────────────────────────────────────────────
def _scored(service, name, version, vid="CVE-1", aliases=("GHSA-x",)):
    pkg = Package(ecosystem="pypi", name=name, version=version, purl=f"pkg:pypi/{name}@{version}")
    f = Finding(service=service, package=pkg, vuln_id=vid, aliases=list(aliases))
    return Scored(finding=f, cvss=7.0, cvss_version="3.1", cvss_source="t", epss=None, epss_percentile=None,
                  epss_source="prior", kev=False, likelihood=0.1, impact=0.5, score=5.0)


def test_judge_findings_end_to_end(repo, tmp_path_factory, monkeypatch):
    tmp_path = tmp_path_factory.mktemp("cache")              # outside the searched repo
    monkeypatch.setattr(C, "COND_CACHE", tmp_path / "c")
    monkeypatch.setattr(R, "JUDGMENT_CACHE", tmp_path / "j.json")
    svc = [ServiceSpec(name="a", repo=str(repo), components=[ComponentSpec(kind="python-venv", venv=".venv")]),
           ServiceSpec(name="b", repo=str(tmp_path / "missing"), components=[])]
    osv = {"GHSA-x": rec()}
    rows = [_scored("a", "pillow", "10.0.0"), _scored("b", "pillow", "10.0.0"), _scored("a", "pillow", "10.3.0")]
    llm = FakeLLM(ac(cond("api", ["ImageFont.truetype"])))
    js = R.judge_findings(rows, svc, osv, llm, verbose=False)
    assert llm.calls == 1                                       # once per (vuln, package)
    assert [(j.verdict, j.rule) for j in js] == [
        ("affected", "condition_symbol_in_code"), ("uncertain", "code_unavailable"),
        ("not_affected", "version_out_of_range")]
    assert js[0].evidence["code_hits"] == ["app.py:4: font = ImageFont.truetype(f)"]
    assert js[0].affected_ranges == [["0", "10.2.0"]] and js[0].package == "pypi:pillow@10.0.0"
    assert all(j.seconds >= 0 for j in js)
    # suppression + judgment cache
    sup = lambda s, p, v: DEC if (s, p, v) == ("a", "pypi:pillow", "CVE-1") else None
    js2 = R.judge_findings(rows, svc, osv, llm, suppression=sup, verbose=False)
    assert js2[0].rule == "feedback_suppressed" and js2[0].decided_by == "feedback"
    js3 = R.judge_findings(rows, svc, osv, llm, suppression=sup, verbose=False)
    assert all(j.evidence.get("judgment_cache") == "hit" for j in js3)
    # LLM down → uncertain, not cached
    js4 = R.judge_findings(rows[:2], svc, osv, FakeLLM(fail=True), use_cache=False, verbose=False)
    assert {j.rule for j in js4} == {"llm_unavailable"}


# ── review regressions ──────────────────────────────────────────────────────────────
def test_range_unparseable_version_is_unknown_not_out_of_range():
    aff = [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]
    assert range_info("A", aff, "npm", "git+https://example/x.git").in_range is None
    assert range_info("A", aff, "pypi", "weird!ver").in_range is None
    assert range_info("A", [{"versions": ["1.0"]}], "pypi", "weird!ver").in_range is None
    r = decide(RuleInput(None, ac(cond("input")), True))
    assert r.rule != "version_out_of_range"


@pytest.mark.parametrize("plats,verdict,rule", [
    (["node"], "uncertain", "condition_not_checkable"),       # environment, not an OS we exclude
    (["browser"], "uncertain", "condition_not_checkable"),
    (["windows", "node"], "not_affected", "platform_excluded"),
    (["unix"], "affected", "unconditional_version_match"),
])
def test_platform_environment_tokens_not_excluded(plats, verdict, rule):
    r = decide(RuleInput(True, ac(cond("platform", platforms=plats)), True))
    assert (r.verdict, r.rule) == (verdict, rule)
    r = decide(RuleInput(True, ac(cond("platform", platforms=["node"])), True, runtime=["linux", "node"]))
    assert r.verdict == "affected"


def test_conditions_cache_corrupt_and_text_change(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "COND_CACHE", tmp_path)
    llm = FakeLLM(ac(cond("api", ["ImageFont.truetype"])))
    C.extract_conditions("V", "pypi", "pillow", [], rec(), llm)
    (f,) = list(tmp_path.iterdir())
    f.write_text("{not json")
    c, meta = C.extract_conditions("V", "pypi", "pillow", [], rec(), llm)
    assert c is not None and not meta["cached"] and llm.calls == 2
    r2 = rec(); r2["details"] += " Also affects ImageFont.load."
    C.extract_conditions("V", "pypi", "pillow", [], r2, llm)
    assert llm.calls == 3                                       # edited advisory → re-extract
