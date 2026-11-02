"""LLM request kwargs per model, trusted hosts, cache-only fallback; SBOM-only ingest (CycloneDX +
Grype/Trivy) without repo/manifests/venv; unsupported ecosystems never yield not_affected."""
import json
from pathlib import Path

import pytest

import sca.judge.conditions as C
import sca.judge.run as R
from sca.config import ComponentSpec, ServiceSpec
from sca.contracts import Action, AdvisoryConditions, Condition, PlanResult
from sca.ingest import inventory as inv_mod
from sca.ingest.inventory import build_inventory, dependency_class
from sca.ingest.parsers import parse_trivy
from sca.ingest.scan import needed_tools
from sca.llm import LLM, is_reasoning_model, request_kwargs
from sca.plan.greedy import plan_actions
from sca.score.risk import Scored

FIX = Path(__file__).parent / "fixtures"


# ── LLM ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("model,has_temp", [
    ("gpt-oss:20b", True), ("gemma4:12b", True), ("gpt-4.1", True), ("gpt-4o-mini", True),
    ("gpt-5", False), ("gpt-5.1", False), ("gpt-5-mini", False), ("o3", False), ("o4-mini", False),
    ("o1", False), ("openai/gpt-5.1", False), ("gpt-5-chat-latest", True)])
def test_request_kwargs_temperature_per_model(model, has_temp):
    kw = request_kwargs(model, reasoning="low", temperature=0.0)
    assert ("temperature" in kw) is has_temp
    assert kw["reasoning_effort"] == "low"
    assert "reasoning_effort" not in request_kwargs(model, reasoning="", temperature=0.0)
    assert "temperature" not in request_kwargs(model, "", temperature=None)


def test_llm_env_defaults_and_trusted_hosts(monkeypatch):
    for k in ("SCA_LLM_BASE_URL", "SCA_LLM_MODEL", "SCA_LLM_REASONING", "SCA_LLM_TEMPERATURE",
              "SCA_LLM_TRUSTED_HOSTS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("sca.llm._load_dotenv", lambda: None)
    llm = LLM()
    assert llm.is_local and llm.is_trusted and llm.name == "gpt-oss:20b@local"
    assert llm._extra() == {"reasoning_effort": "low", "temperature": 0.0}
    gpt5 = LLM(base_url="https://api.openai.com/v1", model="gpt-5.1", api_key="x")
    assert not gpt5.is_local and not gpt5.is_trusted and "temperature" not in gpt5._extra()
    # substring tricks do not count as local
    assert not LLM(base_url="https://evil.example/localhost/v1", api_key="x").is_local
    monkeypatch.setenv("SCA_LLM_TRUSTED_HOSTS", "llm.corp.example, 10.0.0.5")
    inhouse = LLM(base_url="https://imember.llm.corp.example/v1", api_key="x")
    assert inhouse.is_trusted and not inhouse.is_local
    assert LLM(base_url="http://10.0.0.5:8000/v1", api_key="x").is_trusted
    assert not LLM(base_url="https://api.openai.com/v1", api_key="x").is_trusted
    monkeypatch.setenv("SCA_LLM_TEMPERATURE", "0.2")
    assert LLM(model="gemma4:12b", api_key="x")._extra()["temperature"] == 0.2
    assert is_reasoning_model("o3-mini") and not is_reasoning_model("gpt-4.1")


class _Fake:
    def __init__(self, trusted=False, cache_only=False):
        self.is_local, self.is_trusted, self.cache_only = False, trusted, cache_only
        self.calls, self.system = 0, ""

    @property
    def name(self):
        return "fake@remote"

    def structured(self, system, user, schema):
        self.calls += 1
        self.system = system
        return AdvisoryConditions(vuln_id="", package="", unconditional=True, advisory_quote="x")


def _rec():
    return {"id": "GHSA-1", "summary": "s", "details": "Calling foo() crashes."}


def test_few_shot_for_trusted_inhouse_host(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "COND_CACHE", tmp_path)
    t = _Fake(trusted=True)
    C.extract_conditions("V", "pypi", "p", [], _rec(), t, examples=["NOTE"], use_cache=False)
    assert "NOTE" in t.system
    u = _Fake(trusted=False)
    C.extract_conditions("V", "pypi", "p", [], _rec(), u, examples=["NOTE"], use_cache=False)
    assert "NOTE" not in u.system


def test_cache_only_serves_cache_and_never_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "COND_CACHE", tmp_path)
    up = _Fake()
    c1, _ = C.extract_conditions("V", "pypi", "p", [], _rec(), up)          # fills the cache
    down = _Fake(cache_only=True)
    c2, meta = C.extract_conditions("V", "pypi", "p", [], _rec(), down)
    assert down.calls == 0 and meta["cached"] and c2 == c1
    c3, meta3 = C.extract_conditions("W", "pypi", "p", [], _rec(), down)    # cache miss
    assert c3 is None and down.calls == 0 and "unreachable" in meta3["error"]


def test_guard_stops_before_overwriting_outputs():
    from sca.contracts import Judgment
    from sca.pipeline import _guard_llm_unavailable
    j = Judgment(service="s", cve="V", package="pypi:p@1", verdict="uncertain", rule="llm_unavailable")
    _guard_llm_unavailable(None, [j])                       # --no-llm: allowed
    _guard_llm_unavailable(_Fake(cache_only=False), [j])     # backend up: allowed
    _guard_llm_unavailable(_Fake(cache_only=True), [])       # down but everything cached: allowed
    with pytest.raises(SystemExit):
        _guard_llm_unavailable(_Fake(cache_only=True), [j])


# ── SBOM-only ingest ────────────────────────────────────────────────────────────────
def _sbom_service(fmt: str, repo: str = "does/not/exist") -> ServiceSpec:
    vulns = FIX / ("min.trivy.json" if fmt == "trivy" else "min.grype.json")
    return ServiceSpec(name="finals-svc", repo=repo, components=[
        ComponentSpec(kind="sbom", sbom=str(FIX / "min.cdx.json"), vulns=str(vulns), vulns_format=fmt)])


def test_component_spec_sbom_requires_files():
    with pytest.raises(ValueError):
        ComponentSpec(kind="sbom", sbom="x.json")
    assert needed_tools([_sbom_service("grype")]) == []
    assert needed_tools([ServiceSpec(name="a", repo=".", components=[ComponentSpec(kind="python-reqs")])]) == \
        ["syft", "grype", "uv"]
    assert needed_tools([ServiceSpec(name="a", repo=".", components=[ComponentSpec(kind="npm-lock")])]) == \
        ["syft", "grype"]


@pytest.mark.parametrize("fmt", ["grype", "trivy"])
def test_sbom_only_inventory_uses_cyclonedx_edges(fmt, tmp_path, monkeypatch):
    monkeypatch.setattr(inv_mod, "RAW_DIR", tmp_path)          # no scan_index.json needed
    inv = build_inventory(_sbom_service(fmt))
    keys = {p.key for p in inv.packages}
    assert keys == {"maven:org.apache.logging.log4j/log4j-core@2.14.1",
                    "maven:org.apache.logging.log4j/log4j-api@2.14.1", "pypi:requests@2.25.0",
                    "pypi:urllib3@1.26.4"}
    cls = dependency_class(inv)
    assert cls["maven:org.apache.logging.log4j/log4j-core@2.14.1"] == "direct"
    assert cls["maven:org.apache.logging.log4j/log4j-api@2.14.1"] == "transitive"
    assert cls["pypi:urllib3@1.26.4"] == "transitive"
    ids = {(f.package.key, f.vuln_id) for f in inv.findings}
    assert ("maven:org.apache.logging.log4j/log4j-core@2.14.1", "CVE-2021-44228") in ids
    log4shell = next(f for f in inv.findings if f.vuln_id == "CVE-2021-44228")
    assert log4shell.fix_versions[0] == "2.15.0" and log4shell.package.direct
    assert any(c.base_score == 10.0 for c in log4shell.cvss)


def test_trivy_fixed_versions_split_and_filtered():
    fs = parse_trivy(FIX / "min.trivy.json", "s")
    f = next(x for x in fs if x.vuln_id == "CVE-2021-44228")
    assert f.fix_versions == ["2.15.0", "2.16.0"]            # "2.3.1" (older than 2.14.1) dropped
    assert f.severity == "Critical" and f.matcher == "trivy"
    u = next(x for x in fs if x.package.name == "urllib3")
    assert u.package.ecosystem == "pypi" and u.vuln_id == "CVE-2021-33503" and "GHSA-q2q7-5pp4-w6pg" in u.aliases


def _scored(f) -> Scored:
    return Scored(finding=f, cvss=9.0, cvss_version="3.1", cvss_source="t", epss=None, epss_percentile=None,
                  epss_source="prior", kev=False, likelihood=0.1, impact=0.5, score=1.0)


def test_sbom_without_edges_never_proposes_removal(tmp_path, monkeypatch):
    doc = json.loads((FIX / "min.cdx.json").read_text())
    doc.pop("dependencies")
    p = tmp_path / "noedges.cdx.json"
    p.write_text(json.dumps(doc))
    monkeypatch.setattr(inv_mod, "RAW_DIR", tmp_path)
    svc = ServiceSpec(name="s", repo="missing", components=[
        ComponentSpec(kind="sbom", sbom=str(p), vulns=str(FIX / "min.grype.json"))])
    inv = build_inventory(svc)
    cls = dependency_class(inv)
    assert set(cls.values()) == {"unknown"}
    scored = [_scored(f) for f in inv.findings]
    plan = plan_actions(scored, [], {"s": cls}, k=10)
    assert plan.actions and all(a.kind == "upgrade" for a in plan.actions)


def test_unsupported_ecosystem_is_never_not_affected(tmp_path, monkeypatch):
    """Log4Shell-style api condition on a maven package with a Java repo present: code search
    cannot see Java imports, so the row must stay uncertain in both modes."""
    monkeypatch.setattr(C, "COND_CACHE", tmp_path / "c")
    monkeypatch.setattr(R, "JUDGMENT_CACHE", tmp_path / "j.json")
    repo = tmp_path / "javarepo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "App.java").write_text(
        "import org.apache.logging.log4j.LogManager;\nclass App { void f(){ LogManager.getLogger().error(x); } }\n")
    monkeypatch.setattr(inv_mod, "RAW_DIR", tmp_path)
    svc = _sbom_service("grype", repo=str(repo))
    inv = build_inventory(svc)
    f = next(x for x in inv.findings if x.vuln_id == "CVE-2021-44228")
    cond = AdvisoryConditions(vuln_id="", package="", unconditional=False, advisory_quote="Logger.error",
                              conditions=[Condition(kind="api", description="logs attacker input",
                                                    symbols=["Logger.error"])])

    class L(_Fake):
        def structured(self, system, user, schema):
            return cond.model_copy(deep=True)
    osv = {"CVE-2021-44228": {"id": "GHSA-jfh8", "summary": "Logger.error with lookups",
                              "details": "Calling Logger.error with attacker data triggers JNDI lookups."}}
    for mode in ("proactive", "conservative"):
        js = R.judge_findings([_scored(f)], [svc], osv, L(), use_cache=False, mode=mode, verbose=False)
        assert js[0].verdict == "uncertain" and js[0].rule == "code_unavailable", (mode, js[0].rule)
        assert "not supported for maven" in js[0].check_in_code


def test_runtime_check_skips_missing_venv(monkeypatch, tmp_path):
    from sca import pipeline
    svc = ServiceSpec(name="s", repo=str(tmp_path / "gone"),
                      components=[ComponentSpec(kind="python-venv", venv=".venv")])
    a = Action(kind="upgrade", ecosystem="pypi", package="aiohttp", target_version="3.14.4", services=["s"],
               from_versions=["3.13.5"], covers=[], risk_covered=1.0)
    plan = PlanResult(k=1, total_risk=1.0, actions=[a], covered_risk=1.0, coverage=1.0)
    monkeypatch.setattr("sca.enrich.feeds.fetch_pypi_release", lambda *a, **k: {"requires_python": ">=3.10"})
    pipeline.runtime_check(plan, [svc], offline=True)         # must not raise
    assert not a.runtime_upgrade and not a.major_bump


def test_runtime_check_sets_runtime_flag_not_major(monkeypatch):
    from sca import pipeline
    svc = ServiceSpec(name="s", repo=".", components=[])
    a = Action(kind="upgrade", ecosystem="pypi", package="aiohttp", target_version="3.14.4", services=["s"],
               from_versions=["3.13.5"], covers=[], risk_covered=1.0)
    plan = PlanResult(k=1, total_risk=1.0, actions=[a], covered_risk=1.0, coverage=1.0)
    monkeypatch.setattr("sca.enrich.feeds.fetch_pypi_release", lambda *a, **k: {"requires_python": ">=3.10"})
    monkeypatch.setattr("sca.plan.alternatives.service_pythons", lambda svcs: {"s": ["3.9.6"]})
    pipeline.runtime_check(plan, [svc], offline=True)
    assert a.runtime_upgrade and not a.major_bump
    assert a.runtime_note == "Python 3.9.6 → >=3.10" and "런타임 업그레이드 필요" in a.note


# ── review fixes: name joins, fix_state, reasoning effort, mixed services ──────────────
def test_trivy_without_pkg_identifier_matches_cyclonedx_key(tmp_path):
    doc = json.loads((FIX / "min.trivy.json").read_text())
    for res in doc["Results"]:
        for v in res.get("Vulnerabilities", []):
            v.pop("PkgIdentifier", None)
    p = tmp_path / "old.trivy.json"
    p.write_text(json.dumps(doc))
    f = next(x for x in parse_trivy(p, "s") if x.vuln_id == "CVE-2021-44228")
    assert f.package.key == "maven:org.apache.logging.log4j/log4j-core@2.14.1"


def test_trivy_fix_state_needs_a_newer_fix(tmp_path):
    doc = json.loads((FIX / "min.trivy.json").read_text())
    v = next(v for r in doc["Results"] for v in r.get("Vulnerabilities", [])
             if v["VulnerabilityID"] == "CVE-2021-44228")
    v["FixedVersion"] = "2.3.1, 2.14.1"                       # none newer than installed 2.14.1
    p = tmp_path / "t.json"
    p.write_text(json.dumps(doc))
    f = next(x for x in parse_trivy(p, "s") if x.vuln_id == "CVE-2021-44228")
    assert f.fix_versions == [] and f.fix_state != "fixed"


def test_scoped_npm_name_comes_from_purl():
    from sca.ingest.parsers import make_package
    assert make_package("pkg:npm/%40babel/core@7.0.0", "core", "7.0.0").key == "npm:@babel/core@7.0.0"
    assert make_package("pkg:pypi/Pillow@10.0.0", "Pillow", "10.0.0").key == "pypi:pillow@10.0.0"


def test_gpt5_chat_gets_no_reasoning_effort(monkeypatch):
    monkeypatch.delenv("SCA_LLM_REASONING", raising=False)
    monkeypatch.setattr("sca.llm._load_dotenv", lambda: None)
    chat = LLM(base_url="https://api.openai.com/v1", model="gpt-5-chat-latest", api_key="x")
    assert "reasoning_effort" not in chat._extra()
    assert LLM(base_url="https://api.openai.com/v1", model="openai/gpt-5.1", api_key="x").reasoning == "low"


def test_unknown_class_only_for_edgeless_sbom_packages():
    from sca.ingest.schema import Edge, Package, ServiceInventory
    pk = lambda n, d=False: Package(ecosystem="pypi", name=n, version="1.0", purl=f"pkg:pypi/{n}@1.0", direct=d)
    inv = ServiceInventory(service="s", packages=[pk("a", True), pk("b"), pk("left"), pk("sb")],
                           edges=[Edge(parent="pypi:a@1.0", child="pypi:b@1.0")],
                           unknown_class=["pypi:sb@1.0"])
    cls = dependency_class(inv)
    assert cls == {"pypi:a@1.0": "direct", "pypi:b@1.0": "transitive",
                   "pypi:left@1.0": "unreferenced", "pypi:sb@1.0": "unknown"}
    # scanned service whose manifests give no direct deps: still 'unreferenced', not 'unknown'
    assert set(dependency_class(ServiceInventory(service="t", packages=[pk("x")])).values()) == {"unreferenced"}


def test_sbom_only_service_needs_no_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(inv_mod, "RAW_DIR", tmp_path)
    svc = ServiceSpec(name="finals-svc", components=[
        ComponentSpec(kind="sbom", sbom=str(FIX / "min.cdx.json"), vulns=str(FIX / "min.grype.json"))])
    assert not svc.repo_path.exists()
    assert build_inventory(svc).findings
    with pytest.raises(ValueError):
        ServiceSpec(name="x", components=[ComponentSpec(kind="python-reqs")])
