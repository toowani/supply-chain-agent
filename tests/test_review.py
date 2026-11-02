import json

import pytest
import yaml
from openpyxl import load_workbook

from sca.config import ComponentSpec, ServiceSpec
from sca.eval import review as rv
from sca.eval.groundtruth import load_ground_truth

GT_HEADER = "# 판정 정답셋 헤더\n# 두 번째 줄\n"


@pytest.fixture
def env(tmp_path):
    repo = tmp_path / "svc"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "main.py").write_text("import x\nx.load_from_checkpoint(p)\nprint(1)\n", encoding="utf-8")
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "GHSA-aaaa-bbbb-cccc.json").write_text(json.dumps({
        "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1"], "summary": "RCE via checkpoint",
        "details": "Intro text that is fairly long here. Only affects apps that call load_from_checkpoint on untrusted files. "
                   "Unrelated trivia sentence about the project history.",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "LightNing"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.6.6"}]}]}],
    }), encoding="utf-8")
    items = [
        {"id": "G01", "set": "core", "service": "svc", "package": "pypi:lightning@2.6.0", "vuln_id": "CVE-2026-1",
         "label": "affected", "rationale": "호출됨", "labeled_by": "claude-draft", "reviewed": False,
         "evidence": ["GHSA-aaaa-bbbb-cccc: 'call load_from_checkpoint'", "app/main.py:2 x.load_from_checkpoint(p)",
                      "grep foo: no hits"], "agent_minutes": 3.0},
        {"id": "G02", "set": "core", "service": "svc", "package": "pypi:lightning@2.6.0", "vuln_id": "CVE-9",
         "label": "not_affected", "rationale": "미사용", "labeled_by": "claude-draft", "reviewed": False, "evidence": []},
        {"id": "G90", "set": "extra", "service": "svc", "package": "pypi:a@1", "vuln_id": "CVE-8",
         "label": "not_affected", "rationale": "secret code", "evidence": ["app/main.py:1"], "reviewed": False},
    ]
    gt = tmp_path / "ground_truth.yaml"
    gt.write_text(GT_HEADER + yaml.safe_dump({"items": items}, allow_unicode=True, sort_keys=False), encoding="utf-8")
    pub = tmp_path / "ground_truth.public.yaml"
    pub.write_text("# 공개 헤더\nitems: []\n", encoding="utf-8")
    timing = tmp_path / "human_timing.yaml"
    timing.write_text("# 시간 헤더\nitems:\n- {id: G02, minutes: 9}\n- {id: G90, minutes: 1}\n", encoding="utf-8")
    svc = ServiceSpec(name="svc", repo=str(repo), components=[ComponentSpec(kind="python-reqs")])
    return {"gt": gt, "pub": pub, "timing": timing, "osv": osv, "svcs": [svc], "xlsx": tmp_path / "r.xlsx"}


def _export(env, **kw):
    return rv.export_review(env["xlsx"], gt_path=env["gt"], osv_dir=env["osv"], services=env["svcs"], **kw)


def _fill(path, values):
    wb = load_workbook(path)
    ws = wb["검수"]
    for r in range(2, ws.max_row + 1):
        rid = ws.cell(r, rv.COL["ID"]).value
        if rid in values:
            v, m, memo = values[rid]
            ws.cell(r, rv.COL["내 판정"]).value = v
            ws.cell(r, rv.COL["소요 시간(분)"]).value = m
            ws.cell(r, rv.COL["메모"]).value = memo
    wb.save(path)


def test_export_core_only_no_agent_verdict(env):
    r = _export(env)
    assert r["rows"] == 2 and r["missing_advisory"] == ["G02"] and r["snippets"] == 1
    wb = load_workbook(env["xlsx"])
    assert wb.sheetnames == ["검수", "안내"]
    ws = wb["검수"]
    assert [c.value for c in ws[1]] == rv.HEADERS
    assert ws.freeze_panes == "B2"
    row = {h: ws.cell(2, rv.COL[h]).value for h in rv.HEADERS}
    assert row["ID"] == "G01" and row["내 판정"] is None
    assert "Only affects apps that call load_from_checkpoint" in row["권고문 요약/인용"]
    assert "trivia" not in row["권고문 요약/인용"]
    assert row["영향 버전 범위"].startswith("[0, 2.6.6)")
    assert "2: x.load_from_checkpoint(p)" in row["코드 근거"] and "(확인) grep foo" in row["코드 근거"]
    assert "GHSA-aaaa" not in row["코드 근거"]
    assert len(ws.data_validations.dataValidation) == 2


def test_refs_parsing():
    refs = rv._refs("pipeline/publish_reel.py:39 import requests; :226 requests.get(")
    assert refs == [("pipeline/publish_reel.py", [39]), ("pipeline/publish_reel.py", [226])]
    assert rv._refs("a/b.py:476-485 x")[0][1] == [476, 477]
    assert rv._refs("a/model.py:678,693 k")[0][1] == [678, 693]
    assert rv._refs("grep foo: no hits") == []


def test_export_refuses_to_overwrite_filled(env):
    _export(env)
    _fill(env["xlsx"], {"G01": ("affected", 2, None)})
    with pytest.raises(FileExistsError):
        _export(env)
    _export(env, force=True)


def test_import_updates_gt_public_timing(env):
    _export(env)
    _fill(env["xlsx"], {"G01": ("not_affected", 4.5, "체크포인트는 고정 리비전"), "G02": ("not_affected", None, None)})
    s = rv.import_review(env["xlsx"], gt_path=env["gt"], public_path=env["pub"], timing_path=env["timing"])
    assert s["reviewed"] == 2 and s["timed"] == 1 and s["mean_minutes"] == 4.5
    assert s["changed_labels"] == [{"id": "G01", "from": "affected", "to": "not_affected"}]
    assert s["missing_minutes"] == ["G02"] and s["unfilled"] == []

    text = env["gt"].read_text(encoding="utf-8")
    assert text.startswith(GT_HEADER)
    raw = {it["id"]: it for it in yaml.safe_load(text)["items"]}
    assert raw["G01"]["label"] == "not_affected" and raw["G01"]["ai_label"] == "affected"
    assert raw["G01"]["reviewed"] is True and raw["G01"]["labeled_by"] == rv.REVIEWED_BY
    assert "고정 리비전" in raw["G01"]["review_note"]
    assert raw["G90"]["reviewed"] is False and raw["G90"]["evidence"] == ["app/main.py:1"]
    assert len(load_ground_truth(env["gt"])) == 3

    pub_text = env["pub"].read_text(encoding="utf-8")
    assert pub_text.startswith("# 공개 헤더")
    pub = yaml.safe_load(pub_text)["items"]
    assert [p["id"] for p in pub] == ["G01", "G02", "G90"]
    assert all("evidence" not in p and "rationale" not in p and "review_note" not in p for p in pub)
    assert pub[0]["ai_label"] == "affected"

    t_text = env["timing"].read_text(encoding="utf-8")
    assert t_text.startswith("# 시간 헤더")
    t = {it["id"]: it["minutes"] for it in yaml.safe_load(t_text)["items"]}
    assert t == {"G02": 9, "G90": 1, "G01": 4.5}


def test_import_reverting_label_drops_ai_label(env):
    _export(env)
    _fill(env["xlsx"], {"G01": ("uncertain", 1, None)})
    rv.import_review(env["xlsx"], gt_path=env["gt"], public_path=env["pub"], timing_path=env["timing"])
    _fill(env["xlsx"], {"G01": ("affected", 1, None)})
    rv.import_review(env["xlsx"], gt_path=env["gt"], public_path=env["pub"], timing_path=env["timing"])
    g01 = yaml.safe_load(env["gt"].read_text(encoding="utf-8"))["items"][0]
    assert g01["label"] == "affected" and "ai_label" not in g01 and "review_note" not in g01


def test_reimport_same_sheet_is_idempotent(env):
    _export(env)
    _fill(env["xlsx"], {"G01": ("not_affected", 2, None)})
    kw = dict(gt_path=env["gt"], public_path=env["pub"], timing_path=env["timing"])
    s1 = rv.import_review(env["xlsx"], **kw)
    gt1 = env["gt"].read_text(encoding="utf-8")
    s2 = rv.import_review(env["xlsx"], **kw)
    assert s1 == s2 and s2["changed_labels"] == [{"id": "G01", "from": "affected", "to": "not_affected"}]
    assert env["gt"].read_text(encoding="utf-8") == gt1


def test_import_rejects_bad_input_without_writing(env):
    _export(env)
    before = env["gt"].read_text(encoding="utf-8")
    _fill(env["xlsx"], {"G01": ("maybe", 1, None), "G02": ("affected", -3, None)})
    with pytest.raises(ValueError) as e:
        rv.import_review(env["xlsx"], gt_path=env["gt"], public_path=env["pub"], timing_path=env["timing"])
    assert "G01" in str(e.value) and "G02" in str(e.value)
    assert env["gt"].read_text(encoding="utf-8") == before
