"""Human review sheet for the core ground-truth set: export → 사람이 판정·시간 기입 → import.

The sheet holds private code snippets, so it is local only (.gitignore). It deliberately leaves out
the agent's own verdict so the reviewer is not anchored by it."""
from __future__ import annotations

import glob
import json
import re
import statistics
from pathlib import Path

import yaml

from sca.config import CACHE_DIR, ROOT, ServiceSpec, load_services
from sca.eval.groundtruth import GT_PATH
from sca.eval.metrics import HUMAN_TIMING_PATH

REVIEW_PATH = ROOT / "data" / "eval" / "review_core.xlsx"
PUBLIC_GT_PATH = ROOT / "data" / "eval" / "ground_truth.public.yaml"
OSV_DIR = CACHE_DIR / "osv"
VERDICTS = ("affected", "not_affected", "uncertain")
REVIEWED_BY = "AI 초안 2회 + 본인 검수"
PUBLIC_FIELDS = ("id", "set", "service", "package", "vuln_id", "label", "ai_label", "labeled_by", "reviewed")
ADVISORY_MAX = 600

HEADERS = ["ID", "서비스", "패키지", "취약점", "권고문 요약/인용", "영향 버전 범위", "코드 근거",
           "AI 라벨", "AI 근거", "내 판정", "소요 시간(분)", "메모"]
WIDTHS = [7, 14, 24, 20, 60, 22, 70, 13, 60, 14, 12, 30]
COL = {h: i + 1 for i, h in enumerate(HEADERS)}

GUIDE = [
    "정답셋 검수 안내",
    "",
    "1. 한 행 = 한 건(서비스 × 패키지 × 취약점). '권고문'과 '영향 버전 범위'로 전제조건을 확인하고,",
    "   '코드 근거'(file:line + 실제 코드 1~2줄)와 필요하면 레포를 직접 열어 그 전제가 서비스에서 성립하는지 판단한다.",
    "2. '내 판정'에 드롭다운으로 하나를 고른다.",
    "   affected = 취약 버전이고 권고문의 전제(호출 경로·설정·입력)가 서비스에서 성립",
    "   not_affected = 버전은 범위 안이지만 전제가 성립하지 않음(취약 API 미사용, 플랫폼 다름, 개발 전용 등)",
    "   uncertain = 정적 근거만으로 결정 불가 → 실제 운영이라면 사람이 추가 확인할 건",
    "3. '소요 시간(분)': 그 행을 읽기 시작한 순간부터 판정을 고를 때까지의 분(소수 가능). 타이머를 건별로 재고 기록.",
    "   AI 라벨·근거를 먼저 보면 시간과 판단이 짧아지므로, 가능하면 권고문·코드 근거로 먼저 판단한 뒤 AI 칸과 비교.",
    "4. AI 라벨과 다르게 판정하면 '메모'에 이유를 한 줄 남긴다(공개 파일에는 메모가 실리지 않음).",
    "5. 다 채우면 저장하고 실행:  .venv/bin/python -m sca review import",
    "   → ground_truth.yaml(라벨·reviewed·labeled_by), ground_truth.public.yaml, human_timing.yaml 갱신.",
    "   이후 python -m sca run --skip-scan --offline 으로 지표를 재계산.",
    "",
    "주의: 이 파일에는 비공개 레포 코드가 들어 있으므로 커밋·공유하지 말 것(.gitignore 처리됨).",
]

_REF = re.compile(r"((?:~|/)?[\w.\-]*(?:/[\w.\-]+|/\.\.\.)*\.[A-Za-z]{1,5}):(\d+(?:\s*[-,]\s*\d+)*)")
_BARE = re.compile(r"(?:^|[\s;,(]):(\d+(?:[-,]\d+)*)")
_ADVISORY = re.compile(r"^(?:advisory\s+)?(?:GHSA-|CVE-|PYSEC-)", re.I)


# ---------- advisory ----------

def load_osv(osv_dir: Path = OSV_DIR) -> dict[str, dict]:
    """{id or alias: record} from the OSV cache."""
    out: dict[str, dict] = {}
    for f in sorted(glob.glob(str(Path(osv_dir) / "*.json"))):
        try:
            rec = json.loads(Path(f).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not rec.get("id"):
            continue
        out.setdefault(rec["id"], rec)
        for a in rec.get("aliases", []) or []:
            out.setdefault(a, rec)
    return out


def _split_key(pkg_key: str) -> tuple[str, str, str]:
    eco, rest = pkg_key.split(":", 1)
    name, _, ver = rest.rpartition("@") if "@" in rest[1:] else (rest, "", "")
    return eco, name, ver


def _norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco.lower() == "pypi" else name.lower()


def _sentences(text: str) -> list[str]:
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"^#+\s.*$", " ", text, flags=re.M)
    text = re.sub(r"[`*>]", "", text)
    parts = re.split(r"(?<=[.!?])\s+|\n\s*\n|\n[-*]\s", text)
    return [re.sub(r"\s+", " ", p).strip() for p in parts if len(p.strip()) > 20]


_COND = ("only", "when", "if ", "unless", "requires", "untrusted", "attacker", "affected", "exposed")


def advisory_excerpt(rec: dict | None, quotes: list[str], limit: int = ADVISORY_MAX) -> str:
    """OSV summary + the details sentences that best overlap the GT advisory quotes (or state conditions)."""
    if not rec:
        return "(OSV 캐시에 권고문 없음)"
    head = f"[{rec.get('id', '')}] {rec.get('summary', '').strip()}"
    qwords = {w for q in quotes for w in re.findall(r"[a-z_]{4,}", q.lower())}
    sents = _sentences(rec.get("details", "") or "")
    scored = []
    for i, s in enumerate(sents):
        words = set(re.findall(r"[a-z_]{4,}", s.lower()))
        score = len(words & qwords) + 2 * sum(c in s.lower() for c in _COND)
        scored.append((score, i, s))
    picked: list[tuple[int, str]] = []
    budget = limit - len(head) - 2
    for score, i, s in sorted(scored, key=lambda t: (-t[0], t[1])):
        if score <= 0 or len(picked) >= 3:
            break
        s = s if len(s) <= 260 else s[:257] + "…"
        if len(s) + 3 > budget:
            continue
        picked.append((i, s))
        budget -= len(s) + 3
    body = " / ".join(s for _, s in sorted(picked))
    out = head + ("\n" + body if body else "")
    return out[:limit]


def affected_ranges(rec: dict | None, pkg_key: str) -> str:
    """OSV affected ranges for this package, e.g. '[0, 2.6.6)' — empty when not derivable."""
    if not rec:
        return ""
    eco, name, ver = _split_key(pkg_key)
    want = _norm(eco, name)
    spans: list[str] = []
    for aff in rec.get("affected", []) or []:
        p = aff.get("package", {}) or {}
        if _norm(p.get("ecosystem", ""), p.get("name", "")) != want or p.get("ecosystem", "").lower() != eco.lower():
            continue
        for r in aff.get("ranges", []) or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            lo = None
            for ev in r.get("events", []):
                if "introduced" in ev:
                    lo = ev["introduced"]
                elif "fixed" in ev:
                    spans.append(f"[{lo or '0'}, {ev['fixed']})")
                    lo = None
                elif "last_affected" in ev:
                    spans.append(f"[{lo or '0'}, {ev['last_affected']}]")
                    lo = None
            if lo is not None:
                spans.append(f"[{lo}, ∞)")
    if not spans:
        return ""
    return " ∪ ".join(dict.fromkeys(spans)) + (f"\n현재 설치: {ver}" if ver else "")


# ---------- code evidence ----------

def _refs(line: str) -> list[tuple[str, list[int]]]:
    """file:line references in one evidence line; a bare ':226' attaches to the preceding path."""
    out: list[tuple[str, list[int]]] = []
    last_end, last_path = 0, None
    for m in _REF.finditer(line):
        if last_path:
            for b in _BARE.finditer(line[last_end:m.start()]):
                out.append((last_path, _expand(b.group(1))))
        out.append((m.group(1), _expand(m.group(2))))
        last_end, last_path = m.end(), m.group(1)
    if last_path:
        for b in _BARE.finditer(line[last_end:]):
            out.append((last_path, _expand(b.group(1))))
    return out


def _expand(spec: str) -> list[int]:
    """'649-651' → [649, 650] (first two lines of a range), '678,693' → [678, 693]."""
    nums: list[int] = []
    for part in re.sub(r"\s", "", spec).split(","):
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit():
                nums += [int(a)] + ([int(a) + 1] if b.isdigit() and int(b) > int(a) else [])
        elif part.isdigit():
            nums.append(int(part))
    return nums


def _resolve(path: str, svc: ServiceSpec | None) -> Path | None:
    p = Path(path).expanduser()
    if p.is_absolute():
        return p if p.is_file() else None
    if svc is None:
        return None
    repo = svc.repo_path
    if "..." in path:
        pre, _, suf = path.partition("...")
        hits = glob.glob(str(repo / pre.strip("/") / "**" / suf.strip("/")), recursive=True)
        return Path(hits[0]) if hits else None
    for base in (repo, repo.parent):
        if (base / p).is_file():
            return base / p
    for c in svc.components:
        if c.venv:
            hits = glob.glob(str(repo / c.venv / "lib" / "python*" / "site-packages" / path))
            if hits:
                return Path(hits[0])
    return None


def _read_lines(f: Path, nums: list[int], width: int = 160) -> list[str]:
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for n in nums:
        if 1 <= n <= len(lines):
            s = lines[n - 1].strip()
            out.append(f"    {n}: {s[:width] + ('…' if len(s) > width else '')}")
    return out


def code_evidence(evidence: list[str], svc: ServiceSpec | None, max_snippet_lines: int = 10) -> str:
    """file:line evidence lines (+ local code snippet) first, then the other non-advisory checks (검색 결과 등)."""
    ref_blocks, others, seen = [], [], set()
    shown: set[tuple[Path, int]] = set()
    budget = max_snippet_lines
    for ev in evidence:
        ev = ev.strip()
        if not ev or _ADVISORY.match(ev) or ev in seen:
            continue
        seen.add(ev)
        refs = _refs(ev)
        if not refs:
            others.append(f"(확인) {ev}")
            continue
        block = [f"• {ev}"]
        for path, nums in refs:
            f = _resolve(path, svc)
            nums = [n for n in nums if (f, n) not in shown]
            if f is None or budget <= 0 or not nums:
                continue
            shown.update((f, n) for n in nums[:budget])
            snip = _read_lines(f, nums[:budget])
            budget -= len(snip)
            block += snip
        ref_blocks.append("\n".join(block))
    return "\n".join(ref_blocks + others)


# ---------- export ----------

def _load_gt_raw(gt_path: Path) -> tuple[str, dict]:
    text = Path(gt_path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if isinstance(data, list):
        data = {"items": data}
    return _leading_comments(text), data


def _leading_comments(text: str) -> str:
    out = []
    for ln in text.splitlines():
        if ln.startswith("#") or not ln.strip():
            out.append(ln)
        else:
            break
    return "\n".join(out).rstrip() + "\n" if out else ""


def _has_filled(path: Path) -> bool:
    from openpyxl import load_workbook
    try:
        ws = load_workbook(path, read_only=True)["검수"]
    except Exception:  # noqa: BLE001 - unreadable/foreign file: let the caller decide
        return False
    return any(r[COL["내 판정"] - 1] not in (None, "") for r in ws.iter_rows(min_row=2, values_only=True))


def export_review(path: Path = REVIEW_PATH, gt_path: Path = GT_PATH, osv_dir: Path = OSV_DIR,
                  services: list[ServiceSpec] | None = None, force: bool = False) -> dict:
    """Write the review .xlsx for set=core. Returns {path, rows, snippets, missing_advisory}."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation

    path = Path(path)
    if path.exists() and not force and _has_filled(path):
        raise FileExistsError(f"{path} 에 이미 기입된 판정이 있음 — 덮어쓰려면 --force")
    _, data = _load_gt_raw(gt_path)
    core = [it for it in data.get("items", []) if it.get("set") == "core"]
    osv = load_osv(osv_dir)
    svcs = {s.name: s for s in (services if services is not None else load_services())}

    wb = Workbook()
    ws = wb.active
    ws.title = "검수"
    ws.append(HEADERS)
    hdr_fill = PatternFill("solid", fgColor="DDE4EE")
    you_fill = PatternFill("solid", fgColor="FFF6D5")
    for c in ws[1]:
        c.font = Font(bold=True)
        c.fill = hdr_fill
        c.alignment = Alignment(wrap_text=True, vertical="center")
    snippets, missing = 0, []
    for it in core:
        rec = osv.get(it["vuln_id"])
        if rec is None:
            missing.append(it["id"])
        quotes = [e for e in it.get("evidence", []) if _ADVISORY.match(e.strip())]
        code = code_evidence(it.get("evidence", []), svcs.get(it["service"]))
        snippets += sum(1 for ln in code.splitlines() if re.match(r"^\s{4}\d+: ", ln))
        ws.append([it["id"], it["service"], it["package"], it["vuln_id"], advisory_excerpt(rec, quotes),
                   affected_ranges(rec, it["package"]), code, it.get("label", ""), it.get("rationale", ""),
                   None, None, None])
    last = ws.max_row
    for row in ws.iter_rows(min_row=2, max_row=last):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
        for h in ("내 판정", "소요 시간(분)", "메모"):
            row[COL[h] - 1].fill = you_fill
    for i, w in enumerate(WIDTHS, start=1):
        ws.column_dimensions[ws.cell(1, i).column_letter].width = w
    ws.freeze_panes = "B2"
    if last >= 2:
        v_col = ws.cell(1, COL["내 판정"]).column_letter
        m_col = ws.cell(1, COL["소요 시간(분)"]).column_letter
        dv = DataValidation(type="list", formula1='"' + ",".join(VERDICTS) + '"', allow_blank=True,
                            showErrorMessage=True, errorTitle="판정", error="affected / not_affected / uncertain 중 선택")
        dm = DataValidation(type="decimal", operator="greaterThanOrEqual", formula1="0", allow_blank=True,
                            showErrorMessage=True, errorTitle="소요 시간", error="0 이상의 숫자(분)")
        ws.add_data_validation(dv)
        ws.add_data_validation(dm)
        dv.add(f"{v_col}2:{v_col}{last}")
        dm.add(f"{m_col}2:{m_col}{last}")
    g = wb.create_sheet("안내")
    for ln in GUIDE:
        g.append([ln])
    g["A1"].font = Font(bold=True, size=13)
    g.column_dimensions["A"].width = 120
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return {"path": str(path), "rows": len(core), "snippets": snippets, "missing_advisory": missing}


# ---------- import ----------

def _read_sheet(path: Path) -> list[dict]:
    from openpyxl import load_workbook
    ws = load_workbook(path, data_only=True)["검수"]
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    idx = {str(h).strip(): i for i, h in enumerate(rows[0]) if h is not None}
    need = ("ID", "내 판정", "소요 시간(분)")
    lost = [h for h in need if h not in idx]
    if lost:
        raise ValueError(f"검수 시트에 열 없음: {lost}")
    out = []
    for r in rows[1:]:
        rid = r[idx["ID"]]
        if rid in (None, ""):
            continue
        out.append({"id": str(rid).strip(), "verdict": r[idx["내 판정"]], "minutes": r[idx["소요 시간(분)"]],
                    "memo": r[idx["메모"]] if "메모" in idx else None})
    return out


def _dump(header: str, data: dict) -> str:
    return header + yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=160)


def public_items(items: list[dict]) -> list[dict]:
    """Public summary rows: identifiers + labels only (no rationale/evidence/memo: private code)."""
    return [{k: it[k] for k in PUBLIC_FIELDS if k in it} for it in items]


def import_review(path: Path = REVIEW_PATH, gt_path: Path = GT_PATH, public_path: Path = PUBLIC_GT_PATH,
                  timing_path: Path = HUMAN_TIMING_PATH) -> dict:
    """Apply filled rows → ground_truth.yaml, ground_truth.public.yaml, human_timing.yaml.
    Returns {reviewed, changed_labels:[{id, from, to}], timed, mean_minutes, missing_minutes, unfilled}."""
    rows = _read_sheet(Path(path))
    header, data = _load_gt_raw(gt_path)
    items = data.get("items", [])
    by_id = {it.get("id"): it for it in items}

    bad_verdict, bad_minutes, unknown = [], [], []
    filled: list[tuple[dict, str, float | None]] = []
    unfilled = []
    for r in rows:
        v = "" if r["verdict"] is None else str(r["verdict"]).strip().lower()
        if not v:
            unfilled.append(r["id"])
            continue
        if v not in VERDICTS:
            bad_verdict.append(f"{r['id']}({r['verdict']})")
            continue
        if r["id"] not in by_id:
            unknown.append(r["id"])
            continue
        m = r["minutes"]
        if m not in (None, ""):
            try:
                m = float(m)
            except (TypeError, ValueError):
                m = -1.0
            if m < 0:
                bad_minutes.append(f"{r['id']}({r['minutes']})")
                continue
        else:
            m = None
        filled.append((r, v, m))
    errs = []
    if bad_verdict:
        errs.append(f"알 수 없는 판정 {bad_verdict} — {'/'.join(VERDICTS)} 중 하나")
    if bad_minutes:
        errs.append(f"소요 시간이 0 이상 숫자가 아님 {bad_minutes}")
    if unknown:
        errs.append(f"ground_truth.yaml 에 없는 ID {unknown}")
    if errs:
        raise ValueError("; ".join(errs))

    changed, timing = [], {}
    for r, v, m in filled:
        it = by_id[r["id"]]
        ai = it.get("ai_label", it.get("label"))   # the original AI label survives re-imports
        if v != ai:
            changed.append({"id": r["id"], "from": ai, "to": v})
            it["ai_label"] = ai
            note = f"검수: AI 라벨 {ai} → {v}"
            it["review_note"] = note + (f" ({r['memo']})" if r["memo"] else "")
        else:
            it.pop("ai_label", None)
            if r["memo"]:
                it["review_note"] = str(r["memo"])
            else:
                it.pop("review_note", None)
        it["label"] = v
        it["reviewed"] = True
        it["labeled_by"] = REVIEWED_BY
        if m is not None:
            timing[r["id"]] = m

    Path(gt_path).write_text(_dump(header, data), encoding="utf-8")
    pub_path = Path(public_path)
    pub_header = _leading_comments(pub_path.read_text(encoding="utf-8")) if pub_path.exists() else \
        "# 공개용 요약: 근거(코드 인용)는 비공개 레포 내용이라 로컬 ground_truth.yaml 에만 있음\n"
    pub_path.write_text(_dump(pub_header, {"items": public_items(items)}), encoding="utf-8")
    _write_timing(Path(timing_path), timing)

    mins = list(timing.values())
    return {"reviewed": len(filled), "changed_labels": changed, "timed": len(mins),
            "mean_minutes": round(statistics.mean(mins), 2) if mins else None,
            "missing_minutes": [r["id"] for r, _, m in filled if m is None], "unfilled": unfilled}


def _write_timing(path: Path, timing: dict[str, float]) -> None:
    """Replace entries for the given ids, keep the rest and the header comments."""
    if path.exists():
        text = path.read_text(encoding="utf-8")
        header = _leading_comments(text)
        cur = (yaml.safe_load(text) or {}).get("items", []) or []
    else:
        header, cur = "# 정답셋 검수할 때 건별로 걸린 시간(분)을 기록. id 는 ground_truth.yaml 의 id.\n", []
    items = [it for it in cur if it.get("id") not in timing]
    items += [{"id": k, "minutes": (int(v) if float(v).is_integer() else v)} for k, v in timing.items()]
    path.write_text(_dump(header, {"items": items}), encoding="utf-8")
