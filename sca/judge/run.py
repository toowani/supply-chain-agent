"""Judge stage driver: one contracts.Judgment per Scored row (service, package.key, vuln_id).

    ranges (CODE, OSV) → conditions (LLM, public advisory text, once per vuln×package)
    → code search (CODE, service repo) → rules (CODE) → Judgment

`seconds` per judgment = this judgment's code wall time + the LLM extraction time of its
advisory amortized over the judgments sharing it (original measured time when cached).
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path
from typing import Callable

from sca.config import CACHE_DIR, WORK_DIR, ServiceSpec
from sca.contracts import AdvisoryConditions, CodeHit, Decision, Judgment, finding_id
from sca.judge.code_search import direct_import_hits, symbol_hits  # noqa: F401
from sca.judge.reach import reach
from sca.judge.conditions import PROMPT_VERSION, extract_conditions
from sca.judge.osv_ranges import RangeInfo, resolve
from sca.judge.rules import DEFAULT_RUNTIME, RuleInput, decide
from sca.score.risk import Scored

RULES_VERSION = 5          # 5: code_unavailable rule, unsupported-ecosystem gate, Korean evidence labels
# ecosystems whose import/usage the code search understands (sca/judge/code_search.py, reach.py);
# others (maven, golang, nuget, …) get no code verdict → uncertain/code_unavailable, never not_affected
SEARCHABLE = {"pypi", "npm"}
JUDGMENT_CACHE = CACHE_DIR / "judge" / "judgments.json"
Suppression = Callable[[str, str, str], Decision | None]


def service_venvs(svc: ServiceSpec) -> list[Path]:
    """python-venv: repo/<venv>; python-reqs: work/venvs/<service>."""
    out = []
    for c in svc.components:
        if c.kind == "python-venv" and c.venv:
            out.append(svc.repo_path / c.venv)
        elif c.kind == "python-reqs":
            out.append(WORK_DIR / "venvs" / svc.name)
    return out


def _imports(svc: ServiceSpec | None, ecosystem: str, name: str) -> tuple[bool | None, list[CodeHit]]:
    if svc is None or not svc.repo_path.is_dir():
        return None, []
    venvs = service_venvs(svc) if ecosystem == "pypi" else []
    hits: list[CodeHit] = []
    for v in venvs or [None]:
        hits = direct_import_hits(svc.repo_path, ecosystem, name, v)
        if hits:
            break
    return bool(hits), hits


def _fmt_hit(h: CodeHit) -> str:
    return f"{h.file}:{h.line}: {h.text}"


def _fmt_cond(c) -> str:
    extra = f" (symbols: {', '.join(c.symbols)})" if c.symbols else ""
    extra += f" (platforms: {', '.join(c.platforms)})" if c.platforms else ""
    return f"[{c.kind}] {c.description}{extra}"


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
                          .encode()).hexdigest()[:16]


def _load_cache() -> dict:
    try:
        return json.loads(JUDGMENT_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    JUDGMENT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    JUDGMENT_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")


def judge_findings(scored: list[Scored], services: list[ServiceSpec], osv: dict[str, dict], llm,
                   suppression: Suppression | None = None,
                   examples: list[str] | Callable[[str, str], list[str]] | None = None,
                   use_cache: bool = True, runtime: dict[str, list[str]] | None = None,
                   dependents: Callable[[str, str], list[tuple]] | None = None,
                   mode: str = "conservative",
                   verbose: bool = True) -> list[Judgment]:
    """Judge every Scored row. runtime: service -> platforms override (default linux+macos)."""
    svc_by = {s.name: s for s in services}
    cache = _load_cache() if use_cache else {}

    # 1) ranges per row + conditions once per unique (vuln_id, ecosystem:name)
    rows: list[tuple[Scored, RangeInfo, dict]] = []
    for s in scored:
        f = s.finding
        ri, rec = resolve(osv, [f.vuln_id, *f.aliases], f.package.ecosystem, f.package.name,
                          f.package.version)
        if not rec:                                   # no record covers the package: any text we have
            rec = next((osv[i] for i in [f.vuln_id, *f.aliases] if osv.get(i)), {})
        rows.append((s, ri, rec))
    users = Counter((s.finding.vuln_id, f"{s.finding.package.ecosystem}:{s.finding.package.name}")
                    for s, _, _ in rows)
    conds: dict[tuple[str, str], tuple[AdvisoryConditions | None, dict]] = {}

    out: list[Judgment] = []
    for n, (s, ri, rec) in enumerate(rows, 1):
        if verbose and (n % 10 == 0 or n == len(rows)):
            print(f"  judge {n}/{len(rows)}", flush=True)
        t0 = time.perf_counter()
        f, p = s.finding, s.finding.package
        name_key = f"{p.ecosystem}:{p.name}"
        ck = (f.vuln_id, name_key)
        decision = suppression(f.service, name_key, f.vuln_id) if suppression else None
        llm_secs = 0.0
        if ck not in conds and decision is None and ri.in_range is not False:
            conds[ck] = extract_conditions(f.vuln_id, p.ecosystem, p.name, ri.ranges, rec, llm,
                                           examples=examples(name_key, f.vuln_id) if callable(examples)
                                           else examples, use_cache=use_cache)
        c, meta = conds.get(ck, (None, {}))
        if ck in conds:
            llm_secs = float(meta.get("seconds", 0.0)) / users[ck]

        svc = svc_by.get(f.service)
        imported, imp_hits, sym_hits, dep_hits, searched, scopes, complete = None, [], [], [], False, [], False
        needs_code = (decision is None and ri.in_range is not False and c is not None
                      and not c.unconditional and c.conditions)
        code_note = ""
        if needs_code and p.ecosystem not in SEARCHABLE:
            code_note = f"code search not supported for {p.ecosystem}"
            needs_code = False
        elif needs_code and (svc is None or not svc.repo_path.is_dir()):
            code_note = "service repo not available"
        if needs_code:
            imported, imp_hits = _imports(svc, p.ecosystem, p.name)
            kinds = ("api",) if mode == "conservative" else ("api", "input")
            syms = [sym for k in c.conditions if k.kind in kinds for sym in k.symbols]
            if svc is not None and svc.repo_path.is_dir() and syms:
                venvs = service_venvs(svc) if p.ecosystem == "pypi" else []
                rr = reach(svc.repo_path, p.ecosystem, p.name, syms,
                           dependents(f.service, p.key) if dependents else [],
                           venvs[0] if venvs else None)
                sym_hits, dep_hits, searched, complete = rr.service_hits, rr.dependent_hits, True, rr.complete
                scopes = rr.searched + [f"미검색 {u}" for u in rr.unsearched[:5]]
        rt = (runtime or {}).get(f.service, DEFAULT_RUNTIME)

        fid = finding_id(f.service, p.key, f.vuln_id)
        h = _hash({"rules": RULES_VERSION, "prompt": PROMPT_VERSION, "ranges": ri.model_dump(),
                   "conditions": c.model_dump() if c else None, "imported": imported,
                   "hits": sorted(_fmt_hit(x) for x in sym_hits),
                   "dep_hits": sorted(_fmt_hit(x) for x in dep_hits), "complete": complete,
                   "qv": bool(meta.get("quote_verified", True)), "mode": mode,
                   "decision": decision.model_dump() if decision else None, "runtime": rt,
                   "code_note": code_note})
        hit = cache.get(f"{mode}|{fid}")
        if hit and hit.get("hash") == h:
            j = Judgment(**hit["judgment"])
            j.evidence = {**j.evidence, "judgment_cache": "hit"}
            out.append(j)
            continue

        r = decide(RuleInput(in_range=ri.in_range, conditions=c, imported=imported,
                             symbol_hits=sym_hits, dependent_hits=dep_hits, searched=searched,
                             complete=complete, quote_verified=bool(meta.get("quote_verified", True)),
                             mode=mode,
                             runtime=rt, decision=decision, code_note=code_note))
        checked = []
        if code_note:
            checked.append(f"코드 검색 불가: {code_note}")
        elif needs_code:
            checked.append(f"{p.name} 직접 import "
                           + ("확인 불가(레포 없음)" if imported is None else f"{len(imp_hits)}곳"))
            syms = sorted({sym for k in c.conditions if k.kind == "api" for sym in k.symbols})
            if syms:
                checked.append(f"API {syms}: 서비스 코드 {len(sym_hits)}곳, 의존 패키지 "
                               f"{len(dep_hits)}곳 · 검색 범위: {'; '.join(scopes)}")
        evidence = {
            "advisory_quote": c.advisory_quote if c else "",
            "code_hits": [_fmt_hit(x) for x in sym_hits],
            "dependent_hits": [_fmt_hit(x) for x in dep_hits[:8]],
            "import_hits": [_fmt_hit(x) for x in imp_hits[:5]],
            "advisory_id": ri.advisory_id or (rec.get("id", "") if rec else ""),
            "quote_verified": bool(meta.get("quote_verified", False)),
            "dropped_symbols": meta.get("dropped_symbols", []),
            "llm_model": c.model if c else "",
            "llm_cached": bool(meta.get("cached", False)),
            "llm_seconds": float(meta.get("seconds", 0.0)) if ck in conds else 0.0,
            "note": r.note,
        }
        if decision is not None:
            evidence["feedback_by"] = decision.by
        if ri.last_affected:
            evidence["last_affected"] = ri.last_affected
        if meta.get("error"):
            evidence["llm_error"] = meta["error"]
        if meta.get("no_advisory_text"):
            evidence["note"] += " (no OSV advisory text; scanner version match stands)"
        j = Judgment(
            service=f.service, cve=f.vuln_id, package=p.key, affected_ranges=ri.ranges,
            in_range=ri.in_range, conditions=[_fmt_cond(k) for k in c.conditions] if c else [],
            check_in_code="; ".join(checked), verdict=r.verdict, rule=r.rule,
            decided_by=r.decided_by, evidence=evidence, workaround=c.workaround if c else "",
            seconds=round(time.perf_counter() - t0 + llm_secs, 4),
        )
        out.append(j)
        if use_cache and r.rule != "llm_unavailable":
            cache[f"{mode}|{fid}"] = {"hash": h, "judgment": j.model_dump()}
    if use_cache:
        _save_cache(cache)
    return out


def rule_counts(judgments: list[Judgment]) -> dict[str, dict[str, int]]:
    """{'verdict': {...}, 'rule': {...}} for summaries."""
    return {"verdict": dict(Counter(j.verdict for j in judgments)),
            "rule": dict(Counter(j.rule for j in judgments))}
