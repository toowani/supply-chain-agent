"""Approximate reachability without a call graph: a vulnerable API counts as referenced only in
files that import the vulnerable package — in the service's own code, or in the installed source
of the packages in that service that depend on it (its dependents). Plain words like `decode` are
then safe to search, and instance calls (`img.paste(`) match `Image.paste` via the last segment.

`complete` is False when a scope could not be inspected: a dependent that names the package
without a static import (dynamic/bundled use we cannot see), too many dependents, a missing repo
or an ecosystem this search does not support. Files skipped by the indexer (dist/, build/,
files over 1 MB) are not tracked. In conservative mode the rules never conclude not_affected
from an incomplete search; proactive mode (default) does not check `complete` — one unmet
api/input condition in the searched scopes is enough (see sca/judge/rules.py R4).
A real call graph (roadmap) would replace this; the rules only need `ReachResult`."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from sca.contracts import CodeHit
from sca.judge.code_search import (LOCK_FILES, OTHER_LANG, _hit, _index, _line_at, _npm_pattern,
                                   clean_symbol, family_import_names, index_installed)

MAX_DEPENDENTS = 60
SUPPORTED = {"pypi", "npm"}      # import detection exists only for these (see _importing)
CAP = 5


@dataclass
class ReachResult:
    service_hits: list[CodeHit] = field(default_factory=list)     # symbol in service code
    dependent_hits: list[CodeHit] = field(default_factory=list)   # symbol in a dependent's source
    searched: list[str] = field(default_factory=list)             # scopes searched (for evidence)
    unsearched: list[str] = field(default_factory=list)           # dependents we could not inspect

    @property
    def complete(self) -> bool:
        return not self.unsearched


def _patterns(symbol: str) -> list[re.Pattern]:
    s = clean_symbol(symbol)
    names = [s] if len(s) >= 3 else []
    if "." in s:
        last = s.rsplit(".", 1)[1]
        if len(last) >= 3:
            names.append(last)
    return [re.compile(r"(?<![\w$])" + re.escape(n) + r"(?![\w$])") for n in dict.fromkeys(names)]


def _importing(texts, ecosystem: str, package: str, venv: Path | None) -> set[str]:
    if ecosystem == "pypi":
        mods = family_import_names(package, venv)
        pat = re.compile(r"^\s*(?:from\s+(?:%s)(?:\.[\w.]+)?\s+import\b|import\s+[^#\n]*\b(?:%s)\b)"
                         % ("|".join(map(re.escape, mods)), "|".join(map(re.escape, mods))), re.M)
        return {rel for rel, t in texts if rel.endswith(".py") and pat.search(t)}
    pat = _npm_pattern(package)
    return {rel for rel, t in texts if package in t and pat.search(t)}


_LOW = re.compile(r"(^|/)(_?archive|old|backup|tests?|examples?)(/|$)|(^|/)test_[^/]*$", re.I)


def _low_priority(rel: str) -> bool:
    """Archived/test/example paths: still searched (a hit there still counts), listed last."""
    return bool(_LOW.search(rel))


def _search(texts, files: set[str], symbols: list[str], ecosystem: str, prefix: str = "") -> list[CodeHit]:
    skip = OTHER_LANG.get(ecosystem, set())
    pool = [(rel, t) for rel, t in texts
            if rel in files and Path(rel).name not in LOCK_FILES and Path(rel).suffix not in skip]
    pool.sort(key=lambda rt: _low_priority(rt[0]))   # stable: live code first, then archive/tests
    hits: list[CodeHit] = []
    for sym in dict.fromkeys(symbols):
        found = 0
        for pat in _patterns(sym):
            for rel, text in pool:
                for m in pat.finditer(text):
                    i, line = _line_at(text, m.start())
                    if not line.lstrip().startswith(("import ", "from ")):
                        hits.append(_hit(prefix + rel, i, line, sym))
                        found += 1
                    if found >= CAP:
                        break
                if found >= CAP:
                    break
            if found:
                break
    return hits


def reach(repo: Path | None, ecosystem: str, package: str, symbols: list[str],
          dependents: list[tuple], venv: Path | None = None) -> ReachResult:
    """dependents: [(label, installed source dir[, depth])] of packages in this service that
    require `package`; depth 1 = requires it directly (default)."""
    r = ReachResult()
    if not symbols:
        return r
    if ecosystem not in SUPPORTED:
        r.unsearched.append(f"{ecosystem} 코드 검색 미지원")
        return r
    if repo is None or not repo.is_dir():
        r.unsearched.append("서비스 레포 없음")
        return r
    texts = _index(str(repo))
    files = _importing(texts, ecosystem, package, venv)
    r.searched.append(f"서비스 코드({package} import 파일 {len(files)}개)")
    r.service_hits = _search(texts, files, symbols, ecosystem)
    groups: dict[str, list[tuple[Path, int]]] = {}
    for dep in dependents:
        label, src, depth = (*dep, 1)[:3]
        groups.setdefault(label, []).append((src.resolve(), depth))
    names = family_import_names(package, venv) if ecosystem == "pypi" else [package]
    for n_dep, (label, dirs) in enumerate(groups.items()):
        if n_dep >= MAX_DEPENDENTS:
            r.unsearched.append(f"{label}(의존 패키지 {MAX_DEPENDENTS}개 초과)")
            continue
        found_any, mentions = False, False
        for src, depth in dict.fromkeys(dirs):
            texts = index_installed(str(src))
            files = _importing(texts, ecosystem, package, venv)
            if files:
                found_any = True
                r.dependent_hits += _search(texts, files, symbols, ecosystem, prefix=f"[{label}] ")
            elif depth == 1 and any(n in t for _, t in texts for n in names):
                mentions = True
        if found_any:
            r.searched.append(label)
        elif mentions:   # names the package but no static import → dynamic/bundled use we can't follow
            r.unsearched.append(f"{label}({package} 언급, 정적 import 없음)")
    return r
