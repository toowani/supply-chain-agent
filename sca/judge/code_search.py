"""Pure-Python search of a service repo: direct imports of a package and advisory symbols.

Results are internal data (service source code) → used by deterministic rules only, never put
into an LLM prompt. A call-graph engine is out of scope (roadmap "hybrid extension"); this is
grep-level evidence.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from sca.contracts import CodeHit
from sca.ingest.manifests import norm_pypi

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "work", "dist", "build", "__pycache__",
             ".claude", "site-packages", ".wrangler"}
EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".toml", ".yaml", ".yml",
        ".cfg", ".ini", ".sh", ".html", ".sql"}
JS_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html"}
# lock/manifests list package names, not usage → excluded from symbol search
LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
              "Pipfile.lock", "npm-shrinkwrap.json"}
MAX_BYTES = 1_000_000
MAX_TEXT = 200


@lru_cache(maxsize=32)
def _index(repo: str) -> tuple[tuple[str, str], ...]:
    """(relative path, text) of every searchable text file, cached per repo per process."""
    root = Path(repo)
    if not root.is_dir():
        return ()
    out = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in SKIP_DIRS and not p.name.endswith(".dist-info"):
                    stack.append(p)
                continue
            if p.suffix not in EXTS:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                raw = p.read_bytes()
            except OSError:
                continue
            if b"\0" in raw[:8192]:
                continue
            text = raw.decode("utf-8", errors="replace")
            out.append((p.relative_to(root).as_posix(), text))
    return tuple(sorted(out))


def clear_cache() -> None:
    _index.cache_clear()
    _import_names.cache_clear()


def _hit(rel: str, i: int, line: str, symbol: str) -> CodeHit:
    return CodeHit(file=rel, line=i, text=line.strip()[:MAX_TEXT], symbol=symbol)


def _line_at(text: str, pos: int) -> tuple[int, str]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text.count("\n", 0, pos) + 1, text[start: end if end >= 0 else len(text)]


# ── direct imports ──────────────────────────────────────────────────────────────────
def _site_packages(venv: Path) -> list[Path]:
    return sorted(venv.glob("lib/python*/site-packages")) + sorted(venv.glob("Lib/site-packages"))


@lru_cache(maxsize=1024)
def _import_names(dist_name: str, venv: Path | None) -> tuple[str, ...]:
    return tuple(python_import_names_uncached(dist_name, venv))


def python_import_names(dist_name: str, venv: Path | None = None) -> list[str]:
    """Top-level import names of an installed distribution (cached)."""
    return list(_import_names(dist_name, venv))


def python_import_names_uncached(dist_name: str, venv: Path | None = None) -> list[str]:
    """Top-level import names of an installed distribution (top_level.txt, else RECORD),
    fallback name.replace('-', '_')."""
    want = norm_pypi(dist_name)
    names: set[str] = set()
    for sp in _site_packages(venv) if venv else []:
        for di in sp.glob("*.dist-info"):
            dn = di.name[: -len(".dist-info")].rsplit("-", 1)[0]
            if norm_pypi(dn) != want:
                continue
            tl = di / "top_level.txt"
            if tl.exists():
                names |= {l.strip() for l in tl.read_text(errors="replace").splitlines() if l.strip()}
            rec = di / "RECORD"
            if not names and rec.exists():
                for row in rec.read_text(errors="replace").splitlines():
                    path = row.split(",", 1)[0]
                    first = path.split("/", 1)[0]
                    if (not first or first.startswith("..") or first.endswith((".dist-info", ".data", ".pth"))
                            or first == "__pycache__"):
                        continue
                    if "/" not in path and not first.endswith(".py"):
                        continue            # .so / data files at top level
                    names.add(first[:-3] if first.endswith(".py") else first)
    names = {n for n in names if n.isidentifier() and not n.startswith("_distutils")}
    return sorted(names) or [dist_name.replace("-", "_").replace(".", "_")]


_PY_FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import\b")
_PY_IMPORT = re.compile(r"^\s*import\s+(.+)$")


def _py_imported(line: str) -> list[str]:
    m = _PY_FROM.match(line)
    if m:
        return [m.group(1).split(".")[0]]
    m = _PY_IMPORT.match(line)
    if m:
        body = m.group(1).split("#", 1)[0]
        return [part.strip().split()[0].split(".")[0] for part in body.split(",") if part.strip()]
    return []


def _npm_pattern(name: str) -> re.Pattern:
    n = re.escape(name)
    return re.compile(r"""(?:require\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*|\bimport\s+)(['"`])"""
                      + n + r"""(?:/[^'"`]*)?\1""")


def direct_import_hits(repo: Path, ecosystem: str, package_name: str,
                       venv: Path | None = None) -> list[CodeHit]:
    """Lines of service code that import the package directly (python: import/from; npm:
    require('x') / from 'x' / import('x') / import 'x', subpaths 'x/...' included)."""
    hits: list[CodeHit] = []
    if ecosystem == "pypi":
        mods = set(python_import_names(package_name, venv))
        for rel, text in _index(str(repo)):
            if not rel.endswith(".py") or not any(m in text for m in mods):
                continue
            for i, line in enumerate(text.split("\n"), 1):
                for m in _py_imported(line):
                    if m in mods:
                        hits.append(_hit(rel, i, line, m))
                        break
    elif ecosystem == "npm":
        pat = _npm_pattern(package_name)
        for rel, text in _index(str(repo)):
            if Path(rel).suffix not in JS_EXTS or package_name not in text:
                continue
            for m in pat.finditer(text):
                i, line = _line_at(text, m.start())
                if not hits or (hits[-1].file, hits[-1].line) != (rel, i):
                    hits.append(_hit(rel, i, line, package_name))
    return hits


# ── advisory symbols ────────────────────────────────────────────────────────────────
def clean_symbol(s: str) -> str:
    s = s.strip().strip("`'\"")
    s = re.sub(r"\(.*\)$", "", s)          # "Image.open()" → "Image.open"
    return s.strip()


def _specific(name: str) -> bool:
    """snake_case / camelCase identifiers are specific enough to grep alone; plain words are not."""
    return len(name) >= 5 and ("_" in name.strip("_") or bool(re.search(r"[a-z][A-Z]", name)))


def symbol_patterns(symbol: str) -> list[str]:
    """Exact symbol; for dotted names also the last segment when it is a specific identifier
    (e.g. 'PIL.Image.frombuffer' → 'frombuffer' is not, 'tarfile.extract_all' → 'extract_all' is)."""
    s = clean_symbol(symbol)
    if len(s) < 3:
        return []
    out = [s]
    if "." in s:
        last = s.rsplit(".", 1)[1]
        if _specific(last) and last not in out:
            out.append(last)
    return out


OTHER_LANG = {"pypi": JS_EXTS, "npm": {".py"}}


def symbol_hits(repo: Path, symbols: list[str], cap: int = 5,
                ecosystem: str | None = None) -> list[CodeHit]:
    """Word-boundary matches of each symbol (≤cap hits per symbol). Lock files are excluded;
    with `ecosystem`, source files of the other language are skipped (a PyPI API name found in
    JS code is not a use of that API)."""
    hits: list[CodeHit] = []
    skip = OTHER_LANG.get(ecosystem or "", set())
    files = [(rel, text) for rel, text in _index(str(repo))
             if Path(rel).name not in LOCK_FILES and Path(rel).suffix not in skip]
    for sym in dict.fromkeys(symbols):
        found = 0
        for pat_s in symbol_patterns(sym):
            pat = re.compile(r"(?<![\w$])" + re.escape(pat_s) + r"(?![\w$])")
            for rel, text in files:
                if pat_s not in text:
                    continue
                last_line = 0
                for m in pat.finditer(text):
                    i, line = _line_at(text, m.start())
                    if i == last_line:
                        continue
                    last_line = i
                    hits.append(_hit(rel, i, line, sym))
                    found += 1
                    if found >= cap:
                        break
                if found >= cap:
                    break
            if found:
                break                         # exact matched → don't widen to last segment
    return hits


# ── installed-distribution metadata (dependents & import-name families) ───────────────
@lru_cache(maxsize=16)
def installed_requires(venv: Path) -> dict[str, frozenset[str]]:
    """{dist: names it requires} from every installed dist-info METADATA (markers and extras
    ignored on purpose: for 'who could call this package' over-inclusion is the safe side)."""
    from email.parser import Parser

    from packaging.requirements import InvalidRequirement, Requirement
    out: dict[str, frozenset[str]] = {}
    for sp in _site_packages(venv):
        for meta in sp.glob("*.dist-info/METADATA"):
            msg = Parser().parsestr(meta.read_text(encoding="utf-8", errors="replace"), headersonly=True)
            reqs = set()
            for r in msg.get_all("Requires-Dist") or []:
                try:
                    reqs.add(norm_pypi(Requirement(r).name))
                except InvalidRequirement:
                    pass
            out[norm_pypi(msg["Name"] or "")] = frozenset(reqs)
    return out


def family_import_names(dist_name: str, venv: Path | None) -> list[str]:
    """Import names of the distribution plus those of directly related distributions that ship
    the same project under another name (e.g. lightning ↔ pytorch-lightning → pytorch_lightning)."""
    names = set(python_import_names(dist_name, venv))
    if venv is None:
        return sorted(names)
    me = norm_pypi(dist_name)
    req = installed_requires(venv)
    related = set(req.get(me, ())) | {d for d, rs in req.items() if me in rs}
    for d in related:
        if me in d.split("-") or d in me.split("-"):
            names |= set(python_import_names(d, venv))
    return sorted(names)


DEP_SKIP_DIRS = {".git", "node_modules", "__pycache__", "tests", "test", "__tests__"}
DEP_MAX_BYTES = 60_000_000


@lru_cache(maxsize=256)
def index_installed(root: str) -> tuple[tuple[str, str], ...]:
    """Like _index but for an installed package dir: dist/ and build/ are its code, bundles can be
    large, nested node_modules are other packages (searched as their own dependents)."""
    base = Path(root)
    if not base.is_dir():
        return ()
    out, stack = [], [base]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in DEP_SKIP_DIRS:
                    stack.append(p)
                continue
            if p.suffix not in {".py", ".js", ".mjs", ".cjs"}:
                continue
            try:
                if p.stat().st_size > DEP_MAX_BYTES:
                    continue
                text = p.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                continue
            out.append((p.relative_to(base).as_posix(), text))
    return tuple(sorted(out))
