"""Read declared manifests: which packages are direct dependencies, npm dev flags and edges.
Scanners differ in how much of this they keep, so it is read from the source of truth here."""
from __future__ import annotations

import json
import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement


def norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def norm_npm(name: str) -> str:
    return name.lower()


def requirements_parse(path: Path) -> list[Requirement]:
    text = re.sub(r"\\\r?\n", " ", path.read_text(encoding="utf-8"))   # line continuations
    reqs = []
    for raw in text.splitlines():
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0]
        line = re.split(r"\s--?[a-z]", line, maxsplit=1)[0].strip()     # per-line options (--hash)
        if not line or line.startswith("-"):
            continue
        try:
            reqs.append(Requirement(line))
        except InvalidRequirement:
            continue
    return reqs


def requirements_direct(path: Path) -> list[str]:
    return [norm_pypi(r.name) for r in requirements_parse(path)]


_ENV_SNIPPET = """
import json, os, platform, sys
v = sys.version_info
print(json.dumps({
  "implementation_name": sys.implementation.name,
  "implementation_version": f"{v.major}.{v.minor}.{v.micro}",
  "os_name": os.name, "platform_machine": platform.machine(),
  "platform_release": platform.release(), "platform_system": platform.system(),
  "platform_version": platform.version(),
  "python_full_version": platform.python_version(),
  "platform_python_implementation": platform.python_implementation(),
  "python_version": ".".join(platform.python_version_tuple()[:2]),
  "sys_platform": sys.platform}))
"""


def venv_marker_env(venv: Path) -> dict[str, str]:
    import subprocess
    out = subprocess.run([str(venv / "bin" / "python"), "-c", _ENV_SNIPPET],
                         check=True, text=True, capture_output=True).stdout
    return json.loads(out)


def _installed_dists(venv: Path) -> dict[str, tuple[str, list[Requirement]]]:
    from email.parser import Parser
    dists = {}
    for meta in venv.glob("lib/python*/site-packages/*.dist-info/METADATA"):
        msg = Parser().parsestr(meta.read_text(encoding="utf-8", errors="replace"), headersonly=True)
        reqs = []
        for r in msg.get_all("Requires-Dist") or []:
            try:
                reqs.append(Requirement(r))
            except InvalidRequirement:
                pass
        dists[norm_pypi(msg["Name"])] = (msg["Version"], reqs)
    return dists


def _active(req: Requirement, env: dict, extras: frozenset[str]) -> bool:
    if req.marker is None:
        return True
    return any(req.marker.evaluate({**env, "extra": e}) for e in (extras | {""}))


def python_venv_graph(venv: Path, direct: list[Requirement]) -> tuple[set[str], list[tuple[str, str]]]:
    """Installed METADATA → (direct keys, edges). Markers are evaluated against the venv's own
    interpreter; extras are followed only when a parent actually requested them."""
    env, dists = venv_marker_env(venv), _installed_dists(venv)
    key = lambda n: f"pypi:{n}@{dists[n][0]}"
    direct_keys, edges = set(), set()
    queue: list[tuple[str, frozenset[str]]] = []
    for r in direct:
        n = norm_pypi(r.name)
        if n in dists and (r.marker is None or r.marker.evaluate({**env, "extra": ""})):
            direct_keys.add(key(n))
            queue.append((n, frozenset(r.extras)))
    seen = set()
    while queue:
        n, extras = queue.pop()
        if (n, extras) in seen:
            continue
        seen.add((n, extras))
        for r in dists[n][1]:
            c = norm_pypi(r.name)
            if c in dists and _active(r, env, extras):
                edges.add((key(n), key(c)))
                queue.append((c, frozenset(r.extras)))
    return direct_keys, sorted(edges)


def package_json_direct(pkg_dir: Path) -> list[str]:
    pj = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
    names = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        names |= set(pj.get(field, {}) or {})
    return sorted(norm_npm(n) for n in names)


def _lock_name(path_key: str, entry: dict) -> str:
    return entry.get("name") or path_key.rsplit("node_modules/", 1)[-1]


def npm_lock_graph(pkg_dir: Path) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """lockfile v2/v3 → ({key: {name, version, dev}}, [(parent_key, child_key)]).
    key = 'npm:<name>@<version>'. Dependency names are resolved like Node does:
    nearest node_modules/<dep> walking up from the dependent's own folder."""
    lock = json.loads((pkg_dir / "package-lock.json").read_text(encoding="utf-8"))
    pkgs = lock.get("packages")
    if pkgs is None:
        raise ValueError(f"{pkg_dir}: lockfileVersion 1 not supported")

    def key_of(path_key: str) -> str | None:
        e = pkgs.get(path_key)
        if not e or "version" not in e or e.get("link"):
            return None
        return f"npm:{norm_npm(_lock_name(path_key, e))}@{e['version']}"

    def resolve(from_path: str, dep: str) -> str | None:
        base = from_path
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in pkgs:
                return cand
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""

    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str]] = []
    for path_key, e in pkgs.items():
        if not path_key:
            continue
        k = key_of(path_key)
        if k is None:
            continue
        prev = nodes.get(k)
        dev = bool(e.get("dev") or e.get("devOptional"))
        # same name@version can appear at several paths; dev only if every copy is dev
        nodes[k] = {"name": norm_npm(_lock_name(path_key, e)), "version": e["version"],
                    "dev": dev and (prev["dev"] if prev else True)}
    for path_key, e in pkgs.items():
        parent = "ROOT" if not path_key else key_of(path_key)
        if parent is None:
            continue
        deps = {**e.get("dependencies", {}), **e.get("optionalDependencies", {})}
        if not path_key:
            deps = {**deps, **e.get("devDependencies", {})}
        for dep in deps:
            target = resolve(path_key, dep)
            ck = key_of(target) if target else None
            if ck:
                edges.append((parent, ck))
    return nodes, sorted(set(edges))
