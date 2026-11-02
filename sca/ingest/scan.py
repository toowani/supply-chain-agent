"""Prepare scan targets, then run Syft (CycloneDX SBOM) and Grype (JSON) per component."""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
from pathlib import Path

from sca.config import OUT_DIR, RAW_DIR, WORK_DIR, ComponentSpec, ServiceSpec

SBOM_DIR = RAW_DIR / "sbom"
GRYPE_DIR = RAW_DIR / "grype"
RESOLVED_DIR = OUT_DIR / "resolved"


def _run(cmd: list[str], env: dict | None = None, capture: bool = False) -> str:
    res = subprocess.run(
        cmd, env={**os.environ, **(env or {})}, check=True, text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    return res.stdout or ""


def needed_tools(services: list[ServiceSpec] | None) -> list[str]:
    """Tools a scan of `services` needs: syft+grype for any scanned component, uv only for
    python-reqs (temp venv). kind 'sbom' components bring their own files → nothing."""
    if services is None:
        return ["syft", "grype", "uv"]
    kinds = {c.kind for s in services for c in s.components}
    out = ["syft", "grype"] if kinds - {"sbom"} else []
    return out + (["uv"] if "python-reqs" in kinds else [])


def require_tools(services: list[ServiceSpec] | None = None, strict: bool = True) -> dict[str, str]:
    """{tool: version}. strict: a needed tool missing → SystemExit; otherwise it is recorded as
    'not installed' (e.g. --skip-scan reusing out/raw)."""
    versions = {}
    need = needed_tools(services)
    for tool in ("syft", "grype", "uv"):
        if not shutil.which(tool):
            if strict and tool in need:
                raise SystemExit(f"{tool} not found. Install: brew install {tool}")
            versions[tool] = "not installed"
            continue
        try:
            out = _run([tool, "version"] if tool != "uv" else [tool, "--version"], capture=True)
        except (OSError, subprocess.CalledProcessError):
            versions[tool] = "?"
            continue
        line = next((l for l in out.splitlines() if l.startswith(("Version", "uv "))), "")
        versions[tool] = line.split()[1] if line.startswith("uv ") else (line.split()[-1] if line else "?")
    return versions


def ensure_repo(svc: ServiceSpec) -> Path:
    path = svc.repo_path
    if not path.exists():
        if not svc.clone:
            raise SystemExit(f"[{svc.name}] repo not found: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        _run(["gh", "repo", "clone", svc.clone, str(path), "--", "--depth", "1"])
    return path


def ensure_temp_venv(svc: ServiceSpec, comp: ComponentSpec, repo: Path, refresh: bool) -> Path:
    """No venv in the repo → install its manifests into work/venvs/<service> and scan that."""
    venv = WORK_DIR / "venvs" / svc.name
    resolved = RESOLVED_DIR / f"{svc.name}.txt"
    if refresh and venv.exists():
        shutil.rmtree(venv)
    if not venv.exists():
        _run(["uv", "venv", "-q", "--python", "3.11", str(venv)])
        args = [a for m in comp.manifests for a in ("-r", str(repo / m))]
        _run(["uv", "pip", "install", "-q", "--python", str(venv / "bin" / "python"), *args])
        freeze = _run(["uv", "pip", "freeze", "--python", str(venv / "bin" / "python")], capture=True)
        RESOLVED_DIR.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        resolved.write_text(
            f"# resolved {stamp} with uv from {', '.join(comp.manifests)} (python 3.11)\n{freeze}",
            encoding="utf-8",
        )
    return venv


def syft_cmd(target: str, cataloger: str, out: Path, exclude: list[str] = ()) -> list[str]:
    cmd = ["syft", f"dir:{target}", "--override-default-catalogers", cataloger, "-q",
           "-o", f"cyclonedx-json={out}"]
    for e in exclude:
        cmd += ["--exclude", e]
    return cmd


def scan_component(svc: ServiceSpec, idx: int, comp: ComponentSpec, repo: Path,
                   refresh_venv: bool) -> dict:
    tag = f"{svc.name}__{idx}-{comp.kind}"
    sbom = SBOM_DIR / f"{tag}.cdx.json"
    grype_out = GRYPE_DIR / f"{tag}.json"
    env = None
    if comp.kind == "python-venv":
        cmd = syft_cmd(str(repo / comp.venv), "python-installed-package-cataloger", sbom)
    elif comp.kind == "python-reqs":
        venv = ensure_temp_venv(svc, comp, repo, refresh_venv)
        cmd = syft_cmd(str(venv), "python-installed-package-cataloger", sbom)
    else:  # npm-lock: lock entries = what `npm ci` installs; include devDependencies
        cmd = syft_cmd(str(repo / comp.path), "javascript-lock-cataloger", sbom,
                       exclude=["./node_modules/**", "./.claude/**", "./**/.claude/**"])
        env = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}
    _run(cmd, env=env)
    grype_json = _run(["grype", f"sbom:{sbom}", "-o", "json", "-q"], capture=True)
    grype_out.write_text(grype_json, encoding="utf-8")
    # paths relative to RAW_DIR: moving/renaming the checkout keeps --skip-scan working
    return {"service": svc.name, "index": idx, "kind": comp.kind,
            "sbom": sbom.relative_to(RAW_DIR).as_posix(), "grype": grype_out.relative_to(RAW_DIR).as_posix()}


def raw_path(p: str) -> Path:
    """scan_index path → file (relative to RAW_DIR; absolute paths from older indexes kept)."""
    q = Path(p)
    return q if q.is_absolute() else RAW_DIR / q


def scan_all(services: list[ServiceSpec], refresh_venv: bool = False) -> list[dict]:
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    GRYPE_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for svc in services:
        scanned = [(i, c) for i, c in enumerate(svc.components) if c.kind != "sbom"]
        if not scanned:                  # SBOM + vuln report given: nothing to scan, repo optional
            continue
        repo = ensure_repo(svc)
        for idx, comp in scanned:
            print(f"  scan {svc.name} [{comp.kind}]", flush=True)
            results.append(scan_component(svc, idx, comp, repo, refresh_venv))
    (RAW_DIR / "scan_index.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    return results
