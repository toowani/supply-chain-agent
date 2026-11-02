"""Build one ServiceInventory per service from raw scan output + manifests, or (kind 'sbom')
from a given CycloneDX SBOM + vulnerability report alone."""
from __future__ import annotations

import json
from collections import deque

from sca.config import RAW_DIR, WORK_DIR, ServiceSpec, project_path
from sca.ingest.manifests import (norm_pypi, npm_lock_graph, package_json_direct,
                                  python_venv_graph, requirements_parse)
from sca.ingest.parsers import cyclonedx_direct, merge_findings, parse_cyclonedx, parse_grype, parse_vulns
from sca.ingest.scan import raw_path
from sca.ingest.schema import Edge, Package, ServiceInventory


def _sbom_component(comp, pkgs, edges, direct_keys, notes) -> set[str]:
    """kind 'sbom': packages + edges from the SBOM's `dependencies`. Direct = the root
    component's dependsOn when recorded, else packages no other package depends on. No edges at
    all → nothing is marked direct; returns those package keys, which dependency_class reports
    as 'unknown' (never 'unreferenced') unless another component reaches them."""
    path = project_path(comp.sbom)
    comp_pkgs, comp_edges = parse_cyclonedx(path)
    for p in comp_pkgs:
        pkgs.setdefault(p.key, p)
    keys = {p.key for p in comp_pkgs}
    for e in comp_edges:
        edges.add((e.parent, e.child))
    root = cyclonedx_direct(path)
    if root:
        direct_keys |= root & keys
    elif comp_edges:
        children = {e.child for e in comp_edges}
        direct_keys |= {k for k in keys if k not in children}
        notes.append(f"{path.name}: no root dependencies; packages without a parent marked direct")
    else:
        notes.append(f"{path.name}: SBOM has no dependency edges; direct/transitive unknown")
        return keys
    return set()


def build_inventory(svc: ServiceSpec) -> ServiceInventory:
    scanned = any(c.kind != "sbom" for c in svc.components)
    index_path = RAW_DIR / "scan_index.json"
    if scanned and not index_path.exists():
        raise SystemExit(f"{index_path} not found: run `sca run` without --skip-scan first, "
                         "or describe the service as `kind: sbom` in config/services.local.yaml")
    index = json.loads(index_path.read_text(encoding="utf-8")) if scanned else []
    entries = [e for e in index if e["service"] == svc.name and svc.components[e["index"]].kind != "sbom"]
    repo = svc.repo_path
    pkgs: dict[str, Package] = {}
    edges: set[tuple[str, str]] = set()
    direct_keys: set[str] = set()
    manifest_direct: dict[str, list[str]] = {}
    findings = []
    notes = []
    unknown_keys: set[str] = set()

    for comp in svc.components:
        if comp.kind == "sbom":
            unknown_keys |= _sbom_component(comp, pkgs, edges, direct_keys, notes)
            findings += parse_vulns(project_path(comp.vulns), svc.name, comp.vulns_format)

    for e in entries:
        comp = svc.components[e["index"]]
        comp_pkgs, _ = parse_cyclonedx(raw_path(e["sbom"]))   # edges come from manifests below
        if comp.kind == "npm-lock":
            lock_nodes, lock_edges = npm_lock_graph(repo / comp.path)
            # Syft also emits the project root itself as a library; keep lock entries only
            dropped = [p.key for p in comp_pkgs if p.key not in lock_nodes]
            if dropped:
                notes.append(f"SBOM entries not in lock (project root etc.) skipped: {dropped}")
            comp_pkgs = [p for p in comp_pkgs if p.key in lock_nodes]
        for p in comp_pkgs:
            pkgs.setdefault(p.key, p)
        if comp.kind == "npm-lock":
            names = package_json_direct(repo / comp.path)
            manifest_direct.setdefault("npm", []).extend(names)
            for parent, child in lock_edges:
                if parent == "ROOT":
                    direct_keys.add(child)
                else:
                    edges.add((parent, child))
            for k, meta in lock_nodes.items():
                if k in pkgs:
                    pkgs[k].dev = meta["dev"]
                else:
                    notes.append(f"lock entry not in SBOM: {k}")
        else:
            reqs = [r for m in comp.manifests for r in requirements_parse(repo / m)]
            names = sorted({norm_pypi(r.name) for r in reqs})
            manifest_direct.setdefault("pypi", []).extend(names)
            venv = repo / comp.venv if comp.kind == "python-venv" else WORK_DIR / "venvs" / svc.name
            d_keys, py_edges = python_venv_graph(venv, reqs)
            direct_keys |= d_keys
            edges |= set(py_edges)
            missing = set(names) - {p.name for p in comp_pkgs}
            if missing:
                notes.append(f"declared but not installed: {sorted(missing)}")
        findings += parse_grype(raw_path(e["grype"]), svc.name)

    for k in direct_keys:
        if k in pkgs:
            pkgs[k].direct = True
    findings = merge_findings(findings)
    for f in findings:  # attach the inventory's own Package (direct/dev flags)
        if f.package.key in pkgs:
            f.package = pkgs[f.package.key]
        else:
            notes.append(f"finding on package not in SBOM: {f.package.key}")
    return ServiceInventory(
        service=svc.name, packages=sorted(pkgs.values(), key=lambda p: p.key),
        edges=[Edge(parent=a, child=b) for a, b in sorted(edges)],
        findings=findings,
        manifest_direct={k: sorted(set(v)) for k, v in manifest_direct.items()},
        notes=notes,
        unknown_class=sorted(unknown_keys),
    )


def dependency_class(inv: ServiceInventory) -> dict[str, str]:
    """key -> direct | transitive | unreferenced (installed, not reachable from a direct dep,
    e.g. pip/setuptools in a venv or leftovers from an old install) | unknown (no package is
    dependency data, i.e. a package from an SBOM without dependency edges that no other component
    reaches: it cannot be called unused)."""
    unknown = set(inv.unknown_class)
    children: dict[str, list[str]] = {}
    for e in inv.edges:
        children.setdefault(e.parent, []).append(e.child)
    direct = [p.key for p in inv.packages if p.direct]
    seen = set(direct)
    q = deque(direct)
    while q:
        for c in children.get(q.popleft(), []):
            if c not in seen:
                seen.add(c)
                q.append(c)
    return {p.key: "direct" if p.direct else ("transitive" if p.key in seen else
                                              ("unknown" if p.key in unknown else "unreferenced"))
            for p in inv.packages}
