"""Team–Service–Package–Vuln graph (networkx). Node ids: 'team:x', 'svc:x', 'pkg:<eco>:<name>@<ver>',
'vuln:<id>'. Package→package edges carry the set of services they were observed in, so path
explanations never cross into another service's dependency tree."""
from __future__ import annotations

from collections import defaultdict

import networkx as nx

from sca.config import Asset
from sca.ingest.inventory import dependency_class
from sca.ingest.schema import ServiceInventory


def build_graph(invs: list[ServiceInventory], assets: dict[str, Asset]) -> nx.DiGraph:
    g = nx.DiGraph()
    for inv in invs:
        s = f"svc:{inv.service}"
        a = assets.get(inv.service)
        g.add_node(s, kind="service", **(a.model_dump() if a else {}))
        if a:
            g.add_node(f"team:{a.owner_team}", kind="team")
            g.add_edge(f"team:{a.owner_team}", s, rel="owns")
        dep_class = dependency_class(inv)
        for p in inv.packages:
            n = f"pkg:{p.key}"
            g.add_node(n, kind="package", ecosystem=p.ecosystem, name=p.name, version=p.version)
            g.add_edge(s, n, rel="uses", dependency=dep_class[p.key], dev=p.dev)
        for e in inv.edges:
            u, v = f"pkg:{e.parent}", f"pkg:{e.child}"
            if g.has_edge(u, v):
                g[u][v]["services"].add(inv.service)
            else:
                g.add_edge(u, v, rel="depends_on", services={inv.service})
        for f in inv.findings:
            vn = f"vuln:{f.vuln_id}"
            g.add_node(vn, kind="vuln", severity=f.severity)
            g.add_edge(f"pkg:{f.package.key}", vn, rel="has_vuln")
    return g


def explain_path(g: nx.DiGraph, service: str, pkg_key: str) -> list[str]:
    """Shortest chain service → direct dep → … → package, inside that service's tree only."""
    s, target = f"svc:{service}", f"pkg:{pkg_key}"
    direct = [v for _, v, d in g.out_edges(s, data=True) if d.get("dependency") == "direct"]
    if target in direct:
        return [service, pkg_key]
    sub = nx.DiGraph()
    sub.add_edges_from((u, v) for u, v, d in g.edges(data=True)
                       if d.get("rel") == "depends_on" and service in d["services"])
    best = None
    for d in direct:
        if d in sub and target in sub:
            try:
                p = nx.shortest_path(sub, d, target)
            except nx.NetworkXNoPath:
                continue
            if best is None or len(p) < len(best):
                best = p
    if best:
        return [service, *(n.removeprefix("pkg:") for n in best)]
    if not direct:
        return [service, "(dependency path unknown: no direct-dependency data)", pkg_key]
    return [service, "(unreferenced: not reachable from a declared dependency)", pkg_key]


def blast_radius(g: nx.DiGraph, vuln_id: str) -> list[str]:
    """Services that install a package carrying this vulnerability."""
    out = set()
    for pkg in g.predecessors(f"vuln:{vuln_id}"):
        out |= {u.removeprefix("svc:") for u in g.predecessors(pkg) if u.startswith("svc:")}
    return sorted(out)


def summary(g: nx.DiGraph, invs: list[ServiceInventory]) -> dict:
    by_name: dict[tuple[str, str], dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for inv in invs:
        for p in inv.packages:
            by_name[(p.ecosystem, p.name)][inv.service].add(p.version)
    shared = sorted(
        ({"ecosystem": eco, "package": name, "services": len(svcs),
          "service_names": sorted(svcs),
          "versions": sorted({v for vs in svcs.values() for v in vs})}
         for (eco, name), svcs in by_name.items() if len(svcs) > 1),
        key=lambda r: (-r["services"], r["ecosystem"], r["package"]))
    kinds = defaultdict(int)
    for _, d in g.nodes(data=True):
        kinds[d.get("kind")] += 1
    per_service = []
    for inv in invs:
        cls = dependency_class(inv)
        counts = defaultdict(int)
        for p in inv.packages:
            counts[cls[p.key]] += 1
        vuln_pkgs = {f.package.key for f in inv.findings}
        vcounts = defaultdict(int)
        for k in vuln_pkgs:
            vcounts[cls.get(k, "unknown")] += 1
        per_service.append({
            "service": inv.service, "packages": len(inv.packages),
            "direct": counts["direct"], "transitive": counts["transitive"],
            "unreferenced": counts["unreferenced"],
            **({"unknown": counts["unknown"]} if counts["unknown"] else {}),   # SBOM without edges
            "dev_only": sum(p.dev for p in inv.packages),
            "findings": len(inv.findings),
            "vulnerable_packages": len(vuln_pkgs),
            "vulnerable_direct": vcounts["direct"], "vulnerable_transitive": vcounts["transitive"],
            "vulnerable_unreferenced": vcounts["unreferenced"],
            **({"vulnerable_unknown": vcounts["unknown"]} if vcounts["unknown"] else {}),
        })
    unique_versions = {f"{p.ecosystem}:{p.name}@{p.version}" for inv in invs for p in inv.packages}
    unique_names = {(p.ecosystem, p.name) for inv in invs for p in inv.packages}
    return {
        "services": kinds["service"], "teams": kinds["team"],
        "package_versions": len(unique_versions), "package_names": len(unique_names),
        "vulnerabilities": kinds["vuln"], "edges": g.number_of_edges(),
        "shared_packages_total": len(shared), "shared_top10": shared[:10],
        "per_service": per_service,
    }
