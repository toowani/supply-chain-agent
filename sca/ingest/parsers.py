"""CycloneDX JSON (Syft or any tool) + Grype / Trivy JSON → common schema. A new input format
= a new parser here (plus, if it is not a CycloneDX SBOM + report pair, how sca/ingest/inventory.py
assembles it); later stages only see sca/ingest/schema.py."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote

from sca.ingest.manifests import norm_npm, norm_pypi
from sca.ingest.schema import CvssScore, Edge, Finding, Package
from sca.versions import is_newer, sort_versions

_ECO = {"pypi": norm_pypi, "npm": norm_npm}


def _purl_eco(purl: str) -> str:
    return purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else "unknown"


def _strip_qualifiers(ref: str) -> str:
    return unquote(ref.split("?", 1)[0])


def _purl_name(purl: str) -> str:
    """'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?x=y' → 'org.apache.logging.log4j/log4j-core'."""
    if not purl.startswith("pkg:") or "/" not in purl:
        return ""
    path = _strip_qualifiers(purl).split("#", 1)[0].split("/", 1)[1]
    return path.rsplit("@", 1)[0] if "@" in path[1:] else path


def make_package(purl: str, name: str, version: str) -> Package:
    """pypi/npm: normalised purl name (the purl carries an npm scope that a CycloneDX `name`
    may lack, e.g. cdxgen group '@babel' + name 'core'). Other ecosystems: purl namespace/name,
    so the SBOM, Grype ('log4j-core') and Trivy ('group:artifact') name the same package."""
    eco = _purl_eco(purl)
    if eco in _ECO:
        norm = _ECO[eco](_purl_name(purl) or name)
    else:
        norm = (_purl_name(purl) or name).lower()
    return Package(ecosystem=eco, name=norm, version=version, purl=_strip_qualifiers(purl))


def parse_cyclonedx(path: Path) -> tuple[list[Package], list[Edge]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    by_ref: dict[str, Package] = {}
    for c in doc.get("components", []):
        if c.get("type") != "library" or not c.get("purl") or not c.get("version"):
            continue
        by_ref[c["bom-ref"]] = make_package(c["purl"], c["name"], c["version"])
    edges = []
    for d in doc.get("dependencies", []) or []:
        p = by_ref.get(d["ref"])
        for child in d.get("dependsOn", []):
            c = by_ref.get(child)
            if p and c:
                edges.append(Edge(parent=p.key, child=c.key))
    return list(by_ref.values()), edges


def cyclonedx_direct(path: Path) -> set[str] | None:
    """Package keys the SBOM's root component (metadata.component) depends on directly, or None
    when the SBOM does not record root dependencies."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    by_ref = {c["bom-ref"]: make_package(c["purl"], c["name"], c["version"]).key
              for c in doc.get("components", [])
              if c.get("type") == "library" and c.get("purl") and c.get("version") and c.get("bom-ref")}
    for d in doc.get("dependencies", []) or []:
        if root and d.get("ref") == root:
            return {by_ref[c] for c in d.get("dependsOn", []) if c in by_ref}
    return None


def _cvss_list(v: dict) -> list[CvssScore]:
    out = []
    source = v.get("dataSource", "") or v.get("namespace", "")
    for c in v.get("cvss", []) or []:
        score = (c.get("metrics") or {}).get("baseScore")
        if score is None:
            continue
        out.append(CvssScore(source=source, type=c.get("type", ""), version=str(c.get("version", "")),
                             base_score=float(score), vector=c.get("vector", "")))
    return out


def canonical_id(vid: str, related: list[str]) -> str:
    cves = sorted(i for i in [vid, *related] if i.startswith("CVE-"))
    return cves[0] if cves else vid


def parse_grype(path: Path, service: str) -> list[Finding]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for m in doc.get("matches", []):
        v, art = m["vulnerability"], m["artifact"]
        pkg = make_package(art["purl"], art["name"], art["version"])
        related = m.get("relatedVulnerabilities", []) or []
        rel_ids = [r["id"] for r in related]
        cvss = _cvss_list(v)
        for r in related:
            cvss += _cvss_list(r)
        fix = v.get("fix") or {}
        fixes = [f for f in fix.get("versions", []) or [] if is_newer(pkg.ecosystem, f, pkg.version)]
        vid = canonical_id(v["id"], rel_ids)
        findings.append(Finding(
            service=service, package=pkg, vuln_id=vid,
            aliases=sorted({v["id"], *rel_ids} - {vid}),
            severity=v.get("severity", "Unknown"), cvss=cvss,
            fix_versions=sort_versions(pkg.ecosystem, sorted(set(fixes))),
            fix_state=fix.get("state", "unknown"),
            data_source=v.get("dataSource", ""),
            matcher=(m.get("matchDetails") or [{}])[0].get("matcher", ""),
        ))
    return findings


# Trivy result Type → purl ecosystem (used when a vulnerability has no PkgIdentifier.PURL)
_TRIVY_TYPE = {"pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi", "python-pkg": "pypi",
               "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "bun": "npm",
               "jar": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven",
               "gomod": "golang", "gobinary": "golang", "nuget": "nuget", "dotnet-core": "nuget",
               "cargo": "cargo", "rust-binary": "cargo", "composer": "composer", "gemspec": "gem",
               "bundler": "gem"}


def _trivy_cvss(v: dict) -> list[CvssScore]:
    out = []
    for src, c in sorted((v.get("CVSS") or {}).items()):
        for ver, key, vec in (("3.1", "V3Score", "V3Vector"), ("4.0", "V40Score", "V40Vector"),
                              ("2.0", "V2Score", "V2Vector")):
            if c.get(key) is not None:
                vector = c.get(vec, "")
                if ver == "3.1" and vector.startswith("CVSS:3.0"):
                    ver = "3.0"
                out.append(CvssScore(source=src, version=ver, base_score=float(c[key]), vector=vector))
    return out


def parse_trivy(path: Path, service: str) -> list[Finding]:
    """Trivy JSON (`trivy fs|image|sbom -f json`): Results[].Vulnerabilities[] → Finding.
    FixedVersion may list several versions ("1.2.3, 2.0.1"); only versions newer than the
    installed one are kept (packaging-based compare, never string compare)."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for res in doc.get("Results", []) or []:
        eco_default = _TRIVY_TYPE.get(str(res.get("Type", "")).lower(), str(res.get("Type", "")).lower() or "unknown")
        for v in res.get("Vulnerabilities", []) or []:
            name, ver = v.get("PkgName", ""), v.get("InstalledVersion", "")
            if not name or not ver:
                continue
            # Trivy names maven packages 'group:artifact'; the purl form is 'group/artifact'
            pname = name.replace(":", "/", 1) if eco_default == "maven" else name
            purl = (v.get("PkgIdentifier") or {}).get("PURL") or f"pkg:{eco_default}/{pname}@{ver}"
            pkg = make_package(purl, name, ver)
            fixed = [x.strip() for x in str(v.get("FixedVersion") or "").split(",") if x.strip()]
            fixes = [x for x in fixed if is_newer(pkg.ecosystem, x, pkg.version)]
            vid0 = v.get("VulnerabilityID", "")
            related = [a for a in v.get("VendorIDs", []) or [] if a != vid0]
            vid = canonical_id(vid0, related)
            findings.append(Finding(
                service=service, package=pkg, vuln_id=vid,
                aliases=sorted({vid0, *related} - {vid}),
                severity=str(v.get("Severity", "Unknown")).title(), cvss=_trivy_cvss(v),
                fix_versions=sort_versions(pkg.ecosystem, sorted(set(fixes))),
                fix_state="fixed" if fixes else ("not-fixed" if v.get("Status") == "affected" else "unknown"),
                data_source=v.get("PrimaryURL", "") or (v.get("DataSource") or {}).get("URL", ""),
                matcher="trivy",
            ))
    return findings


def parse_vulns(path: Path, service: str, fmt: str = "grype") -> list[Finding]:
    return parse_trivy(path, service) if fmt == "trivy" else parse_grype(path, service)


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Same (service, package, canonical vuln) reported by several matchers → one row."""
    merged: dict[tuple, Finding] = {}
    for f in findings:
        k = (f.service, f.package.key, f.vuln_id)
        if k not in merged:
            merged[k] = f
            continue
        g = merged[k]
        g.aliases = sorted(set(g.aliases) | set(f.aliases))
        g.cvss += [c for c in f.cvss if c not in g.cvss]
        g.fix_versions = sort_versions(g.package.ecosystem, sorted(set(g.fix_versions) | set(f.fix_versions)))
        g.matcher = ",".join(sorted(set(g.matcher.split(",")) | {f.matcher}))
    return list(merged.values())
