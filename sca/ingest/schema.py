"""Common schema. Every scanner/format is converted into these models; downstream stages
(enrich/graph/score) depend only on this, so swapping the input format = new parser here."""
from __future__ import annotations

from pydantic import BaseModel, Field


class Package(BaseModel):
    ecosystem: str                    # pypi | npm | ...
    name: str                         # normalized (PEP 503 for pypi, lowercase for npm)
    version: str
    purl: str
    direct: bool = False
    dev: bool = False                 # npm devDependency-only

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


class CvssScore(BaseModel):
    source: str
    type: str = ""                    # Primary | Secondary
    version: str
    base_score: float
    vector: str = ""


class Finding(BaseModel):
    """One vulnerability matched to one package in one service."""
    service: str
    package: Package
    vuln_id: str                      # canonical: CVE id if known, else GHSA/other
    aliases: list[str] = Field(default_factory=list)
    severity: str = "Unknown"
    cvss: list[CvssScore] = Field(default_factory=list)
    fix_versions: list[str] = Field(default_factory=list)
    fix_state: str = "unknown"        # fixed | not-fixed | wont-fix | unknown
    data_source: str = ""
    matcher: str = ""

    @property
    def cve_ids(self) -> list[str]:
        ids = [self.vuln_id, *self.aliases]
        return sorted({i for i in ids if i.startswith("CVE-")})


class Edge(BaseModel):
    parent: str                       # Package.key
    child: str


class ServiceInventory(BaseModel):
    service: str
    packages: list[Package]
    edges: list[Edge] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    manifest_direct: dict[str, list[str]] = Field(default_factory=dict)  # ecosystem -> names
    notes: list[str] = Field(default_factory=list)
    unknown_class: list[str] = Field(default_factory=list)   # keys from edgeless SBOMs
