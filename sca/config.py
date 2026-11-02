"""Paths and YAML config loading."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
WORK_DIR = ROOT / "work"
OUT_DIR = ROOT / "out"
RAW_DIR = OUT_DIR / "raw"
CACHE_DIR = ROOT / "data" / "cache"


class ComponentSpec(BaseModel):
    """python-venv / python-reqs / npm-lock: scanned here (Syft → Grype) with manifests.
    sbom: a given CycloneDX SBOM + vulnerability report (Grype or Trivy JSON) — no scan, no
    manifests, no venv; dependency edges come from the SBOM's `dependencies`."""
    kind: Literal["python-venv", "python-reqs", "npm-lock", "sbom"]
    venv: str | None = None          # python-venv: path relative to repo
    path: str = "."                  # npm-lock: dir holding package.json / package-lock.json
    manifests: list[str] = Field(default_factory=list)
    sbom: str | None = None          # sbom: CycloneDX JSON (absolute, or relative to the project root)
    vulns: str | None = None         # sbom: vulnerability report JSON (same path rules)
    vulns_format: Literal["grype", "trivy"] = "grype"

    @model_validator(mode="after")
    def _sbom_files(self):
        if self.kind == "sbom" and not (self.sbom and self.vulns):
            raise ValueError("kind 'sbom' needs both `sbom` and `vulns` paths")
        return self


def project_path(p: str) -> Path:
    """Config path → absolute ($VARS and ~ expanded; relative = project root)."""
    q = Path(os.path.expandvars(p)).expanduser()
    return q if q.is_absolute() else ROOT / q


class ServiceSpec(BaseModel):
    name: str
    repo: str | None = None          # required unless every component is kind 'sbom'
    clone: str | None = None         # "owner/name" on GitHub, cloned when repo is missing
    components: list[ComponentSpec]

    @model_validator(mode="after")
    def _repo_needed(self):
        if self.repo is None and any(c.kind != "sbom" for c in self.components):
            raise ValueError(f"[{self.name}] `repo` is required for scanned components")
        return self

    @property
    def repo_path(self) -> Path:
        """No repo (SBOM-only service) → a path that does not exist: code checks are skipped
        and those conditions go to a human (judge rule code_unavailable)."""
        if self.repo is None:
            return WORK_DIR / "no-repo" / self.name
        p = Path(os.path.expandvars(self.repo)).expanduser()
        return p if p.is_absolute() else ROOT / p


class Asset(BaseModel):
    exposure: Literal["internet", "internal"]
    criticality: int = Field(ge=1, le=3)
    owner_team: str
    confirmed: bool = False


class ScoringConfig(BaseModel):
    exposure_weight: dict[str, float]
    criticality_weight: dict[int, float]
    likelihood: dict[str, float | str]
    dev_weight: float = 1.0
    cvss_fallback: dict[str, float]


def _load(name: str) -> dict:
    return yaml.safe_load((CONFIG_DIR / name).read_text(encoding="utf-8"))


def load_services() -> list[ServiceSpec]:
    """services.local.yaml (gitignored: real local paths, private repos) wins over the
    committed services.example.yaml."""
    name = "services.local.yaml" if (CONFIG_DIR / "services.local.yaml").exists() else "services.example.yaml"
    return [ServiceSpec(**s) for s in _load(name)["services"]]


def load_assets() -> dict[str, Asset]:
    return {k: Asset(**v) for k, v in _load("assets.yaml")["assets"].items()}


def load_scoring() -> ScoringConfig:
    return ScoringConfig(**_load("scoring.yaml"))
