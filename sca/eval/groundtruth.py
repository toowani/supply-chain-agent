"""Hand-labelled ground truth for judge accuracy (CLAUDE.md §5 측정값 2). The file itself is
drafted by the lead and reviewed by a human; this module only loads it."""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from sca.config import ROOT
from sca.contracts import Verdict

GT_PATH = ROOT / "data" / "eval" / "ground_truth.yaml"


class GTItem(BaseModel):
    service: str
    package: str                       # Package.key, e.g. "pypi:pillow@11.3.0"
    vuln_id: str
    label: Verdict
    rationale: str = ""
    evidence: list[str] = Field(default_factory=list)
    labeled_by: str = ""
    reviewed: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.service, self.package, self.vuln_id)


def load_ground_truth(path: Path = GT_PATH) -> list[GTItem] | None:
    """None when the file does not exist yet. Accepts a top-level list or {items: [...]}."""
    path = Path(path)
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    items = data.get("items", []) if isinstance(data, dict) else data
    return [GTItem(**it) for it in items or []]
