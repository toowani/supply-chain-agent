"""Stage contracts shared by judge / plan / feedback / report / eval.

Division of labour (CLAUDE.md §4): CODE computes (versions, ranges, search, scores, plan),
LLM interprets public advisory text only, HUMAN decides (uncertain queue, approve/reject).
Internal data (asset info, service source code, feedback notes) is never sent to a remote LLM.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["affected", "not_affected", "uncertain"]


# ── judge ────────────────────────────────────────────────────────────────────────────
class Condition(BaseModel):
    """One precondition from the advisory that must hold for exploitation."""
    kind: Literal["api", "config", "platform", "input", "feature", "other"]
    description: str                                   # short paraphrase, English
    symbols: list[str] = Field(default_factory=list)   # functions/classes/options to grep for
    platforms: list[str] = Field(default_factory=list) # kind=platform: windows|linux|macos|...


class AdvisoryConditions(BaseModel):
    """LLM output for one (package, vuln) advisory. Public data only → cacheable per vuln."""
    vuln_id: str
    package: str
    unconditional: bool          # advisory states no precondition → version alone decides
    conditions: list[Condition] = Field(default_factory=list)
    advisory_quote: str = ""     # verbatim sentence from the advisory supporting conditions
    workaround: str = ""
    model: str = ""              # backend/model that produced it, or "rule" for fallback


class CodeHit(BaseModel):
    file: str                    # path relative to the service repo
    line: int
    text: str                    # stripped line, ≤200 chars
    symbol: str


class Judgment(BaseModel):
    """CLAUDE.md judge schema + bookkeeping. One per (service, package@version, vuln)."""
    service: str
    cve: str                                      # canonical vuln id (CVE if known)
    package: str                                  # Package.key, e.g. "pypi:pillow@11.3.0"
    affected_ranges: list[list[str]] = Field(default_factory=list)  # [[introduced, fixed|""]]
    in_range: bool | None = None                  # CODE: OSV range check (None = no range data)
    conditions: list[str] = Field(default_factory=list)
    check_in_code: str = ""                       # what was searched, human readable
    verdict: Verdict
    rule: str                                     # which deterministic rule decided (see judge)
    evidence: dict = Field(default_factory=lambda: {"advisory_quote": "", "code_hits": []})
    workaround: str = ""
    decided_by: Literal["code", "feedback", "human"] = "code"
    seconds: float = 0.0                          # wall time for this judgment


# ── feedback ("개선" loop) ───────────────────────────────────────────────────────────
ReasonCode = Literal[
    "not_reachable",     # vulnerable code path not used by this service
    "platform",          # condition is platform/runtime we don't run
    "dev_only",          # build/test tooling only, no untrusted input
    "false_positive",    # scanner matched wrong package/version
    "accepted_risk",     # known, accepted until a date
    "fixed",             # remediation applied → verify on rescan
    "confirmed",         # human confirms affected
]


class Decision(BaseModel):
    service: str
    package: str                       # package NAME with ecosystem, e.g. "pypi:pillow" (version-free)
    vuln_id: str
    decision: Literal["approve", "reject"]   # approve = agent verdict/ticket correct; reject = wrong
    verdict: Verdict                   # the human's final verdict
    reason: ReasonCode
    note: str = ""                     # free text (internal → never to remote LLM)
    scope: Literal["service", "all_services"] = "service"   # suppression reach
    at: str                            # ISO8601 UTC
    by: str = "reviewer"


# ── plan ─────────────────────────────────────────────────────────────────────────────
class Action(BaseModel):
    kind: Literal["upgrade", "remove"]
    ecosystem: str
    package: str                       # name
    target_version: str = ""           # upgrade only
    services: list[str]
    from_versions: list[str]
    covers: list[str]                  # finding ids "service|pkgkey|vuln"
    risk_covered: float                # Σ score of covered (not not_affected) findings
    major_bump: bool = False           # semver major change (is_major_bump) only
    runtime_upgrade: bool = False      # target's Requires-Python excludes a service interpreter
    runtime_note: str = ""             # e.g. "Python 3.9.6 → >=3.10"
    note: str = ""


class PlanResult(BaseModel):
    k: int
    total_risk: float                  # Σ score over findings not judged not_affected
    actions: list[Action]              # greedy order
    covered_risk: float
    coverage: float                    # covered_risk / total_risk
    unfixable: list[str] = Field(default_factory=list)   # finding ids with no fix and not removable


def finding_id(service: str, pkg_key: str, vuln_id: str) -> str:
    return f"{service}|{pkg_key}|{vuln_id}"
