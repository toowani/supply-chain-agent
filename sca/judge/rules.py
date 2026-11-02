"""Deterministic verdict rules. The LLM only supplies AdvisoryConditions (public text); the
decision is made here, first matching rule wins:

    R0 feedback_suppressed          a human decision (feedback store) exists → its verdict
    R1 version_out_of_range         OSV ranges say the installed version is not affected → not_affected
    -- llm_unavailable              conditions could not be extracted → uncertain (HUMAN)
    R2 unconditional_version_match  advisory states no precondition (unconditional, or no
                                    condition extracted), or only platform conditions that all
                                    match the runtime → affected by version alone
    R3 platform_excluded            every platform condition names an OS and is disjoint from the
                                    service runtime (default linux+macos) → not_affected.
                                    Environment-only conditions (node, browser, workerd, …) not in
                                    the runtime list are NOT excluded; they are treated as
                                    non-checkable conditions (→ R7 uncertain at most)
    -- Hits count only in files importing the vulnerable package (service code, or installed
       source of the service's packages that depend on it) — see sca/judge/reach.py.
       Platform conditions with empty `platforms` are read from text (not when negated).
    R4 api_not_referenced           conservative: NO symbol of any api-kind condition is referenced
                                    in service code nor in any dependent, the search was complete,
                                    and the advisory quote was verified → not_affected (the LLM may
                                    split alternatives, so one unmet condition is not enough).
                                    proactive (default): ONE api/input condition whose symbols are
                                    absent from the searched scopes suffices — it does NOT require
                                    a complete search (unsearched dependents/bundles) nor a verified
                                    quote. More filtering, may miss; compared side by side in
                                    metrics.mode_comparison.
    R5 input_trust_needs_human      all api conditions met in service code, but an input-kind
                                    condition (attacker-controlled data) remains → uncertain
    R6 condition_symbol_in_code     all api conditions met in service code, no input condition
                                    → affected
    R7 reachable_via_dependency     api conditions met only inside dependents → uncertain
                                    (call-graph would settle it: roadmap)
    R8a code_unavailable            no service code to search (repo missing, SBOM-only input, or an
                                    ecosystem code search does not support) → uncertain (HUMAN)
    R8 transitive_needs_callgraph   no searchable api symbols, package not imported → uncertain
    R9 condition_not_checkable      config/input/feature/other conditions only → uncertain

"remaining" = non-platform conditions (platform ones matching the runtime are satisfied).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sca.contracts import AdvisoryConditions, CodeHit, Decision, Verdict

RULE_ORDER = ["feedback_suppressed", "version_out_of_range", "llm_unavailable",
              "unconditional_version_match", "platform_excluded", "api_not_referenced",
              "input_trust_needs_human", "condition_symbol_in_code", "reachable_via_dependency",
              "code_unavailable", "transitive_needs_callgraph", "condition_not_checkable"]
KNOWN_OS = {"windows", "linux", "macos", "android", "ios", "freebsd"}
DEFAULT_RUNTIME = ["linux", "macos"]   # macOS dev + GitHub Actions ubuntu (+ Cloudflare workerd)

_PLATFORM_ALIASES = {
    "darwin": "macos", "mac": "macos", "osx": "macos", "mac os": "macos", "macosx": "macos",
    "os x": "macos", "win": "windows", "win32": "windows", "win64": "windows", "nt": "windows",
    "microsoft windows": "windows", "gnu/linux": "linux", "unix": "unix", "posix": "unix",
    "node.js": "node", "nodejs": "node", "cloudflare workers": "workerd",
}


def norm_platform(p: str) -> str:
    p = p.strip().lower()
    return _PLATFORM_ALIASES.get(p, p)


_OS_WORDS = re.compile(r"\b(windows|linux|macos|mac os|darwin|android|ios|freebsd)\b", re.I)


def _os_in_text(text: str) -> list[str]:
    """Platform condition with empty `platforms` (LLM left it out): read OS names from the text."""
    return [m.group(1) for m in _OS_WORDS.finditer(text or "")]


def api_conditions(rest) -> list:
    """api-kind conditions with symbols. Input-kind symbols are often data tokens (file markers,
    header names) that never appear in code, so they are never used as negative evidence."""
    return [k for k in rest if k.kind == "api" and k.symbols]


_NEGATION = re.compile(r"\b(except|other than|not on|non-|excluding|all platforms but)\b", re.I)


def _platform_set(ps: list[str]) -> set[str]:
    out = {norm_platform(p) for p in ps if p.strip()}
    if "unix" in out:                     # unix-like covers linux and macos
        out |= {"linux", "macos"}
    return out


@dataclass
class RuleInput:
    in_range: bool | None
    conditions: AdvisoryConditions | None
    imported: bool | None                 # None = no searchable code (repo missing / unsupported ecosystem)
    symbol_hits: list[CodeHit] = field(default_factory=list)      # service code (qualified)
    dependent_hits: list[CodeHit] = field(default_factory=list)   # dependents' source
    searched: bool = False                                         # reachability search ran
    complete: bool = False                                         # every scope was inspectable
    quote_verified: bool = True                                    # advisory quote matched verbatim
    mode: str = "conservative"   # conservative: not_affected only on complete, all-absent evidence
                         # proactive: one unmet api/input condition suffices (more filtering, may miss)
    runtime: list[str] = field(default_factory=lambda: list(DEFAULT_RUNTIME))
    decision: Decision | None = None
    code_note: str = ""                   # why code is unavailable (imported is None)


@dataclass
class RuleResult:
    verdict: Verdict
    rule: str
    decided_by: str = "code"
    note: str = ""


def decide(x: RuleInput) -> RuleResult:
    if x.decision is not None:
        d = x.decision
        return RuleResult(d.verdict, "feedback_suppressed", "feedback",
                          f"{d.decision} by {d.by} at {d.at} (reason={d.reason}, scope={d.scope})")
    if x.in_range is False:
        return RuleResult("not_affected", "version_out_of_range", note="installed version outside OSV ranges")
    c = x.conditions
    if c is None:
        return RuleResult("uncertain", "llm_unavailable", note="advisory conditions not extracted")

    runtime = _platform_set(x.runtime)
    plat, rest, plat_ok = [], [], []
    for k in c.conditions:
        from_text = [] if k.platforms or _NEGATION.search(k.description or "") else _os_in_text(k.description)
        ps = _platform_set(k.platforms or from_text) if k.kind == "platform" else set()
        if not ps:
            rest.append(k)
        elif ps & runtime:
            plat.append(k)
            plat_ok.append(k)
        elif ps & KNOWN_OS:               # names an OS we do not run (extra tokens = qualifiers)
            plat.append(k)
        else:                             # only environments (node/browser/workerd/...) not in
            rest.append(k)                # the runtime list: undecidable by OS → not a platform verdict

    if c.unconditional or not c.conditions:
        return RuleResult("affected", "unconditional_version_match",
                          note="advisory states no precondition beyond the version")
    if plat and not plat_ok:
        ps = sorted({p for k in plat for p in _platform_set(k.platforms)})
        return RuleResult("not_affected", "platform_excluded",
                          note=f"advisory platforms {ps} vs runtime {sorted(runtime)}")
    if not rest:
        return RuleResult("affected", "unconditional_version_match",
                          note="only platform conditions, all matching the runtime")
    api = api_conditions(rest) if x.mode == "conservative" else [k for k in rest if k.kind in ("api", "input") and k.symbols]
    svc_syms = {h.symbol for h in x.symbol_hits}
    dep_syms = {h.symbol for h in x.dependent_hits}
    if api and x.searched and x.mode == "proactive":
        unmet = [k for k in api if not set(k.symbols) & (svc_syms | dep_syms)]
        if unmet:
            return RuleResult("not_affected", "api_not_referenced",
                              note=f"[proactive] required API not referenced: {sorted(s for k in unmet for s in k.symbols)}")
    if api and x.searched:
        all_syms = {s for k in api for s in k.symbols}
        if not (all_syms & (svc_syms | dep_syms)):
            if x.complete and x.quote_verified:
                return RuleResult("not_affected", "api_not_referenced",
                                  note=f"no advisory API referenced by service or dependents: {sorted(all_syms)}")
            why = "search incomplete" if not x.complete else "advisory quote not verified"
            return RuleResult("uncertain", "reachable_via_dependency",
                              note=f"no API reference found, but {why}; human/call-graph needed")
        if all(set(k.symbols) & svc_syms for k in api):
            if any(k.kind == "input" for k in rest):   # API used; is the data attacker-controlled?
                return RuleResult("uncertain", "input_trust_needs_human",
                                  note=f"API used in service code {sorted(svc_syms)}; whether the "
                                       "input is attacker-controlled needs a human")
            return RuleResult("affected", "condition_symbol_in_code",
                              note=f"required API used in service code: {sorted(svc_syms)}")
        return RuleResult("uncertain", "reachable_via_dependency",
                          note=f"API referenced (service {sorted(svc_syms)}, dependents {sorted(dep_syms)}); "
                               "call-graph needed")
    if x.imported is None:
        return RuleResult("uncertain", "code_unavailable",
                          note=f"{x.code_note or 'service code not available'}; conditions cannot be checked in code")
    if not x.imported:
        return RuleResult("uncertain", "transitive_needs_callgraph",
                          note="package not imported by service code; no searchable API symbol (call-graph: roadmap)")
    kinds = sorted({k.kind for k in rest if not (k.kind == "api" and k.symbols)})
    return RuleResult("uncertain", "condition_not_checkable",
                      note=f"conditions not checkable by code search: {kinds}")
