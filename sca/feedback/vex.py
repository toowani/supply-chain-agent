"""OpenVEX v0.2.0 export of judgments — shareable machine-readable 'not affected' evidence.

Only public identifiers go out: vulnerability id, package purl, status, justification and a
generic impact statement derived from the rule. No service names, local paths, code hits or notes.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid
from pathlib import Path
from urllib.parse import quote

from sca.contracts import Judgment
from sca.feedback.store import is_demo

CONTEXT = "https://openvex.dev/ns/v0.2.0"
_NS = uuid.UUID("6f1c3a52-2d0e-4b7a-9f4e-5c1a7e0b9d10")

# (substring of rule, justification, impact statement) — first match wins
_RULES: list[tuple[str, str, str]] = [
    ("false_positive", "component_not_present",
     "Reviewer determined the scanner matched the wrong component or version."),
    ("dev_only", "vulnerable_code_cannot_be_controlled_by_adversary",
     "Component is used only by build/test tooling and never processes untrusted input."),
    ("platform", "vulnerable_code_cannot_be_controlled_by_adversary",
     "The advisory's platform/runtime precondition does not hold for the deployed environment."),
    ("version_out_of_range", "vulnerable_code_not_present",
     "Installed version is outside the advisory's affected version ranges."),
    ("api_not_referenced", "vulnerable_code_not_in_execute_path",
     "The vulnerable API named in the advisory is not referenced by the product's code."),
    ("not_reachable", "vulnerable_code_not_in_execute_path",
     "Reviewer determined the vulnerable code path is not used."),
    ("transitive", "vulnerable_code_not_in_execute_path",
     "Component is a transitive dependency and the vulnerable entry point is not reached."),
]
_RANK = {"affected": 0, "under_investigation": 1, "not_affected": 2}


def purl_of(pkg_key: str) -> str:
    """'pypi:pillow@11.3.0' → 'pkg:pypi/pillow@11.3.0' ('npm:@a/b@1' → 'pkg:npm/%40a/b@1')."""
    eco, _, rest = pkg_key.partition(":")
    i = rest.rfind("@")
    name, ver = (rest[:i], rest[i + 1:]) if i > 0 else (rest, "")
    if name.startswith("@"):
        name = quote(name[:1]) + name[1:]
    return f"pkg:{eco}/{name}" + (f"@{ver}" if ver else "")


def _status(v: str) -> str:
    return {"affected": "affected", "not_affected": "not_affected"}.get(v, "under_investigation")


def _reason(j: Judgment) -> str:
    """Reviewer reason code of a feedback-decided judgment (judge writes 'reason=<code>' in the
    evidence note for rule 'feedback_suppressed'), else ''."""
    m = re.search(r"reason=([a-z_]+)", str((j.evidence or {}).get("note", "")))
    return m.group(1) if m and (j.decided_by == "feedback" or "feedback" in j.rule) else ""


def _eff_status(j: Judgment) -> str:
    return "affected" if _reason(j) == "accepted_risk" else _status(j.verdict)


def _justify(rule: str, reason: str = "") -> tuple[str, str]:
    """Reviewer reason first (it is the decision), then the judge rule."""
    for r in (reason.strip().lower(), rule.strip().lower()):
        if not r:
            continue
        for sub, just, stmt in _RULES:
            if sub in r:
                return just, stmt
    return "", f"Determined not affected by rule '{rule.strip()}'."


def build_openvex(judgments: list[Judgment], author: str, timestamp: str | None = None) -> dict:
    """One statement per (vuln, purl); across services the worst status wins
    (affected > under_investigation > not_affected)."""
    ts = timestamp or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    best: dict[tuple[str, str], Judgment] = {}
    for j in sorted(judgments, key=lambda j: (j.cve, j.package, j.rule, j.service)):
        key = (j.cve, purl_of(j.package))
        cur = best.get(key)
        if cur is None or _RANK[_eff_status(j)] < _RANK[_eff_status(cur)]:
            best[key] = j
    statements = []
    for (vid, purl), j in sorted(best.items()):
        reason = _reason(j)
        st: dict = {"vulnerability": {"name": vid}, "products": [{"@id": purl}], "status": _status(j.verdict)}
        if reason == "accepted_risk":
            # an accepted risk is still affected — never publish it as not_affected
            st["status"] = "affected"
            st["action_statement"] = "Risk accepted by reviewer; remediation deferred."
        elif st["status"] == "not_affected":
            just, stmt = _justify(j.rule, reason)
            if just:
                st["justification"] = just
            st["impact_statement"] = stmt
        elif st["status"] == "affected":
            st["action_statement"] = ("Upgrade to a fixed version." +
                                      (f" Workaround: {j.workaround}" if j.workaround else ""))
        else:
            st["status_notes"] = "Automated analysis inconclusive; queued for human review."
        if is_demo(j):
            st["status_notes"] = "Demonstration feedback record (PoC), not a real review."
        statements.append(st)
    digest = hashlib.sha256(json.dumps([author, statements], sort_keys=True).encode()).hexdigest()
    return {"@context": CONTEXT, "@id": f"urn:uuid:{uuid.uuid5(_NS, digest)}", "author": author,
            "timestamp": ts, "version": 1, "statements": statements}


def write_openvex(judgments: list[Judgment], path: Path | str, author: str,
                  timestamp: str | None = None) -> dict:
    """Write the OpenVEX document to `path` and return it."""
    doc = build_openvex(judgments, author, timestamp)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    return doc
