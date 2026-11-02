"""Reviewer decisions (approve/reject + reason) as append-only JSONL — the "개선" loop input.

Notes are internal data: examples_for() output may only go into a prompt when llm.is_trusted
(local or in-house host).
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from sca.config import ROOT
from sca.contracts import Decision

FEEDBACK_PATH = ROOT / "data" / "feedback" / "decisions.jsonl"
# reasons that suppress (not_affected) or force (confirmed → affected) the next judgment
# reviewer ids of demonstration records (not a real review) — reports label them as such
DEMO_BY = {"demo-reviewer"}
EFFECTIVE_REASONS = {"not_reachable", "platform", "dev_only", "false_positive", "accepted_risk", "confirmed"}


def pkg_name_key(pkg: str) -> str:
    """'pypi:pillow@11.3.0' → 'pypi:pillow'; keeps npm scopes ('npm:@a/b@1.0' → 'npm:@a/b')."""
    eco, sep, rest = pkg.partition(":")
    if not sep:
        eco, rest = "", pkg
    i = rest.rfind("@")
    if i > 0:
        rest = rest[:i]
    return f"{eco}:{rest}" if sep else rest


class FeedbackStore:
    def __init__(self, path: Path | str = FEEDBACK_PATH):
        self.path = Path(path)
        self._items: list[Decision] = []
        self.load()

    def load(self) -> list[Decision]:
        """(Re)read the JSONL file; blank lines skipped, malformed lines raise."""
        self._items = []
        if self.path.exists():
            for n, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
                if line.strip():
                    try:
                        self._items.append(Decision.model_validate_json(line))
                    except ValueError as e:
                        raise ValueError(f"{self.path}:{n}: invalid decision: {e}") from e
        return list(self._items)

    def add(self, d: Decision | dict) -> Decision:
        """Validate and append one decision (package normalised to version-free 'eco:name')."""
        d = Decision.model_validate(d) if isinstance(d, dict) else Decision.model_validate(d.model_dump())
        d = d.model_copy(update={"package": pkg_name_key(d.package)})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(d.model_dump_json() + "\n")
        self._items.append(d)
        return d

    def decisions(self) -> list[Decision]:
        return list(self._items)

    def _matching(self, service: str, package: str, vuln_ids: set[str]) -> list[Decision]:
        pkg = pkg_name_key(package)
        hits = [(at_key(d.at), i, d) for i, d in enumerate(self._items)
                if d.package == pkg and d.vuln_id in vuln_ids
                and (d.service == service or d.scope == "all_services")]
        return [d for _, _, d in sorted(hits, key=lambda t: (t[0], t[1]))]

    def suppression(self, service: str, package: str, vuln_id: str,
                    aliases: list[str] | tuple[str, ...] = ()) -> Decision | None:
        """Latest decision for (service, package, vuln or any alias) if it suppresses/forces the
        verdict. Latest wins (by parsed `at`, then file order); 'all_services' scope applies to
        any service. A latest 'fixed' decision returns None (re-judge; rescan_verify checks it)."""
        hits = self._matching(service, package, {vuln_id, *aliases})
        if not hits or hits[-1].reason not in EFFECTIVE_REASONS:
            return None
        return hits[-1]

    def examples_for(self, package: str, vuln_id: str, n: int = 3) -> list[str]:
        """Few-shot lines from prior decisions on the same package (any vuln), same vuln first,
        then most recent. Contains internal notes → local/in-house (trusted) LLM only."""
        pkg = pkg_name_key(package)
        ds = [(i, d) for i, d in enumerate(self._items) if d.package == pkg]
        ds.sort(key=lambda t: (t[1].vuln_id != vuln_id, -at_key(t[1].at).timestamp(), -t[0]))
        out = []
        for _, d in ds[:n]:
            note = " ".join(d.note.split())[:160]
            out.append(f"{d.package} {d.vuln_id} → {d.verdict} ({d.reason})" + (f": {note}" if note else ""))
        return out


def feedback_by(j) -> str:
    """Reviewer id behind a feedback-decided Judgment ('' otherwise). judge stores it in
    evidence['feedback_by']; older outputs only have the note 'reject by <id> at …'."""
    if getattr(j, "decided_by", "") != "feedback":
        return ""
    ev = getattr(j, "evidence", None) or {}
    if ev.get("feedback_by"):
        return str(ev["feedback_by"])
    m = re.search(r"\bby (\S+) at ", str(ev.get("note", "")))
    return m.group(1) if m else ""


def is_demo(j) -> bool:
    """Judgment decided by a demonstration feedback record (DEMO_BY), not a real review."""
    return feedback_by(j) in DEMO_BY


def at_key(at: str) -> dt.datetime:
    """Parse an ISO8601 `at` to an aware UTC datetime ('Z', offsets, fractions all compare
    correctly; naive → UTC; unparseable → epoch so it never wins 'latest')."""
    try:
        t = dt.datetime.fromisoformat(at.strip().replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime.fromtimestamp(0, dt.timezone.utc)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
