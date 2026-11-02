"""Helper for recording one reviewer decision (used by a CLI subcommand or the Streamlit app)."""
from __future__ import annotations

import datetime as dt

from sca.contracts import Decision
from sca.feedback.store import FeedbackStore, pkg_name_key


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_decision_from_args(service: str, package: str, vuln_id: str, decision: str, verdict: str,
                           reason: str, note: str = "", scope: str = "service", by: str = "reviewer",
                           store: FeedbackStore | None = None) -> Decision:
    """Build a validated Decision stamped with UTC now; also appends it when `store` is given."""
    d = Decision(service=service, package=pkg_name_key(package), vuln_id=vuln_id, decision=decision,
                 verdict=verdict, reason=reason, note=note, scope=scope, at=utc_now(), by=by)
    return store.add(d) if store is not None else d
