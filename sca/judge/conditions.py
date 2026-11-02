"""Advisory text → AdvisoryConditions (LLM). PUBLIC data only: OSV summary/details, package
name and affected ranges. No asset info, service code or reviewer notes go into the prompt;
few-shot `examples` (which may be built from reviewer feedback) are included only when the
backend is local or an in-house trusted host (llm.is_trusted, SCA_LLM_TRUSTED_HOSTS).

Post-checks are deterministic: the quote is verified verbatim against the advisory, and
symbols that do not occur in the advisory text are dropped (hallucination guard).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from sca.config import CACHE_DIR
from sca.contracts import AdvisoryConditions
from sca.llm import trusted

PROMPT_VERSION = 1
MAX_DETAILS = 6000
COND_CACHE = CACHE_DIR / "judge" / "conditions"

SYSTEM = """You read ONE public security advisory and extract the preconditions that must hold,
beyond having a vulnerable version installed, for an application to be exploitable.

Return JSON for the given schema:
- unconditional: true ONLY if the advisory imposes no precondition beyond the vulnerable version
  (any use of the package is affected). If any API, option, platform, input or feature must be
  used/enabled, unconditional is false and each such precondition is listed in conditions.
- conditions[].kind, exactly one of:
    api      - the application must call/use a specific function, class, method or module
    config   - a specific setting/option/flag/environment value must be set (or left default)
    platform - only on specific OS/runtime (fill platforms with: windows, linux, macos, android,
               ios, freebsd, browser, node, workerd)
    input    - the application must pass attacker-controlled input of a certain kind
    feature  - an optional feature/extra/plugin/optional dependency must be installed or enabled
    other    - anything else
- conditions[].description: one short English sentence.
- conditions[].symbols: concrete identifiers a developer could grep for in application code
  (function, class, method, module, option/parameter names) exactly as spelled in the
  advisory. No prose, no generic words, no file paths of the library itself. May be empty.
- advisory_quote: ONE sentence copied VERBATIM from the advisory that best supports the
  conditions (or states that any use is affected). Do not paraphrase.
- workaround: mitigation stated in the advisory other than upgrading, else "".
Do not invent conditions or identifiers that the advisory does not state."""


def advisory_text(record: dict) -> str:
    return "\n\n".join(x for x in (record.get("summary", ""), record.get("details", "")) if x)


def build_user_prompt(vuln_id: str, ecosystem: str, package: str, ranges: list[list[str]],
                      record: dict) -> str:
    rng = "; ".join(f">={lo or '0'}" + (f", <{hi}" if hi else "") for lo, hi in ranges) or "unknown"
    details = (record.get("details") or "")[:MAX_DETAILS]
    return (f"Advisory: {vuln_id}\nPackage: {ecosystem}:{package}\nAffected ranges: {rng}\n\n"
            f"Summary: {record.get('summary', '')}\n\nDetails:\n{details}")


def _norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def quote_verified(quote: str, text: str) -> bool:
    q = _norm_ws(quote.strip().strip('"').strip())
    return bool(q) and q in _norm_ws(text)


def sanitize(c: AdvisoryConditions, text: str) -> tuple[AdvisoryConditions, list[str]]:
    """Drop symbols not present in the advisory (exact or last dotted segment); return dropped."""
    from sca.judge.code_search import clean_symbol
    dropped: list[str] = []
    for cond in c.conditions:
        keep = []
        for s in cond.symbols:
            cs = clean_symbol(s)
            last = cs.rsplit(".", 1)[-1]
            if cs and (cs in text or (len(last) >= 3 and last in text)):
                keep.append(cs)
            else:
                dropped.append(s)
        cond.symbols = list(dict.fromkeys(keep))
        cond.platforms = [p.strip().lower() for p in cond.platforms if p.strip()]
    return c, dropped


def _cache_path(vuln_id: str, package: str, model: str, examples: str = "", text: str = "") -> Path:
    """Key = (vuln, package, model, prompt version, few-shot examples, advisory text): an OSV
    record edited upstream re-extracts instead of serving stale conditions."""
    raw = f"{vuln_id}|{package}|{model}|v{PROMPT_VERSION}" + (f"|ex:{examples}" if examples else "")
    if text:
        raw += "|t:" + hashlib.sha1(text.encode()).hexdigest()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{vuln_id}__{package}")[:120]
    return COND_CACHE / f"{safe}__{hashlib.sha1(raw.encode()).hexdigest()[:10]}.json"


def extract_conditions(vuln_id: str, ecosystem: str, package: str, ranges: list[list[str]],
                       record: dict, llm, examples: list[str] | None = None,
                       use_cache: bool = True) -> tuple[AdvisoryConditions | None, dict]:
    """(conditions | None if the LLM is unavailable, meta{seconds, cached, quote_verified,
    dropped_symbols}). No advisory text → rule fallback: no stated condition (unconditional)."""
    text = advisory_text(record)
    if not text:
        c = AdvisoryConditions(vuln_id=vuln_id, package=package, unconditional=True, model="rule")
        return c, {"seconds": 0.0, "cached": False, "quote_verified": False, "dropped_symbols": [],
                   "no_advisory_text": True}
    if llm is None:
        return None, {"seconds": 0.0, "cached": False, "error": "no LLM backend (--no-llm or unreachable)"}
    shots = "\n---\n".join(examples) if examples and trusted(llm) else ""
    path = _cache_path(vuln_id, package, llm.name, shots, text)
    if use_cache and path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return AdvisoryConditions(**data["conditions"]), {**data["meta"], "cached": True}
        except (OSError, ValueError, KeyError, TypeError):
            pass                    # corrupt/partial cache file → re-extract and overwrite
    if getattr(llm, "cache_only", False):   # backend unreachable: cached extractions only
        return None, {"seconds": 0.0, "cached": False,
                      "error": "LLM backend unreachable and no cached conditions"}
    system = SYSTEM + (f"\n\nExamples of past correct extractions:\n{shots}" if shots else "")
    t0 = time.perf_counter()
    try:
        c = llm.structured(system, build_user_prompt(vuln_id, ecosystem, package, ranges, record),
                           AdvisoryConditions)
    except Exception as e:          # connection refused, model missing, invalid output …
        return None, {"seconds": round(time.perf_counter() - t0, 3), "cached": False,
                      "error": f"{type(e).__name__}: {e}"[:300]}
    secs = round(time.perf_counter() - t0, 3)
    c.vuln_id, c.package, c.model = vuln_id, package, llm.name
    c, dropped = sanitize(c, text)
    meta = {"seconds": secs, "cached": False, "quote_verified": quote_verified(c.advisory_quote, text),
            "dropped_symbols": dropped, "prompt_version": PROMPT_VERSION}
    if use_cache:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"conditions": c.model_dump(), "meta": meta}, ensure_ascii=False,
                                   indent=1), encoding="utf-8")
    return c, meta
