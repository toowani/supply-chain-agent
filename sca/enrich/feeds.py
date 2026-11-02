"""Public threat-intel feeds: FIRST EPSS, CISA KEV, OSV advisories. Cached on disk so runs are
reproducible offline (`--offline`). Only public identifiers (CVE/GHSA) leave the machine;
no internal asset data is sent anywhere."""
from __future__ import annotations

import datetime as dt
import json
import os
import time

import requests

from sca.config import CACHE_DIR

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/vulns/{}"
UA = {"User-Agent": os.environ.get("SCA_HTTP_USER_AGENT", "supply-chain-agent-poc/0.1")}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get(url: str, params: dict | None = None, retries: int = 3) -> requests.Response:
    for i in range(retries):
        try:
            r = requests.get(url, params=params, headers=UA, timeout=30)
            if r.status_code == 404:
                return r
            r.raise_for_status()
            return r
        except requests.RequestException:
            if i == retries - 1:
                raise
            time.sleep(2 ** i)
    raise RuntimeError("unreachable")


def _read(name: str) -> dict:
    p = CACHE_DIR / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _write(name: str, data: dict) -> None:
    p = CACHE_DIR / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def fetch_epss(cves: list[str], offline: bool = False) -> dict[str, dict]:
    """{cve: {epss, percentile, date}} — CVEs FIRST has no score for are absent."""
    cache = _read("epss.json")
    scores, fetched = cache.get("scores", {}), set(cache.get("queried", []))
    todo = sorted(set(cves) - fetched)
    if todo and not offline:
        for i in range(0, len(todo), 80):
            batch = todo[i:i + 80]
            data = _get(EPSS_URL, {"cve": ",".join(batch)}).json()
            for row in data.get("data", []):
                scores[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                                      "date": row.get("date", "")}
            fetched |= set(batch)
        _write("epss.json", {"fetched_at": _now(), "queried": sorted(fetched), "scores": scores})
    return {c: scores[c] for c in cves if c in scores}


def fetch_kev(offline: bool = False, max_age_h: float = 24) -> dict[str, dict]:
    """{cve: {dateAdded, knownRansomwareCampaignUse, ...}} from the CISA KEV catalog."""
    cache = _read("kev.json")
    fresh = False
    if cache.get("fetched_at"):
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.strptime(
            cache["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        fresh = age.total_seconds() < max_age_h * 3600
    if not offline and not fresh:
        cat = _get(KEV_URL).json()
        cache = {"fetched_at": _now(), "catalogVersion": cat.get("catalogVersion"),
                 "count": cat.get("count"),
                 "vulns": {v["cveID"]: {k: v.get(k) for k in
                                        ("dateAdded", "dueDate", "knownRansomwareCampaignUse",
                                         "vulnerabilityName")}
                           for v in cat["vulnerabilities"]}}
        _write("kev.json", cache)
    return cache.get("vulns", {})


def fetch_osv(ids: list[str], offline: bool = False) -> dict[str, dict]:
    """Advisory text for the judge stage (day 2). {id: osv_record | {} if not found}."""
    out = {}
    for vid in sorted(set(ids)):
        name = f"osv/{vid}.json"
        rec = _read(name)
        if not rec and not offline:
            r = _get(OSV_URL.format(vid))
            rec = r.json() if r.status_code == 200 else {"_missing": True}
            _write(name, rec)
        out[vid] = {} if rec.get("_missing") else rec
    return out


def kev_meta() -> dict:
    c = _read("kev.json")
    return {"fetched_at": c.get("fetched_at"), "catalogVersion": c.get("catalogVersion"),
            "count": c.get("count")}


def epss_meta() -> dict:
    return {"fetched_at": _read("epss.json").get("fetched_at")}


def fetch_pypi_release(name: str, version: str, offline: bool = False) -> dict:
    """PyPI JSON for one release (public). Cached; {} when unavailable."""
    path = f"pypi/{name}-{version}.json"
    rec = _read(path)
    if not rec and not offline:
        try:
            r = _get(f"https://pypi.org/pypi/{name}/{version}/json")
            info = r.json().get("info", {}) if r.status_code == 200 else {}
            rec = {"requires_python": info.get("requires_python") or "", "fetched_at": _now()}
        except requests.RequestException:
            rec = {}
        if rec:
            _write(path, rec)
    return rec
