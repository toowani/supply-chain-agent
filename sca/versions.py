"""Deterministic version comparison per ecosystem. Never compare version strings directly
("2.10.0" < "2.9.0" is True as strings)."""
from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver_key(v: str):
    m = _SEMVER.match(v.strip())
    if not m:
        raise ValueError(f"not semver: {v!r}")
    core = tuple(int(x or 0) for x in m.group(1, 2, 3))
    pre = m.group(4)
    return core, pre


def _cmp_pre(a: str | None, b: str | None) -> int:
    # semver §11: a version without prerelease ranks higher than one with it
    if a == b:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1
    for x, y in zip(a.split("."), b.split(".")):
        if x == y:
            continue
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            return -1 if int(x) < int(y) else 1
        if xd != yd:
            return -1 if xd else 1          # numeric identifiers rank lower
        return -1 if x < y else 1
    la, lb = len(a.split(".")), len(b.split("."))
    return (la > lb) - (la < lb)


def compare(ecosystem: str, a: str, b: str) -> int:
    """-1 / 0 / 1. ecosystem: 'pypi' | 'npm' | other (falls back to PEP 440, then semver)."""
    if ecosystem == "npm":
        (ca, pa), (cb, pb) = _semver_key(a), _semver_key(b)
        if ca != cb:
            return -1 if ca < cb else 1
        return _cmp_pre(pa, pb)
    try:
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        return compare("npm", a, b)


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    return sorted(versions, key=cmp_to_key(lambda x, y: compare(ecosystem, x, y)))


def is_newer(ecosystem: str, candidate: str, current: str) -> bool:
    try:
        return compare(ecosystem, candidate, current) > 0
    except ValueError:
        return False
