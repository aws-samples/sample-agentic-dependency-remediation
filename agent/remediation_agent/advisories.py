# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Vulnerability lookups against the Open Source Vulnerabilities (OSV) database."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import http
from .ecosystems import EcosystemAdapter, major, parse_version, sort_stable

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_CANDIDATES_CHECKED = 25


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    fixed_versions: list[str] = field(default_factory=list)


def query(adapter: EcosystemAdapter, package: str, version: str) -> list[Advisory]:
    body = {"package": {"name": adapter.normalize(package), "ecosystem": adapter.osv_ecosystem}, "version": version}
    data = http.request("POST", OSV_QUERY_URL, body=body) or {}
    advisories = []
    for vuln in data.get("vulns", []):
        fixed = []
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                fixed.extend(e["fixed"] for e in rng.get("events", []) if "fixed" in e)
        advisories.append(
            Advisory(
                id=vuln.get("id", ""),
                aliases=vuln.get("aliases", []),
                summary=(vuln.get("summary") or vuln.get("details", ""))[:300],
                fixed_versions=sorted(set(fixed)),
            )
        )
    return advisories


@dataclass
class VersionChoice:
    target: str | None
    current: str
    checked: list[str]
    major_change: bool
    remaining_advisories: list[str]
    note: str


def _next_floor(found: list[Advisory], version: tuple[int, ...]) -> tuple[int, ...] | None:
    """Highest of the per-advisory 'first fixed version above `version`'. None if unknown."""
    floors = []
    for advisory in found:
        fixes = [p for p in (parse_version(f) for f in advisory.fixed_versions) if p and p > version]
        if fixes:
            floors.append(min(fixes))
    return max(floors) if floors else None


def choose_safe_version(adapter: EcosystemAdapter, package: str, current: str, minimum: str | None = None) -> VersionChoice:
    """Return the lowest stable version above `current` (and at least `minimum`) with no known advisories.

    Instead of testing every release, the search jumps to the first version that
    fixes all advisories affecting the version under test, then confirms with OSV.
    """
    current_parsed = parse_version(current)
    if current_parsed is None:
        return VersionChoice(None, current, [], False, [], f"Cannot parse current version '{current}'.")
    floor = current_parsed
    if minimum and parse_version(minimum):
        floor = max(floor, parse_version(minimum))
    if jump := _next_floor(query(adapter, package, current), current_parsed):
        floor = max(floor, jump)
    candidates = [v for v in sort_stable(adapter.registry_versions(package)) if parse_version(v) > current_parsed]
    checked: list[str] = []
    last_ids: list[str] = []
    for candidate in candidates:
        parsed = parse_version(candidate)
        if parsed < floor:
            continue
        if len(checked) >= MAX_CANDIDATES_CHECKED:
            break
        checked.append(candidate)
        found = query(adapter, package, candidate)
        if found and (jump := _next_floor(found, parsed)):
            floor = max(floor, jump)
        if not found:
            return VersionChoice(
                target=candidate,
                current=current,
                checked=checked,
                major_change=major(candidate) != major(current),
                remaining_advisories=[],
                note="Lowest stable version with no known advisories in OSV.",
            )
        last_ids = [a.id for a in found]
    return VersionChoice(None, current, checked, False, last_ids, "No advisory-free version found in the checked range.")
