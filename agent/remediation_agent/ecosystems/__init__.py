# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Ecosystem adapters. To add an ecosystem, implement EcosystemAdapter and register it here."""

from .base import DependencyUpdate, EcosystemAdapter, major, parse_version, sort_stable  # noqa: F401
from .java_maven import JavaMavenAdapter
from .node_npm import NodeNpmAdapter
from .python_pip import PythonPipAdapter

ADAPTERS: dict[str, EcosystemAdapter] = {
    adapter.name: adapter for adapter in (PythonPipAdapter(), NodeNpmAdapter(), JavaMavenAdapter())
}


def get_adapter(ecosystem: str) -> EcosystemAdapter:
    try:
        return ADAPTERS[ecosystem.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported ecosystem '{ecosystem}'. Supported: {', '.join(ADAPTERS)}") from exc


def detect_adapter(ws, app_dir: str) -> EcosystemAdapter:
    """Pick the ecosystem from the manifest found in app_dir. Exactly one must match."""
    found = [adapter for adapter in ADAPTERS.values() if adapter.detect(ws, app_dir)]
    if len(found) != 1:
        names = ", ".join(a.name for a in found) or "none"
        raise ValueError(f"Could not detect a single ecosystem in '{app_dir or '.'}' (found: {names}). Set 'ecosystem' in remediation.json.")
    return found[0]


__all__ = [
    "ADAPTERS",
    "DependencyUpdate",
    "EcosystemAdapter",
    "detect_adapter",
    "get_adapter",
    "major",
    "parse_version",
    "sort_stable",
]
