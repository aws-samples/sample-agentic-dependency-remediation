# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Ecosystem adapter interface and shared version helpers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..workspace import Workspace

_STABLE = re.compile(r"^v?(\d+(?:\.\d+)*)(?:\.RELEASE|\.Final)?$", re.IGNORECASE)


def parse_version(version: str) -> tuple[int, ...] | None:
    """Parse a stable release version. Returns None for pre-releases and snapshots."""
    match = _STABLE.match(version.strip())
    if not match:
        return None
    parts = [int(p) for p in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()  # 2.0.0 == 2.0 == 2
    return tuple(parts)


def sort_stable(versions: list[str]) -> list[str]:
    parsed = [(parse_version(v), v) for v in versions]
    return [v for key, v in sorted((p for p in parsed if p[0] is not None), key=lambda p: p[0])]


def major(version: str) -> int | None:
    parsed = parse_version(version)
    return parsed[0] if parsed else None


@dataclass
class DependencyUpdate:
    manifest: str
    old_spec: str
    new_spec: str


class EcosystemAdapter(ABC):
    #: Identifier used in payloads and the build script.
    name: str
    #: Ecosystem name in the OSV database.
    osv_ecosystem: str
    #: Files that the build regenerates and uploads back (lockfiles).
    lockfiles: tuple[str, ...] = ()

    @abstractmethod
    def manifest_path(self, ws: Workspace, app_dir: str) -> str:
        """Return the relative manifest path, or raise if not found."""

    @abstractmethod
    def current_version(self, ws: Workspace, app_dir: str, package: str) -> str | None:
        """Return the declared version of the package, or None if it is not declared directly."""

    @abstractmethod
    def update_dependency(self, ws: Workspace, app_dir: str, package: str, version: str) -> DependencyUpdate:
        """Change the declared version in the manifest."""

    @abstractmethod
    def registry_versions(self, package: str) -> list[str]:
        """Return all published versions of the package."""

    @abstractmethod
    def list_dependencies(self, ws: Workspace, app_dir: str) -> dict[str, str]:
        """Return {package: version} for directly declared dependencies that have an exact version."""

    def detect(self, ws: Workspace, app_dir: str) -> bool:
        """True if the manifest for this ecosystem exists in app_dir."""
        try:
            self.manifest_path(ws, app_dir)
            return True
        except Exception:
            return False

    def normalize(self, package: str) -> str:
        return package

    @staticmethod
    def join(app_dir: str, filename: str) -> str:
        app_dir = app_dir.strip("/")
        return f"{app_dir}/{filename}" if app_dir else filename
