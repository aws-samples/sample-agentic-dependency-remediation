# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Python adapter for requirements.txt manifests."""

from __future__ import annotations

import re
import urllib.parse

from .. import http
from ..workspace import Workspace, WorkspaceError
from .base import DependencyUpdate, EcosystemAdapter

# name[extras] <spec> ; markers   # comment
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<spec>[=<>!~][^;#]*)?(?P<rest>.*)$"
)


def canonical(name: str) -> str:
    """PEP 503 normalized project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


class PythonPipAdapter(EcosystemAdapter):
    name = "python"
    osv_ecosystem = "PyPI"
    lockfiles = ()

    def normalize(self, package: str) -> str:
        return canonical(package)

    def manifest_path(self, ws: Workspace, app_dir: str) -> str:
        path = self.join(app_dir, "requirements.txt")
        if path not in ws.list_files(app_dir, limit=100000):
            raise WorkspaceError(f"No requirements.txt found in '{app_dir or '.'}'.")
        return path

    def _find(self, text: str, package: str):
        target = canonical(package)
        for index, line in enumerate(text.splitlines()):
            match = _REQ_LINE.match(line.strip())
            if match and canonical(match.group("name")) == target:
                return index, match
        return None, None

    def current_version(self, ws: Workspace, app_dir: str, package: str) -> str | None:
        text = (ws.root / self.manifest_path(ws, app_dir)).read_text()
        _, match = self._find(text, package)
        if not match or not match.group("spec"):
            return None
        pinned = re.search(r"==\s*([^\s,]+)", match.group("spec"))
        return pinned.group(1) if pinned else None

    def update_dependency(self, ws: Workspace, app_dir: str, package: str, version: str) -> DependencyUpdate:
        manifest = self.manifest_path(ws, app_dir)
        lines = (ws.root / manifest).read_text().splitlines()
        index, match = self._find("\n".join(lines), package)
        if match is None:
            raise WorkspaceError(f"'{package}' is not declared in {manifest}. It may be a transitive dependency.")
        old = lines[index]
        extras = match.group("extras") or ""
        rest = match.group("rest").strip()
        new = f"{match.group('name')}{extras}=={version}" + (f" {rest}" if rest else "")
        lines[index] = new
        ws.write_file(manifest, "\n".join(lines) + "\n")
        return DependencyUpdate(manifest, old.strip(), new)

    def list_dependencies(self, ws: Workspace, app_dir: str) -> dict[str, str]:
        deps = {}
        for line in (ws.root / self.manifest_path(ws, app_dir)).read_text().splitlines():
            match = _REQ_LINE.match(line.strip())
            if match and match.group("spec"):
                pinned = re.search(r"==\s*([^\s,]+)", match.group("spec"))
                if pinned:
                    deps[canonical(match.group("name"))] = pinned.group(1)
        return deps

    def registry_versions(self, package: str) -> list[str]:
        data = http.request("GET", f"https://pypi.org/pypi/{urllib.parse.quote(canonical(package))}/json")
        releases = data.get("releases", {})
        # Skip versions where every uploaded file is yanked.
        return [v for v, files in releases.items() if files and not all(f.get("yanked") for f in files)]
