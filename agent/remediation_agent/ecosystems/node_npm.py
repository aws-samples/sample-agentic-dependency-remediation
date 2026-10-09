# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Node.js adapter for package.json manifests managed by npm."""

from __future__ import annotations

import json
import re
import urllib.parse

from .. import http
from ..workspace import Workspace, WorkspaceError
from .base import DependencyUpdate, EcosystemAdapter

_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_PREFIX = re.compile(r"^([\^~]|>=)?\s*v?(\d[\w.\-+]*)$")


class NodeNpmAdapter(EcosystemAdapter):
    name = "node"
    osv_ecosystem = "npm"
    lockfiles = ("package-lock.json",)

    def manifest_path(self, ws: Workspace, app_dir: str) -> str:
        path = self.join(app_dir, "package.json")
        if path not in ws.list_files(app_dir, limit=100000):
            raise WorkspaceError(f"No package.json found in '{app_dir or '.'}'.")
        return path

    def _load(self, ws: Workspace, app_dir: str) -> tuple[str, dict]:
        manifest = self.manifest_path(ws, app_dir)
        return manifest, json.loads((ws.root / manifest).read_text())

    def current_version(self, ws: Workspace, app_dir: str, package: str) -> str | None:
        _, data = self._load(ws, app_dir)
        for section in _SECTIONS:
            spec = data.get(section, {}).get(package)
            if spec:
                match = _PREFIX.match(spec.strip())
                return match.group(2) if match else None
        return None

    def update_dependency(self, ws: Workspace, app_dir: str, package: str, version: str) -> DependencyUpdate:
        manifest, data = self._load(ws, app_dir)
        for section in _SECTIONS:
            deps = data.get(section, {})
            if package in deps:
                old = deps[package]
                match = _PREFIX.match(old.strip())
                prefix = (match.group(1) or "") if match else ""
                deps[package] = f"{prefix}{version}"
                raw = (ws.root / manifest).read_text()
                indent = 4 if re.search(r'^\s{4}"', raw, re.MULTILINE) and not re.search(r'^\s{2}"', raw, re.MULTILINE) else 2
                ws.write_file(manifest, json.dumps(data, indent=indent) + "\n")
                return DependencyUpdate(manifest, f'"{package}": "{old}"', f'"{package}": "{deps[package]}"')
        raise WorkspaceError(f"'{package}' is not declared in {manifest}. It may be a transitive dependency; consider an npm 'overrides' entry.")

    def list_dependencies(self, ws: Workspace, app_dir: str) -> dict[str, str]:
        _, data = self._load(ws, app_dir)
        deps = {}
        for section in _SECTIONS:
            for name, spec in data.get(section, {}).items():
                match = _PREFIX.match(str(spec).strip())
                if match:
                    deps[name] = match.group(2)
        return deps

    def registry_versions(self, package: str) -> list[str]:
        encoded = urllib.parse.quote(package, safe="@")
        data = http.request("GET", f"https://registry.npmjs.org/{encoded}")
        deprecated = {v for v, meta in data.get("versions", {}).items() if meta.get("deprecated")}
        return [v for v in data.get("versions", {}) if v not in deprecated]
