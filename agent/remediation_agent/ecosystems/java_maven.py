# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Java adapter for Maven pom.xml manifests.

Edits are made with targeted text substitution instead of an XML round-trip,
so that comments and formatting in the POM are preserved.
"""

from __future__ import annotations

import re
# defusedxml blocks entity expansion (billion laughs), external entities (XXE), and DTD retrieval.
import defusedxml.ElementTree as ET

from .. import http
from ..workspace import Workspace, WorkspaceError
from .base import DependencyUpdate, EcosystemAdapter

_DEPENDENCY = re.compile(r"<dependency>.*?</dependency>", re.DOTALL)
_PROPERTY_REF = re.compile(r"^\$\{([^}]+)\}$")
_COORDINATE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,200}$")


def _tag(block: str, tag: str) -> str | None:
    match = re.search(rf"<{tag}>\s*([^<]+?)\s*</{tag}>", block)
    return match.group(1) if match else None


class JavaMavenAdapter(EcosystemAdapter):
    name = "java"
    osv_ecosystem = "Maven"
    lockfiles = ()

    def manifest_path(self, ws: Workspace, app_dir: str) -> str:
        path = self.join(app_dir, "pom.xml")
        if path not in ws.list_files(app_dir, limit=100000):
            raise WorkspaceError(f"No pom.xml found in '{app_dir or '.'}'.")
        return path

    @staticmethod
    def _split(package: str) -> tuple[str, str]:
        if ":" not in package:
            raise WorkspaceError("Maven packages must use the form groupId:artifactId.")
        group, artifact = package.split(":", 1)
        return group.strip(), artifact.strip()

    def _locate(self, text: str, package: str):
        group, artifact = self._split(package)
        for match in _DEPENDENCY.finditer(text):
            block = match.group(0)
            if _tag(block, "groupId") == group and _tag(block, "artifactId") == artifact:
                return match
        return None

    def current_version(self, ws: Workspace, app_dir: str, package: str) -> str | None:
        text = (ws.root / self.manifest_path(ws, app_dir)).read_text()
        match = self._locate(text, package)
        if not match:
            return None
        version = _tag(match.group(0), "version")
        if version and (ref := _PROPERTY_REF.match(version)):
            return _tag(text, ref.group(1))
        return version

    def update_dependency(self, ws: Workspace, app_dir: str, package: str, version: str) -> DependencyUpdate:
        manifest = self.manifest_path(ws, app_dir)
        text = (ws.root / manifest).read_text()
        match = self._locate(text, package)
        if not match:
            raise WorkspaceError(f"'{package}' is not declared in {manifest}. It may be a transitive dependency; add it to <dependencyManagement>.")
        block = match.group(0)
        declared = _tag(block, "version")
        if declared is None:
            raise WorkspaceError(f"'{package}' has no <version>; it is managed by a parent POM or BOM.")
        if ref := _PROPERTY_REF.match(declared):
            prop = ref.group(1)
            pattern = re.compile(rf"(<{re.escape(prop)}>)\s*[^<]+?\s*(</{re.escape(prop)}>)")
            new_text, count = pattern.subn(rf"\g<1>{version}\g<2>", text, count=1)
            if count == 0:
                raise WorkspaceError(f"Property '{prop}' is not defined in {manifest}.")
            old_spec, new_spec = f"<{prop}>{_tag(text, prop)}</{prop}>", f"<{prop}>{version}</{prop}>"
        else:
            new_block = re.sub(r"(<version>)\s*[^<]+?\s*(</version>)", rf"\g<1>{version}\g<2>", block, count=1)
            new_text = text[: match.start()] + new_block + text[match.end():]
            old_spec, new_spec = f"<version>{declared}</version>", f"<version>{version}</version>"
        ws.write_file(manifest, new_text)
        return DependencyUpdate(manifest, f"{package} {old_spec}", f"{package} {new_spec}")

    def list_dependencies(self, ws: Workspace, app_dir: str) -> dict[str, str]:
        text = (ws.root / self.manifest_path(ws, app_dir)).read_text()
        deps = {}
        for match in _DEPENDENCY.finditer(text):
            block = match.group(0)
            group, artifact, version = _tag(block, "groupId"), _tag(block, "artifactId"), _tag(block, "version")
            if version and (ref := _PROPERTY_REF.match(version)):
                version = _tag(text, ref.group(1))
            if group and artifact and version and "${" not in version:
                deps[f"{group}:{artifact}"] = version
        return deps

    def registry_versions(self, package: str) -> list[str]:
        group, artifact = self._split(package)
        # Coordinates come from the untrusted POM: validate them before building the URL.
        if not _COORDINATE.match(group) or not _COORDINATE.match(artifact):
            raise WorkspaceError(f"'{package}' is not a valid Maven coordinate.")
        url = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
        root = ET.fromstring(http.request("GET", url, raw=True, headers={"Accept": "application/xml"}))
        return [node.text for node in root.iter("version") if node.text]
