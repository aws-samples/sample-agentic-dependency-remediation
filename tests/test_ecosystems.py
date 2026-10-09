# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json

import pytest

from remediation_agent.ecosystems import get_adapter, parse_version, sort_stable
from remediation_agent.workspace import Workspace, WorkspaceError


def make_ws(tmp_path, files: dict[str, str]) -> Workspace:
    root = tmp_path / "repo"
    for rel, content in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(content)
    ws = Workspace(root)
    ws.snapshot()
    return ws


def test_version_parsing():
    assert parse_version("2.0") == parse_version("2.0.0") == (2,)
    assert parse_version("3.1.6") > parse_version("3.1.5")
    assert parse_version("4.0.0-beta.1") is None
    assert parse_version("2.1-SNAPSHOT") is None
    assert sort_stable(["1.10", "1.9", "2.0rc1", "1.2"]) == ["1.2", "1.9", "1.10"]


def test_python_requirements_update(tmp_path):
    ws = make_ws(tmp_path, {"requirements.txt": "flask==2.0.0\nJinja2[i18n]==2.11.3 ; python_version >= '3.8'  # templating\n"})
    adapter = get_adapter("python")
    assert adapter.current_version(ws, "", "jinja2") == "2.11.3"
    adapter.update_dependency(ws, "", "jinja2", "3.1.6")
    lines = (ws.root / "requirements.txt").read_text().splitlines()
    assert lines[0] == "flask==2.0.0"
    assert lines[1] == "Jinja2[i18n]==3.1.6 ; python_version >= '3.8'  # templating"


def test_python_missing_package(tmp_path):
    ws = make_ws(tmp_path, {"requirements.txt": "flask==2.0.0\n"})
    with pytest.raises(WorkspaceError, match="transitive"):
        get_adapter("python").update_dependency(ws, "", "jinja2", "3.1.6")


def test_node_update_preserves_range_prefix(tmp_path):
    pkg = {"name": "x", "dependencies": {"marked": "^1.2.9"}, "devDependencies": {"jest": "29.0.0"}}
    ws = make_ws(tmp_path, {"web/package.json": json.dumps(pkg, indent=2)})
    adapter = get_adapter("node")
    assert adapter.current_version(ws, "web", "marked") == "1.2.9"
    change = adapter.update_dependency(ws, "web", "marked", "4.0.10")
    assert change.manifest == "web/package.json"
    assert json.loads((ws.root / "web/package.json").read_text())["dependencies"]["marked"] == "^4.0.10"


POM = """<project>
  <properties><snakeyaml.version>1.33</snakeyaml.version></properties>
  <dependencies>
    <!-- keep this comment -->
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${snakeyaml.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.10</version></dependency>
  </dependencies>
</project>
"""


def test_maven_property_version(tmp_path):
    ws = make_ws(tmp_path, {"pom.xml": POM})
    adapter = get_adapter("java")
    assert adapter.current_version(ws, "", "org.yaml:snakeyaml") == "1.33"
    adapter.update_dependency(ws, "", "org.yaml:snakeyaml", "2.0")
    text = (ws.root / "pom.xml").read_text()
    assert "<snakeyaml.version>2.0</snakeyaml.version>" in text
    assert "<!-- keep this comment -->" in text
    assert "<version>2.9.10</version>" in text


def test_maven_literal_version(tmp_path):
    ws = make_ws(tmp_path, {"pom.xml": POM})
    get_adapter("java").update_dependency(ws, "", "com.fasterxml.jackson.core:jackson-databind", "2.17.2")
    text = (ws.root / "pom.xml").read_text()
    assert "<version>2.17.2</version>" in text
    assert "<snakeyaml.version>1.33</snakeyaml.version>" in text


def test_unknown_ecosystem():
    with pytest.raises(ValueError):
        get_adapter("cobol")
