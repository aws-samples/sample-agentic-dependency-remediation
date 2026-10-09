# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Regression tests for the code review findings (injection, SSRF, archives, patches, lockfiles)."""

import io
import os
import subprocess
import tarfile
import zipfile

import pytest

import handler
from remediation_agent import http
from remediation_agent.build_runner import BUILD_SCRIPT, _store_lockfile
from remediation_agent.ecosystems import get_adapter
from remediation_agent.tools import RemediationTask
from remediation_agent.workspace import MAX_ORIGINAL_BYTES, Workspace, WorkspaceError


# ----- CWE-78: shell injection through APP_DIR -------------------------------------------------

@pytest.mark.parametrize("value", [".; rm -rf / #", "$(id)", "`id`", "a b", "x|y", "svc\ntouch pwned"])
def test_app_dir_rejects_shell_metacharacters(value):
    with pytest.raises(ValueError):
        RemediationTask.from_payload({"app_dir": value}, "r")


def test_build_script_treats_app_dir_as_data(tmp_path):
    """Even without validation, a quoted variable is never executed by bash."""
    marker = tmp_path / "pwned"
    script = tmp_path / "build.sh"
    script.write_text(BUILD_SCRIPT)
    env = {**os.environ, "ECOSYSTEM": "none", "APP_DIR": f"; touch {marker} #"}
    result = subprocess.run(["bash", str(script)], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode != 0  # cd into a non-existent folder fails
    assert not marker.exists()


# ----- CWE-918: SSRF ------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://pypi.org/pypi/x/json",
        "https://169.254.169.254/latest/meta-data/",
        "https://evil.example.com/x",
        "https://pypi.org.evil.example.com/x",
        "https://user@pypi.org/x",
        "https://pypi.org:8443/x",
    ],
)
def test_outbound_urls_are_allowlisted(url):
    with pytest.raises(ValueError):
        http.request("GET", url)


def test_redirect_to_disallowed_host_is_refused():
    handler_ = http._AllowlistRedirectHandler()
    req = http.urllib.request.Request("https://pypi.org/pypi/x/json")
    with pytest.raises(ValueError):
        handler_.redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/latest/")


def test_maven_coordinates_are_validated():
    with pytest.raises(WorkspaceError):
        get_adapter("java").registry_versions("../../evil:x")


# ----- CWE-22: archive links and traversal --------------------------------------------------------

def _tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data else None)
    return buffer.getvalue()


def test_tar_symlinks_and_hardlinks_are_skipped(tmp_path):
    regular = tarfile.TarInfo("app.py")
    regular.size = 2
    sym = tarfile.TarInfo("link")
    sym.type, sym.linkname = tarfile.SYMTYPE, "/etc/passwd"
    hard = tarfile.TarInfo("hard")
    hard.type, hard.linkname = tarfile.LNKTYPE, "/etc/passwd"
    ws = Workspace(tmp_path / "repo")
    ws.extract_archive(_tar([(regular, b"x\n"), (sym, None), (hard, None)]))
    assert ws.list_files() == ["app.py"]
    assert not (ws.root / "link").exists() and not (ws.root / "hard").exists()


def test_zip_symlink_entry_is_skipped(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("ok.txt", "x")
        link = zipfile.ZipInfo("link")
        link.external_attr = 0o120777 << 16
        z.writestr(link, "/etc/passwd")
    ws = Workspace(tmp_path / "repo")
    ws.extract_archive(buffer.getvalue())
    assert ws.list_files() == ["ok.txt"]


def test_extraction_size_limit_is_enforced_while_streaming(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.txt", "0" * 2_000_000)  # compresses to a few KB
    ws = Workspace(tmp_path / "repo")
    with pytest.raises(WorkspaceError, match="size limit"):
        ws.extract_archive(buffer.getvalue(), max_total_bytes=1_000_000)


def test_extract_from_file_path(tmp_path):
    archive = tmp_path / "source"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("requirements.txt", "a==1\n")
    archive.write_bytes(buffer.getvalue())
    ws = Workspace(tmp_path / "repo")
    ws.extract_archive(archive)
    assert ws.list_files() == ["requirements.txt"]


# ----- Patch generation for files without a stored original ---------------------------------------

def test_patch_fails_loudly_without_original(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "big.lock").write_text("old\n")
    ws = Workspace(root)
    ws.snapshot()
    ws._originals.pop("big.lock")  # simulate a file larger than MAX_ORIGINAL_BYTES
    (root / "big.lock").write_text("new\n")
    with pytest.raises(WorkspaceError, match=str(MAX_ORIGINAL_BYTES)):
        ws.unified_patch()


# ----- Non-UTF-8 lockfiles ---------------------------------------------------------------------------

def test_non_utf8_lockfile_is_skipped_not_corrupted(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package-lock.json").write_text("{}\n")
    ws = Workspace(root)
    ws.snapshot()
    assert _store_lockfile(ws, "package-lock.json", b"\xff\xfe\x00bad") is False
    assert (root / "package-lock.json").read_text() == "{}\n"
    assert _store_lockfile(ws, "package-lock.json", b'{"lockfileVersion": 3}\n') is True


# ----- Session ID length -------------------------------------------------------------------------------

@pytest.mark.parametrize("run_id,project", [("abcdefgh", "p"), ("3f2c1c8e-1111-4a4a-9999-123456789abc", "x" * 100)])
def test_session_id_length_is_always_valid(run_id, project, monkeypatch):
    captured = {}

    class FakeAgentCore:
        def invoke_agent_runtime(self, **kwargs):
            captured.update(kwargs)
            return {"response": io.BytesIO(b"{}")}

    class FakeS3:
        def head_object(self, **kwargs):
            return {"Metadata": {}}

    class FakeTable:
        def put_item(self, **kwargs):
            return {}

    class FakeDynamo:
        def Table(self, name):
            return FakeTable()

    monkeypatch.setenv("ARTIFACT_BUCKET", "b")
    monkeypatch.setenv("RUNS_TABLE", "t")
    monkeypatch.setenv("AGENT_RUNTIME_ARN", "arn")
    monkeypatch.setattr(handler, "_clients", {"bedrock-agentcore": FakeAgentCore(), "s3": FakeS3(), "dynamodb": FakeDynamo()})
    event = {"detail": {"bucket": {"name": "b"}, "object": {"key": f"requests/{project}/{run_id}/source.zip", "size": 10}}}
    assert handler.handler(event, None)["started"] is True
    assert 33 <= len(captured["runtimeSessionId"]) <= 100


# ----- XML attacks in registry metadata (bandit B314) ---------------------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        # Entity expansion ("billion laughs")
        b'<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><metadata><versioning>'
        b"<versions><version>&b;</version></versions></versioning></metadata>",
        # External entity (XXE)
        b'<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]><metadata><versioning>'
        b"<versions><version>&x;</version></versions></versioning></metadata>",
    ],
)
def test_maven_metadata_rejects_xml_attacks(payload, monkeypatch):
    from defusedxml import DefusedXmlException

    monkeypatch.setattr(http, "request", lambda *a, **k: payload)
    with pytest.raises(DefusedXmlException):
        get_adapter("java").registry_versions("org.example:lib")


def test_maven_metadata_parses_normal_xml(monkeypatch):
    xml = b"<metadata><versioning><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>"
    monkeypatch.setattr(http, "request", lambda *a, **k: xml)
    assert get_adapter("java").registry_versions("org.example:lib") == ["1.0", "2.0"]
