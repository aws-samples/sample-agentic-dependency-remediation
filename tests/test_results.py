# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Archive handling, repository config, reports, and the client packaging."""

import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from remediation_agent.report import build_report, build_result
from remediation_agent.results import LocalResultSink
from remediation_agent.runner import apply_repo_config
from remediation_agent.tools import PackageFix, RemediationTask, RunState
from remediation_agent.workspace import Workspace, WorkspaceError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "client"))
import remediate  # noqa: E402


def zip_bytes(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buffer.getvalue()


def test_extract_zip_without_wrapper(tmp_path):
    ws = Workspace(tmp_path / "repo")
    ws.extract_archive(zip_bytes({"requirements.txt": "a==1\n", "app/main.py": "x\n", "node_modules/x.js": "junk"}))
    assert sorted(ws.list_files()) == ["app/main.py", "requirements.txt"]


def test_extract_strips_single_wrapper_folder(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in ("proj-abc123/pom.xml", "proj-abc123/src/A.java"):
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    ws = Workspace(tmp_path / "repo")
    ws.extract_archive(buffer.getvalue())
    assert ws.list_files() == ["pom.xml", "src/A.java"]


def test_extract_blocks_traversal(tmp_path):
    ws = Workspace(tmp_path / "repo")
    with pytest.raises(WorkspaceError):
        ws.extract_archive(zip_bytes({"ok.txt": "x", "../../evil.txt": "x"}))
    assert not (tmp_path / "evil.txt").exists()


def test_repo_config_merge(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "remediation.json").write_text(json.dumps({"app_dir": "svc", "ignore": ["lodash"], "evil": "x"}))
    ws = Workspace(root)
    merged = apply_repo_config({"project": "p", "app_dir": "", "packages": ["jinja2"]}, ws)
    assert merged == {"app_dir": "svc", "ignore": ["lodash"], "project": "p", "packages": ["jinja2"]}


def test_report_and_local_sink(tmp_path):
    state = RunState(status="PARTIAL_FIX", attempts=2)
    state.packages = {
        "jinja2": PackageFix("jinja2", "2.11.3", "3.1.6", ["GHSA-x"], "UPDATED"),
        "lxml": PackageFix("lxml", "4.0", None, ["GHSA-y"], "SKIPPED", "needs a design decision"),
    }
    task = RemediationTask(run_id="r1", project="demo")
    result = build_result(task, "python", state, {"changed_files": ["requirements.txt"]})
    assert [f["package"] for f in result["fixed"]] == ["jinja2"]
    assert result["skipped"][0]["note"] == "needs a design decision"
    report = build_report(result, "- switched imports", "diff --git ...", None)
    assert "| `jinja2` | 2.11.3 | 3.1.6 |" in report and "git apply --index fix.patch" in report
    LocalResultSink(tmp_path / "out").write(result, "diff --git ...", report)
    assert json.loads((tmp_path / "out/result.json").read_text())["status"] == "PARTIAL_FIX"
    assert (tmp_path / "out/fix.patch").exists()


def test_client_archive_skips_build_folders(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("x")
    (tmp_path / "node_modules/pkg").mkdir(parents=True)
    (tmp_path / "node_modules/pkg/index.js").write_text("x")
    names = zipfile.ZipFile(io.BytesIO(remediate.build_archive(tmp_path))).namelist()
    assert names == ["src/app.py"]


def test_client_keeps_waiting_when_s3_returns_403(monkeypatch):
    """With the client policy, S3 answers a missing result.json with 403, not 404."""
    from botocore.exceptions import ClientError

    calls = {"n": 0}

    class FakeS3:
        def get_object(self, Bucket, Key):
            calls["n"] += 1
            if calls["n"] < 3:
                code = "AccessDenied" if calls["n"] == 1 else "NoSuchKey"
                raise ClientError({"Error": {"Code": code, "Message": "x"}}, "GetObject")
            return {"Body": io.BytesIO(b'{"status": "FIXED"}')}

    monkeypatch.setattr(remediate.time, "sleep", lambda s: None)
    assert remediate.wait_for_result(FakeS3(), "b", "results/p/r/", timeout=60) == {"status": "FIXED"}
    assert calls["n"] == 3


def test_client_raises_other_s3_errors(monkeypatch):
    from botocore.exceptions import ClientError

    class FakeS3:
        def get_object(self, Bucket, Key):
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "x"}}, "GetObject")

    with pytest.raises(ClientError):
        remediate.wait_for_result(FakeS3(), "b", "results/p/r/", timeout=60)


@pytest.mark.parametrize(
    "code,expected",
    [
        ("InvalidClientTokenId", "credentials are missing, expired, or invalid"),
        ("ExpiredToken", "credentials are missing, expired, or invalid"),
        ("AccessDenied", "ClientPolicy"),
        ("ValidationError", "Set AWS_REGION"),
    ],
)
def test_client_explains_stack_lookup_errors(code, expected, monkeypatch):
    from botocore.exceptions import ClientError

    class FakeCfn:
        meta = type("M", (), {"region_name": "us-east-1"})()

        def describe_stacks(self, StackName):
            raise ClientError({"Error": {"Code": code, "Message": "x"}}, "DescribeStacks")

    monkeypatch.setattr(remediate.boto3, "client", lambda *a, **k: FakeCfn())
    with pytest.raises(SystemExit, match=expected):
        remediate.stack_bucket("DependencyRemediationAgent", "us-east-1")


def test_client_explains_missing_region(monkeypatch):
    from botocore.exceptions import NoRegionError

    def no_region(*args, **kwargs):
        raise NoRegionError()

    monkeypatch.setattr(remediate.boto3, "client", no_region)
    with pytest.raises(SystemExit, match="No AWS Region set"):
        remediate.stack_bucket("DependencyRemediationAgent", None)


def test_advisory_summary_count_matches_list():
    from remediation_agent.report import advisory_summary

    eight = [f"GHSA-{i}" for i in range(8)]
    assert advisory_summary(eight) == "8 advisories: GHSA-0, GHSA-1, GHSA-2, GHSA-3, GHSA-4, GHSA-5 (+2 more)"
    assert advisory_summary(["GHSA-x"]) == "1 advisory: GHSA-x"
    assert advisory_summary([]) == "none"


def test_notification_text_is_plain_and_readable():
    from remediation_agent.results import notification_text

    result = {
        "run_id": "r1", "project": "node-marked", "status": "FIXED", "build_attempts": 2,
        "fixed": [{"package": "marked", "from": "1.2.9", "to": "4.0.10", "advisories": ["GHSA-a", "GHSA-b"]}],
        "skipped": [],
        "artifacts": {"report": "s3://b/results/node-marked/r1/report.md", "patch": "s3://b/results/node-marked/r1/fix.patch"},
    }
    subject, body = notification_text(result)
    assert subject == "Dependency remediation: node-marked - FIXED"
    assert "  - marked 1.2.9 -> 4.0.10 (2 advisories: GHSA-a, GHSA-b)" in body
    assert "Not fixed:\n  (none)" in body
    assert "aws s3 cp s3://b/results/node-marked/r1/fix.patch ." in body
    assert '"' not in body  # no JSON quoting
