# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Run the repository build and unit tests, either in AWS CodeBuild or locally.

The agent never runs repository code inside its own runtime. Package install
scripts and tests can execute arbitrary code, so in AWS they run in an
isolated CodeBuild project whose role can only read the source archive and
write lockfiles back to the run's S3 prefix.

The local backend exists for development and for the evaluation harness.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # nosec B404 - used only by the local build backend with a fixed argument list
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .workspace import Workspace

log = logging.getLogger(__name__)

BUILD_SCRIPT_PATH = ".remediation/build.sh"

# The same script runs locally and in CodeBuild. It is written by the agent
# code (never by the model) and is excluded from the published patch.
BUILD_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail
cd "${APP_DIR:-.}"
echo "== remediation build: ecosystem=${ECOSYSTEM} dir=$(pwd)"
case "${ECOSYSTEM}" in
  python)
    VENV="${TMPDIR:-/tmp}/remediation-venv-$$"
    python3 -m venv "$VENV"
    . "$VENV/bin/activate"
    python -m pip install --disable-pip-version-check -q --upgrade pip
    python -m pip install --disable-pip-version-check -q -r requirements.txt
    if [ -f requirements-dev.txt ]; then python -m pip install --disable-pip-version-check -q -r requirements-dev.txt; fi
    python -m pip install --disable-pip-version-check -q pytest
    python -m pytest -q
    ;;
  node)
    npm install --package-lock-only --no-audit --no-fund
    npm ci --no-audit --no-fund
    npm test
    ;;
  java)
    mvn -B -ntp test
    ;;
  *)
    echo "Unsupported ecosystem: ${ECOSYSTEM}" >&2
    exit 2
    ;;
esac
echo "== remediation build: SUCCEEDED"
"""

_ERROR_MARKERS = ("error", "fail", "traceback", "exception", "[error]", "cannot find symbol", "e   ", "assert")
MAX_LOG_CHARS = 12_000


def summarize_log(text: str, tail_lines: int = 80, max_error_lines: int = 60) -> str:
    """Keep error-looking lines plus the tail of the log, within a size budget."""
    lines = text.splitlines()
    errors = [line for line in lines if any(marker in line.lower() for marker in _ERROR_MARKERS)]
    parts = []
    if errors:
        parts.append("--- lines that look like errors ---")
        parts.extend(errors[:max_error_lines])
    parts.append(f"--- last {tail_lines} lines ---")
    parts.extend(lines[-tail_lines:])
    summary = "\n".join(parts)
    return summary if len(summary) <= MAX_LOG_CHARS else summary[-MAX_LOG_CHARS:]


@dataclass
class BuildResult:
    passed: bool
    status: str
    log_summary: str
    build_id: str | None
    duration_seconds: int
    lockfiles_updated: list[str]


class LocalBuildRunner:
    """Runs the build script in a temporary copy of the workspace."""

    def __init__(self, timeout_seconds: int = 1200):
        self.timeout_seconds = timeout_seconds

    def run(self, ws: Workspace, ecosystem: str, app_dir: str, lockfiles: tuple[str, ...], run_id: str, attempt: int) -> BuildResult:
        started = time.time()
        with tempfile.TemporaryDirectory(prefix="remediation-build-") as tmp:
            copy = Path(tmp) / "src"
            shutil.copytree(ws.root, copy, ignore=shutil.ignore_patterns("node_modules", "target", ".venv", ".git"))
            script = copy / BUILD_SCRIPT_PATH
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(BUILD_SCRIPT)
            env = {**os.environ, "ECOSYSTEM": ecosystem, "APP_DIR": app_dir or "."}
            try:
                # Reviewed (bandit B603, B607): fixed argv (no shell); the script is BUILD_SCRIPT written by agent code,
                # never by the model. This backend is for local development and evaluation only;
                # the deployed stack builds in CodeBuild.
                proc = subprocess.run(  # nosec B603 B607
                    ["bash", str(script)], cwd=copy, env=env, capture_output=True, text=True, timeout=self.timeout_seconds
                )
                output, passed, status = proc.stdout + proc.stderr, proc.returncode == 0, "SUCCEEDED" if proc.returncode == 0 else "FAILED"
            except subprocess.TimeoutExpired as exc:
                output, passed, status = f"{exc.stdout or ''}{exc.stderr or ''}\nBuild timed out.", False, "TIMED_OUT"
            updated = _copy_back_lockfiles(copy, ws, app_dir, lockfiles)
        return BuildResult(passed, status, summarize_log(output), None, int(time.time() - started), updated)


class CodeBuildRunner:
    """Packages the workspace to S3 and runs it in the stack's CodeBuild project."""

    def __init__(self, bucket: str, project: str, region: str, timeout_seconds: int = 1200, session=None):
        import boto3

        session = session or boto3.session.Session(region_name=region)
        self.s3 = session.client("s3")
        self.codebuild = session.client("codebuild")
        self.logs = session.client("logs")
        self.bucket = bucket
        self.project = project
        self.timeout_seconds = timeout_seconds

    def run(self, ws: Workspace, ecosystem: str, app_dir: str, lockfiles: tuple[str, ...], run_id: str, attempt: int) -> BuildResult:
        started = time.time()
        prefix = f"runs/{run_id}/attempt-{attempt}-{uuid.uuid4().hex[:6]}"
        source_key = f"{prefix}/source.zip"
        self.s3.put_object(
            Bucket=self.bucket,
            Key=source_key,
            Body=ws.zip_bytes({BUILD_SCRIPT_PATH: BUILD_SCRIPT}),
            ServerSideEncryption="aws:kms",
        )
        build = self.codebuild.start_build(
            projectName=self.project,
            sourceTypeOverride="S3",
            sourceLocationOverride=f"{self.bucket}/{source_key}",
            environmentVariablesOverride=[
                {"name": "ECOSYSTEM", "value": ecosystem, "type": "PLAINTEXT"},
                {"name": "APP_DIR", "value": app_dir or ".", "type": "PLAINTEXT"},
                {"name": "OUTPUT_PREFIX", "value": f"s3://{self.bucket}/{prefix}/output", "type": "PLAINTEXT"},
                {"name": "LOCKFILES", "value": " ".join(lockfiles), "type": "PLAINTEXT"},
            ],
        )["build"]
        build_id = build["id"]
        while True:
            build = self.codebuild.batch_get_builds(ids=[build_id])["builds"][0]
            if build["buildComplete"]:
                break
            if time.time() - started > self.timeout_seconds:
                self.codebuild.stop_build(id=build_id)
                return BuildResult(False, "TIMED_OUT", "Build exceeded the agent's timeout and was stopped.", build_id, int(time.time() - started), [])
            time.sleep(15)
        status = build["buildStatus"]
        log_text = self._read_log(build.get("logs", {}))
        updated = self._download_lockfiles(ws, app_dir, lockfiles, prefix)
        return BuildResult(status == "SUCCEEDED", status, summarize_log(log_text), build_id, int(time.time() - started), updated)

    def _read_log(self, logs: dict) -> str:
        group, stream = logs.get("groupName"), logs.get("streamName")
        if not group or not stream:
            return "(no build log available)"
        for _ in range(6):  # log delivery can lag a few seconds behind build completion
            events = self.logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=False, limit=2000)["events"]
            if events:
                return "".join(e["message"] for e in events)
            time.sleep(5)
        return "(build log is empty)"

    def _download_lockfiles(self, ws: Workspace, app_dir: str, lockfiles: tuple[str, ...], prefix: str) -> list[str]:
        updated = []
        for name in lockfiles:
            key = f"{prefix}/output/{name}"
            try:
                body = self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
            except self.s3.exceptions.NoSuchKey:
                continue
            rel = f"{app_dir.strip('/')}/{name}" if app_dir.strip("/.") else name
            if _store_lockfile(ws, rel, body):
                updated.append(rel)
        return updated


def _copy_back_lockfiles(build_dir: Path, ws: Workspace, app_dir: str, lockfiles: tuple[str, ...]) -> list[str]:
    updated = []
    base = app_dir.strip("/") if app_dir.strip("/.") else ""
    for name in lockfiles:
        rel = f"{base}/{name}" if base else name
        produced = build_dir / rel
        if produced.is_file() and not produced.is_symlink() and _store_lockfile(ws, rel, produced.read_bytes()):
            updated.append(rel)
    return updated


def _store_lockfile(ws: Workspace, rel: str, data: bytes) -> bool:
    """Write a regenerated lockfile into the workspace. Returns True if it changed.

    Lockfiles (for example package-lock.json) are UTF-8 JSON. Anything else is skipped with a
    warning rather than decoded lossily, because a corrupted lockfile would break the patch.
    """
    current = ws.root / rel
    if current.exists() and current.read_bytes() == data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Ignoring regenerated %s: it is not valid UTF-8", rel)
        return False
    ws.write_file(rel, text, trusted=True)
    return True


def make_runner(settings):
    if settings.build_backend == "local":
        return LocalBuildRunner(settings.build_timeout_seconds)
    if not settings.artifact_bucket or not settings.codebuild_project:
        raise RuntimeError("ARTIFACT_BUCKET and CODEBUILD_PROJECT must be set for the codebuild backend.")
    return CodeBuildRunner(settings.artifact_bucket, settings.codebuild_project, settings.region, settings.build_timeout_seconds)
