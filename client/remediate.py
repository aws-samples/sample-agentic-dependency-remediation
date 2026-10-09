#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""remediate: send a repository to the dependency remediation agent and download the verified fix.

Works with any Git host or CI system. It packages the working tree, uploads it
to the stack's bucket (the upload starts the run), waits for the result, and
writes these files to the output folder:

  result.json   machine-readable outcome
  report.md     human-readable report (use it as the merge request description)
  fix.patch     the verified change, only when a fix was found: git apply --index fix.patch

Exit codes: 0 = fixed, partially fixed, or nothing to fix; 2 = not fixed; 1 = error.

Examples:
  remediate                                   # current folder, auto-detect everything
  remediate --path services/api --project orders-api
  remediate --package jinja2 --package requests --out /tmp/remediation
  remediate --bucket my-remediation-bucket    # skip the CloudFormation lookup

Inside a Git work tree, only tracked and untracked-but-not-ignored files are sent
(files matched by .gitignore are left out). Outside Git, the folder is walked and
dependency and build folders (node_modules, target, .venv, ...) are skipped.

AWS credentials come from the standard chain (environment, profile, CI role).
The caller needs the stack's ClientPolicy.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess  # nosec B404 - used only to list files with git, with a fixed argument list
import sys
import time
import uuid
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError

CREDENTIAL_ERRORS = {"InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException", "SignatureDoesNotMatch"}

DEFAULT_STACK = "DependencyRemediationAgent"
SKIP_DIRS = {".git", "node_modules", "target", ".venv", "venv", "__pycache__", "dist", "build", ".gradle", ".idea"}
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
SUCCESS = {"FIXED", "PARTIAL_FIX", "NO_VULNERABILITIES"}
_PROJECT = re.compile(r"[^A-Za-z0-9._-]+")


def list_files(root: Path) -> list[Path]:
    """Tracked and untracked-but-not-ignored files when in a Git work tree, otherwise a filtered walk."""
    try:
        # Fixed argv (no shell); the only variable is the folder the user asked to upload.
        out = subprocess.run(  # nosec B603 B607
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True, capture_output=True,
        ).stdout
        files = [root / p for p in out.decode().split("\0") if p]
        return [f for f in files if f.is_file() and not f.is_symlink()]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            files.extend(Path(dirpath) / n for n in filenames if not (Path(dirpath) / n).is_symlink())
        return files


def build_archive(root: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in list_files(root):
            rel = path.relative_to(root).as_posix()
            if not any(part in SKIP_DIRS for part in rel.split("/")):
                archive.write(path, rel)
    data = buffer.getvalue()
    if len(data) > MAX_ARCHIVE_BYTES:
        raise SystemExit(f"Archive is {len(data) // 1_000_000} MB; the limit is {MAX_ARCHIVE_BYTES // 1_000_000} MB. Use --path to send only the service folder.")
    return data


def stack_bucket(stack: str, region: str | None) -> str:
    try:
        client = boto3.client("cloudformation", region_name=region)
    except NoRegionError as exc:
        raise SystemExit(
            "No AWS Region set. Use the Region where the stack is deployed, for example:\n"
            "  export AWS_REGION=us-east-1   (or: remediate --region us-east-1)"
        ) from exc
    try:
        outputs = client.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in CREDENTIAL_ERRORS:
            hint = "Your AWS credentials are missing, expired, or invalid. Refresh them, then check with: aws sts get-caller-identity"
        elif code in ("AccessDenied", "AccessDeniedException"):
            hint = "Your identity is not allowed to read the stack. Attach the stack's ClientPolicy to it."
        else:
            hint = "Set AWS_REGION (or --region) to the Region where the stack is deployed, and --stack-name if you renamed it."
        raise SystemExit(f"Cannot read stack '{stack}' in {client.meta.region_name}: {exc.response['Error']['Message']}\n{hint}") from exc
    except NoCredentialsError as exc:
        raise SystemExit("No AWS credentials found. Configure them, then check with: aws sts get-caller-identity") from exc
    return next(o["OutputValue"] for o in outputs if o["OutputKey"] == "BucketName")


def wait_for_result(s3, bucket: str, prefix: str, timeout: int) -> dict:
    deadline = time.time() + timeout
    delay = 10
    while time.time() < deadline:
        try:
            return json.loads(s3.get_object(Bucket=bucket, Key=prefix + "result.json")["Body"].read())
        except ClientError as exc:
            # The client policy only allows listing under results/, so S3 answers a missing
            # result.json with 403 instead of 404. Both mean "not written yet".
            if exc.response["Error"]["Code"] not in ("NoSuchKey", "404", "AccessDenied", "403"):
                raise
        print(f"  {time.strftime('%H:%M:%S')} waiting for the agent...", flush=True)
        time.sleep(delay)
        delay = min(delay + 5, 30)
    raise SystemExit(f"Timed out after {timeout}s. Results will appear at s3://{bucket}/{prefix}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="remediate", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--path", default=".", help="Repository or service folder to send (default: current folder)")
    parser.add_argument("--project", help="Project name used in S3 keys (default: folder name)")
    parser.add_argument("--ecosystem", choices=["python", "node", "java"], help="Default: detect from the manifest")
    parser.add_argument("--app-dir", default="", help="Folder inside --path that holds the manifest")
    parser.add_argument("--package", action="append", default=[], help="Only fix this package (repeatable). Default: all vulnerable")
    parser.add_argument("--ignore", action="append", default=[], help="Never change this package (repeatable)")
    parser.add_argument("--bucket", default=os.environ.get("REMEDIATION_BUCKET"), help="Stack bucket (default: read from the stack)")
    parser.add_argument("--stack-name", default=os.environ.get("REMEDIATION_STACK", DEFAULT_STACK))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION"))
    parser.add_argument("--out", default="remediation-output", help="Folder for result.json, report.md, and fix.patch")
    parser.add_argument("--timeout", type=int, default=3600, help="Seconds to wait for the result")
    parser.add_argument("--no-wait", action="store_true", help="Upload and exit; results arrive in S3 and as an event")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        parser.error(f"{root} is not a folder")
    project = _PROJECT.sub("-", args.project or root.name).strip("-.")[:100] or "default"
    run_id = str(uuid.uuid4())
    bucket = args.bucket or stack_bucket(args.stack_name, args.region)
    s3 = boto3.client("s3", region_name=args.region)

    metadata = {"ecosystem": args.ecosystem or "", "app-dir": args.app_dir.strip("/"),
                "packages": ",".join(args.package), "ignore": ",".join(args.ignore)}
    key = f"requests/{project}/{run_id}/source.zip"
    archive = build_archive(root)
    s3.put_object(Bucket=bucket, Key=key, Body=archive, ServerSideEncryption="aws:kms",
                  Metadata={k: v for k, v in metadata.items() if v})
    prefix = f"results/{project}/{run_id}/"
    print(f"Uploaded {len(archive) // 1024} KB as run {run_id} (project {project}).")
    if args.no_wait:
        print(f"Results: s3://{bucket}/{prefix}")
        return 0

    result = wait_for_result(s3, bucket, prefix, args.timeout)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps(result, indent=2))
    for name in ("report.md", "fix.patch"):
        try:
            s3.download_file(bucket, prefix + name, str(out / name))
        except ClientError:
            pass

    print(f"\nStatus: {result['status']}  ({result.get('build_attempts', 0)} build attempt(s))")
    for fix in result.get("fixed", []):
        print(f"  fixed    {fix['package']} {fix['from']} -> {fix['to']}")
    for skip in result.get("skipped", []):
        print(f"  not fixed {skip['package']} {skip['from']}: {skip.get('note') or skip['status']}")
    if result.get("reason"):
        print(f"  reason: {result['reason']}")
    if (out / "fix.patch").exists():
        print(f"\nApply with: git apply --index {out / 'fix.patch'}")
    return 0 if result["status"] in SUCCESS else (1 if result["status"] == "ERROR" else 2)


if __name__ == "__main__":
    sys.exit(main())
