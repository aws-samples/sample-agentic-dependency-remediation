# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Trigger function: starts a remediation run when a source archive is uploaded.

EventBridge delivers the S3 "Object Created" event for keys under requests/.
The key layout is requests/<project>/<run-id>/source.zip (or .tar.gz). Optional
run options come from S3 object metadata (set by the remediate CLI):

  x-amz-meta-ecosystem   python | node | java     (default: detect)
  x-amz-meta-app-dir     folder that holds the manifest
  x-amz-meta-packages    comma-separated packages to fix (default: all vulnerable)
  x-amz-meta-ignore      comma-separated packages to leave alone

The run ID is claimed with a conditional write, so a redelivered event never
starts a second run.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

REQUEST_KEY = re.compile(r"^requests/(?P<project>[A-Za-z0-9][A-Za-z0-9._-]{0,99})/(?P<run_id>[A-Za-z0-9-]{8,64})/source\.(zip|tar\.gz|tgz)$")
METADATA_OPTIONS = {"ecosystem": "ecosystem", "app-dir": "app_dir", "packages": "packages", "ignore": "ignore"}
RUN_TTL_SECONDS = 90 * 24 * 3600

_clients: dict = {}


def client(name: str):
    if name not in _clients:
        _clients[name] = boto3.resource("dynamodb") if name == "dynamodb" else boto3.client(name)
    return _clients[name]


def parse_event(event: dict) -> tuple[str, str, int] | None:
    detail = event.get("detail", {})
    bucket = detail.get("bucket", {}).get("name")
    key = detail.get("object", {}).get("key", "")
    size = int(detail.get("object", {}).get("size", 0))
    if bucket != os.environ["ARTIFACT_BUCKET"] or not REQUEST_KEY.match(key):
        return None
    return bucket, key, size


def options_from_metadata(metadata: dict) -> dict:
    options = {}
    for meta_key, option in METADATA_OPTIONS.items():
        value = metadata.get(meta_key, "").strip()
        if value:
            options[option] = [v.strip() for v in value.split(",") if v.strip()] if option in ("packages", "ignore") else value
    return options


def claim_run(table, run_id: str, project: str, key: str) -> bool:
    try:
        table.put_item(
            Item={"pk": f"run#{run_id}", "status": "QUEUED", "project": project, "source_key": key,
                  "created_at": int(time.time()), "expires_at": int(time.time()) + RUN_TTL_SECONDS},
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def handler(event, _context):
    parsed = parse_event(event)
    if not parsed:
        log.info("Ignoring object that does not match the request layout")
        return {"started": False}
    bucket, key, size = parsed
    match = REQUEST_KEY.match(key)
    project, run_id = match.group("project"), match.group("run_id")

    max_bytes = int(os.environ.get("MAX_ARCHIVE_MB", "200")) * 1024 * 1024
    if size > max_bytes:
        log.warning("Rejecting %s: %d bytes exceeds the limit", key, size)
        return {"started": False, "reason": "archive too large"}

    runs = client("dynamodb").Table(os.environ["RUNS_TABLE"])
    if not claim_run(runs, run_id, project, key):
        log.info("Run %s already claimed; ignoring duplicate event", run_id)
        return {"started": False, "reason": "duplicate"}

    metadata = client("s3").head_object(Bucket=bucket, Key=key).get("Metadata", {})
    payload = {"source_key": key, **options_from_metadata(metadata)}
    response = client("bedrock-agentcore").invoke_agent_runtime(
        agentRuntimeArn=os.environ["AGENT_RUNTIME_ARN"],
        runtimeSessionId=f"remediation-{run_id}-{project}"[:100].ljust(33, "0"),  # 33-100 characters
        contentType="application/json",
        accept="application/json",
        payload=json.dumps(payload).encode(),
    )
    body = response["response"].read().decode()
    log.info("Started run %s for project %s: %s", run_id, project, body[:300])
    return {"started": True, "run_id": run_id}
