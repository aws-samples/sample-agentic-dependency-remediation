# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Runtime configuration, read from environment variables set by the CDK stack."""

from __future__ import annotations

import os
from dataclasses import dataclass


def resolve_region() -> str:
    """The AWS Region the agent runs in.

    Order: REMEDIATION_REGION (set by the CDK stack to the deployment Region), then the
    standard AWS_REGION / AWS_DEFAULT_REGION variables, then the boto3 configuration.
    There is deliberately no hard-coded default, so a run never silently uses another Region.
    """
    for name in ("REMEDIATION_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"):
        if value := os.environ.get(name, "").strip():
            return value
    import boto3

    if region := boto3.session.Session().region_name:
        return region
    raise RuntimeError("No AWS Region configured. Set REMEDIATION_REGION or AWS_REGION.")


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


@dataclass(frozen=True)
class Settings:
    region: str
    model_id: str
    guardrail_id: str | None
    guardrail_version: str | None
    memory_id: str | None
    runs_table: str | None
    artifact_bucket: str | None
    codebuild_project: str | None
    event_bus: str | None
    notification_topic_arn: str | None
    build_backend: str  # "codebuild" or "local"
    max_build_attempts: int
    max_files_changed: int
    max_tool_calls: int
    build_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            region=resolve_region(),
            model_id=os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
            guardrail_id=os.environ.get("GUARDRAIL_ID") or None,
            guardrail_version=os.environ.get("GUARDRAIL_VERSION") or None,
            memory_id=os.environ.get("MEMORY_ID") or None,
            runs_table=os.environ.get("RUNS_TABLE") or None,
            artifact_bucket=os.environ.get("ARTIFACT_BUCKET") or None,
            codebuild_project=os.environ.get("CODEBUILD_PROJECT") or None,
            event_bus=os.environ.get("EVENT_BUS") or None,
            notification_topic_arn=os.environ.get("NOTIFICATION_TOPIC_ARN") or None,
            build_backend=os.environ.get("BUILD_BACKEND", "codebuild"),
            max_build_attempts=_int("MAX_BUILD_ATTEMPTS", 6),
            max_files_changed=_int("MAX_FILES_CHANGED", 20),
            max_tool_calls=_int("MAX_TOOL_CALLS", 100),
            build_timeout_seconds=_int("BUILD_TIMEOUT_SECONDS", 1200),
        )
