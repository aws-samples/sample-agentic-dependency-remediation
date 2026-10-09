# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The solution deploys to any Region; nothing falls back to a hard-coded Region."""

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from infra.remediation_stack import RemediationStack, check_model_region
from remediation_agent.config import resolve_region


def synth(region: str, model_id: str) -> Template:
    app = cdk.App(context={"aws:cdk:bundling-stacks": [], "model_id": model_id})
    stack = RemediationStack(app, "Test", env=cdk.Environment(account="111111111111", region=region))
    return Template.from_stack(stack)


@pytest.mark.parametrize(
    "region,model_id",
    [
        ("us-west-2", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("eu-west-1", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("ap-southeast-2", "apac.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("eu-central-1", "global.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("eu-central-1", "anthropic.claude-sonnet-4-5-20250929-v1:0"),  # in-Region model ID
    ],
)
def test_stack_passes_deployment_region_to_agent(region, model_id):
    template = synth(region, model_id)
    template.has_resource_properties(
        "AWS::BedrockAgentCore::Runtime",
        {"EnvironmentVariables": Match.object_like({"REMEDIATION_REGION": region, "MODEL_ID": model_id})},
    )


@pytest.mark.parametrize(
    "region,model_id",
    [
        ("eu-west-1", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("us-east-1", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("us-gov-west-1", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
    ],
)
def test_mismatched_inference_profile_fails_at_synth(region, model_id):
    with pytest.raises(ValueError, match="cannot be used in"):
        check_model_region(model_id, region)


def test_missing_model_id_fails_at_synth():
    with pytest.raises(ValueError, match="model_id"):
        check_model_region(None, "us-east-1")


def test_region_resolution_order(monkeypatch):
    for name in ("REMEDIATION_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    assert resolve_region() == "ap-south-1"
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert resolve_region() == "eu-west-1"
    monkeypatch.setenv("REMEDIATION_REGION", "ca-central-1")
    assert resolve_region() == "ca-central-1"


def test_no_silent_default_region(monkeypatch, tmp_path):
    for name in ("REMEDIATION_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)
    empty_config = tmp_path / "config"
    empty_config.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(empty_config))
    monkeypatch.setenv("AWS_PROFILE", "default")
    with pytest.raises(RuntimeError, match="No AWS Region"):
        resolve_region()
