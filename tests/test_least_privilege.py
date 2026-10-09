# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Least-privilege guarantees for the IAM policies the stack creates."""

import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra.remediation_stack import RemediationStack, model_resources

ACCOUNT, REGION = "111111111111", "us-east-1"
MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

# Wildcard resources that are allowed, because these actions do not support resource-level permissions.
ALLOWED_STAR_ACTIONS = {
    "ecr:GetAuthorizationToken",
    "xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets",
    "cloudwatch:PutMetricData",  # restricted by a cloudwatch:namespace condition
}


@pytest.fixture(scope="module")
def statements():
    app = cdk.App(context={"aws:cdk:bundling-stacks": [], "model_id": MODEL})
    stack = RemediationStack(app, "Test", env=cdk.Environment(account=ACCOUNT, region=REGION))
    resources = Template.from_stack(stack).to_json()["Resources"]
    out = []
    for logical_id, res in resources.items():
        if res["Type"] in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            for st in res["Properties"]["PolicyDocument"]["Statement"]:
                actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                targets = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
                out.append((logical_id, actions, targets, st.get("Condition")))
    return out


def test_no_action_wildcards(statements):
    for logical_id, actions, _, _ in statements:
        for action in actions:
            assert action != "*" and not action.endswith(":*"), (logical_id, action)


def test_star_resource_only_for_actions_without_resource_support(statements):
    for logical_id, actions, targets, condition in statements:
        if "*" in targets:
            assert set(actions) <= ALLOWED_STAR_ACTIONS, (logical_id, actions)
            if "cloudwatch:PutMetricData" in actions:
                assert condition and "cloudwatch:namespace" in json.dumps(condition)


def test_s3_grants_are_object_scoped(statements):
    for logical_id, actions, targets, condition in statements:
        if logical_id.startswith(("CustomS3AutoDelete", "ArtifactBucketNotifications")):
            continue  # CDK-managed deployment helpers
        s3_actions = [a for a in actions if a.startswith("s3:")]
        assert not any(a.endswith("*") for a in s3_actions), (logical_id, s3_actions)  # no s3:List*, s3:GetObject*
        assert not {"s3:PutObjectLegalHold", "s3:PutObjectRetention", "s3:DeleteObject"} & set(s3_actions), logical_id
        if "s3:ListBucket" in s3_actions:
            assert condition and "s3:prefix" in json.dumps(condition), logical_id


def test_model_access_is_limited_to_the_configured_model(statements):
    invoke = [t for _, a, t, _ in statements if "bedrock:InvokeModel" in a]
    assert len(invoke) == 1
    text = json.dumps(invoke[0])
    assert "foundation-model/*" not in text and "inference-profile/*" not in text
    assert "inference-profile/us.anthropic.claude-sonnet-4-5" in text


def test_memory_access_is_minimal(statements):
    actions = {a for _, acts, _, _ in statements for a in acts if a.startswith("bedrock-agentcore:")}
    assert actions == {"bedrock-agentcore:CreateEvent", "bedrock-agentcore:RetrieveMemoryRecords", "bedrock-agentcore:InvokeAgentRuntime"}


def test_events_publish_is_limited_to_own_source(statements):
    put = [(t, c) for _, a, t, c in statements if "events:PutEvents" in a]
    assert len(put) == 1 and "dependency.remediation" in json.dumps(put[0][1])


@pytest.mark.parametrize(
    "model_id,expected",
    [
        ("us.anthropic.m-v1:0", ["inference-profile/us.anthropic.m-v1:0", "arn:aws:bedrock:*::foundation-model/anthropic.m-v1:0"]),
        ("global.anthropic.m-v1:0", ["inference-profile/global.anthropic.m-v1:0", "arn:aws:bedrock:*::foundation-model/anthropic.m-v1:0"]),
        ("anthropic.m-v1:0", ["arn:aws:bedrock:eu-west-1::foundation-model/anthropic.m-v1:0"]),
    ],
)
def test_model_resources(model_id, expected):
    arns = model_resources(model_id, "eu-west-1", ACCOUNT)
    assert len(arns) == len(expected)
    for arn, want in zip(arns, expected):
        assert arn.endswith(want) or arn == want


@pytest.fixture(scope="module")
def resources():
    app = cdk.App(context={"aws:cdk:bundling-stacks": [], "model_id": MODEL})
    stack = RemediationStack(app, "Test2", env=cdk.Environment(account=ACCOUNT, region=REGION))
    return Template.from_stack(stack).to_json()["Resources"]


def test_no_aws_managed_policies(resources):
    """AWSLambdaBasicExecutionRole and similar grant CloudWatch Logs on "*"; every role uses scoped inline policies."""
    for logical_id, res in resources.items():
        if res["Type"] == "AWS::IAM::Role":
            assert not res["Properties"].get("ManagedPolicyArns"), logical_id


def test_no_cdk_helper_functions(resources):
    """The bucket-notification and auto-delete helpers (and their broad roles) are not deployed."""
    types = {r["Type"] for r in resources.values()}
    assert not {"Custom::S3BucketNotifications", "Custom::S3AutoDeleteObjects"} & types
    functions = [k for k, r in resources.items() if r["Type"] == "AWS::Lambda::Function"]
    assert len(functions) == 1, functions
    bucket = next(r for r in resources.values() if r["Type"] == "AWS::S3::Bucket")
    assert bucket["Properties"]["NotificationConfiguration"]["EventBridgeConfiguration"]["EventBridgeEnabled"] is True


def test_service_trust_policies_are_bound(resources):
    for logical_id, res in resources.items():
        if res["Type"] == "AWS::IAM::Role":
            statement = res["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
            assert "aws:SourceAccount" in json.dumps(statement.get("Condition", {})), logical_id


def test_resource_policies_are_bound_to_their_source(resources):
    for logical_id, res in resources.items():
        if res["Type"] in ("AWS::SNS::TopicPolicy", "AWS::SQS::QueuePolicy"):
            for st in res["Properties"]["PolicyDocument"]["Statement"]:
                if st["Effect"] == "Allow":
                    assert "aws:SourceArn" in json.dumps(st.get("Condition", {})), logical_id
        if res["Type"] == "AWS::Lambda::Permission":
            assert res["Properties"].get("SourceArn"), logical_id
        if res["Type"] == "AWS::S3::BucketPolicy":
            allows = [s for s in res["Properties"]["PolicyDocument"]["Statement"] if s["Effect"] == "Allow"]
            assert not allows, logical_id  # only the TLS-only deny remains


def test_dynamodb_writes_limited_to_run_records(resources):
    found = 0
    for res in resources.values():
        if res["Type"] == "AWS::IAM::Policy":
            for st in res["Properties"]["PolicyDocument"]["Statement"]:
                actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                if any(a.startswith("dynamodb:") for a in actions):
                    found += 1
                    assert "dynamodb:LeadingKeys" in json.dumps(st.get("Condition", {}))
    assert found == 2


def test_agent_logs_scoped_to_its_runtime(statements):
    for _, actions, targets, _ in statements:
        if "logs:PutLogEvents" in actions:
            assert all("runtimes/*" not in json.dumps(t) and not str(t).endswith("log-group:*") for t in targets)
