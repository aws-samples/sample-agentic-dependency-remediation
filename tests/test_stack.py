# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Infrastructure assertions. Lambda bundling is skipped so the test does not need Docker."""

import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from infra.remediation_stack import RemediationStack


@pytest.fixture(scope="module")
def template():
    app = cdk.App(context={"aws:cdk:bundling-stacks": [], "model_id": "us.anthropic.claude-sonnet-4-5-20250929-v1:0"})
    stack = RemediationStack(app, "Test", env=cdk.Environment(account="111111111111", region="us-east-1"))
    return Template.from_stack(stack)


def test_core_resources(template):
    template.resource_count_is("AWS::BedrockAgentCore::Runtime", 1)
    template.resource_count_is("AWS::BedrockAgentCore::Memory", 1)
    template.resource_count_is("AWS::Bedrock::Guardrail", 1)
    template.resource_count_is("AWS::CodeBuild::Project", 1)
    template.resource_count_is("AWS::DynamoDB::Table", 1)
    template.resource_count_is("AWS::SNS::Topic", 1)


def test_no_source_control_credentials(template):
    template.resource_count_is("AWS::BedrockAgentCore::ApiKeyCredentialProvider", 0)
    policies = json.dumps(template.find_resources("AWS::IAM::Policy"))
    assert "GetResourceApiKey" not in policies
    assert "secretsmanager" not in policies


def test_upload_triggers_run(template):
    template.has_resource_properties(
        "AWS::Events::Rule",
        {"EventPattern": Match.object_like({"source": ["aws.s3"], "detail-type": ["Object Created"],
                                            "detail": Match.object_like({"object": {"key": [{"prefix": "requests/"}]}})})},
    )
    # S3 -> EventBridge delivery is set with the native CloudFormation property (no helper function).
    template.has_resource_properties(
        "AWS::S3::Bucket", {"NotificationConfiguration": {"EventBridgeConfiguration": {"EventBridgeEnabled": True}}}
    )


def test_trigger_has_function_dead_letter_queue(template):
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Handler": "handler.handler", "DeadLetterConfig": {"TargetArn": Match.any_value()}},
    )


def test_agent_sends_completion_email(template):
    template.has_resource_properties(
        "AWS::BedrockAgentCore::Runtime",
        {"EnvironmentVariables": Match.object_like({"NOTIFICATION_TOPIC_ARN": Match.any_value()})},
    )
    template.has_resource_properties(
        "AWS::IAM::Policy",
        {"PolicyDocument": {"Statement": Match.array_with([Match.object_like({"Sid": "SendCompletionEmail", "Action": "sns:Publish"})])}},
    )
    # The topic accepts publishing only through IAM (the agent role); no service principal is allowed.
    for res in template.find_resources("AWS::SNS::TopicPolicy").values():
        assert not [s for s in res["Properties"]["PolicyDocument"]["Statement"] if s["Effect"] == "Allow"]


def test_guardrail_filters_prompt_attacks(template):
    template.has_resource_properties(
        "AWS::Bedrock::Guardrail",
        {"ContentPolicyConfig": {"FiltersConfig": [Match.object_like({"Type": "PROMPT_ATTACK", "InputStrength": "HIGH"})]}},
    )


def test_bucket_is_private_and_encrypted(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
            "BucketEncryption": Match.any_value(),
        },
    )


def test_client_policy_is_scoped(template):
    policies = template.find_resources("AWS::IAM::ManagedPolicy")
    assert len(policies) == 1
    text = json.dumps(policies)
    assert "requests/*" in text and "results/*" in text and "runs/*" not in text
