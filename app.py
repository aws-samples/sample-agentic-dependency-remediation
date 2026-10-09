#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import os
from pathlib import Path

import aws_cdk as cdk

from infra.remediation_stack import RemediationStack
from infra.settings import default_model_id, deployment_region, load_dotenv

# Settings from .env (see .env.example). Shell variables and -c context values take precedence.
load_dotenv(Path(__file__).resolve().parent / ".env")

app = cdk.App()
region = deployment_region()

# Model: -c model_id > MODEL_ID > the inference profile for the deployment Region.
if not app.node.try_get_context("model_id"):
    model_id = os.environ.get("MODEL_ID") or (default_model_id(region, os.environ.get("BASE_MODEL_ID")) if region else None)
    if model_id:
        app.node.set_context("model_id", model_id)
if not app.node.try_get_context("notification_email") and os.environ.get("NOTIFICATION_EMAIL"):
    app.node.set_context("notification_email", os.environ["NOTIFICATION_EMAIL"])

RemediationStack(
    app,
    os.environ.get("STACK_NAME") or "DependencyRemediationAgent",
    env=cdk.Environment(account=os.environ.get("CDK_DEFAULT_ACCOUNT"), region=region),
    description="Self-correcting AI agent for dependency remediation (Strands Agents on Amazon Bedrock AgentCore)",
)
app.synth()
