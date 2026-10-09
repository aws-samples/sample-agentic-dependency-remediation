# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The .env file and the automatic model choice for each Region."""

import json
import os
import subprocess  # nosec B404 - runs the CDK app with a fixed argument list
import sys
from pathlib import Path

import pytest

from infra.remediation_stack import check_model_region
from infra.settings import DEFAULT_BASE_MODEL_ID, default_model_id, load_dotenv

ROOT = Path(__file__).resolve().parent.parent
BASE = DEFAULT_BASE_MODEL_ID


@pytest.mark.parametrize(
    "region,prefix",
    [
        ("us-east-1", "us"), ("us-west-2", "us"), ("ca-central-1", "us"),
        ("eu-west-1", "eu"), ("eu-central-2", "eu"), ("eu-west-2", "eu"),
        ("ap-southeast-2", "au"), ("ap-southeast-4", "au"),
        ("ap-northeast-1", "jp"), ("ap-northeast-3", "jp"),
        ("ap-south-1", "global"), ("ap-southeast-1", "global"), ("ap-northeast-2", "global"),
        ("sa-east-1", "global"), ("me-central-1", "global"), ("ca-west-1", "global"),
    ],
)
def test_model_follows_region(region, prefix):
    model = default_model_id(region)
    assert model == f"{prefix}.{BASE}"
    check_model_region(model, region)  # the synth-time check accepts every automatic choice


def test_custom_base_model():
    assert default_model_id("eu-west-1", "anthropic.claude-sonnet-4-6") == "eu.anthropic.claude-sonnet-4-6"


@pytest.mark.parametrize("region", ["us-gov-west-1", "cn-north-1"])
def test_other_partitions_require_explicit_model(region):
    with pytest.raises(ValueError, match="Set MODEL_ID"):
        default_model_id(region)


def test_dotenv_parsing_and_precedence(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n\nexport AWS_REGION=eu-west-1\nMODEL_ID=\nNOTIFICATION_EMAIL='team@example.com'\n"
        'STACK_NAME="Remediation"  \nBASE_MODEL_ID=anthropic.x  # trailing comment\nnot a setting\n'
    )
    for key in ("AWS_REGION", "MODEL_ID", "NOTIFICATION_EMAIL", "STACK_NAME", "BASE_MODEL_ID"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("STACK_NAME", "FromShell")  # the shell wins over .env
    loaded = load_dotenv(env)
    assert os.environ["AWS_REGION"] == "eu-west-1"
    assert os.environ["NOTIFICATION_EMAIL"] == "team@example.com"
    assert os.environ["BASE_MODEL_ID"] == "anthropic.x"
    assert os.environ["STACK_NAME"] == "FromShell"
    assert "MODEL_ID" not in os.environ  # empty values are ignored
    assert loaded["STACK_NAME"] == "Remediation"


def test_missing_dotenv_is_fine(tmp_path):
    assert load_dotenv(tmp_path / ".env") == {}


def _synth_env_vars(extra_env: dict, *context: str) -> dict:
    """Run the real CDK app (app.py) and return the agent runtime's environment variables."""
    out = Path(extra_env["CDK_OUTDIR"])
    env = {k: v for k, v in os.environ.items() if k not in ("AWS_REGION", "MODEL_ID", "BASE_MODEL_ID", "CDK_DEFAULT_REGION")}
    env.update(extra_env, CDK_DEFAULT_ACCOUNT="111111111111")
    args = [sys.executable, "app.py"]
    ctx = {"aws:cdk:bundling-stacks": []}
    for item in context:
        key, value = item.split("=", 1)
        ctx[key] = value
    env["CDK_CONTEXT_JSON"] = json.dumps(ctx)
    subprocess.run(args, cwd=ROOT, env=env, check=True, capture_output=True)  # nosec B603
    template = json.loads(next(out.glob("*.template.json")).read_text())
    runtime = next(r for r in template["Resources"].values() if r["Type"] == "AWS::BedrockAgentCore::Runtime")
    return runtime["Properties"]["EnvironmentVariables"]


def test_app_picks_model_from_region(tmp_path):
    variables = _synth_env_vars({"AWS_REGION": "eu-west-1", "CDK_OUTDIR": str(tmp_path)})
    assert variables["REMEDIATION_REGION"] == "eu-west-1"
    assert variables["MODEL_ID"] == f"eu.{BASE}"


def test_app_explicit_model_wins(tmp_path):
    variables = _synth_env_vars({"AWS_REGION": "ap-south-1", "MODEL_ID": f"apac.{BASE}", "CDK_OUTDIR": str(tmp_path)},
                                f"model_id=global.{BASE}")
    assert variables["MODEL_ID"] == f"global.{BASE}"  # -c beats MODEL_ID
