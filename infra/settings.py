# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Deployment settings: the .env file, and the model ID picked from the deployment Region.

Precedence for every setting, highest first:
  1. cdk -c <key>=<value> on the command line
  2. environment variables already set in the shell
  3. the .env file in the repository root
  4. built-in defaults (the model ID is derived from the Region)
"""

from __future__ import annotations

import os
import re
from pathlib import Path

DEFAULT_BASE_MODEL_ID = "anthropic.claude-sonnet-4-5-20250929-v1:0"

# Geographic cross-Region inference profiles, from the Amazon Bedrock model card for Claude
# Sonnet 4.5 (the US, EU, AU, and JP geographies). Every other commercial Region uses the
# global profile. Check the model card of the base model you choose for its own list.
GEO_PROFILE_REGIONS = {
    "us": {"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1"},
    "eu": {"eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3"},
    "au": {"ap-southeast-2", "ap-southeast-4", "ap-southeast-6"},
    "jp": {"ap-northeast-1", "ap-northeast-3"},
}

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def load_dotenv(path: Path) -> dict[str, str]:
    """Load KEY=VALUE lines into os.environ without overriding variables that are already set.

    Supports comments, blank lines, optional `export`, and single or double quotes.
    No variable expansion, so the file is plain data.
    """
    loaded: dict[str, str] = {}
    if not path.is_file():
        return loaded
    for raw in path.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = _LINE.match(raw)
        if not match:
            continue
        key, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        loaded[key] = value
        if value and not os.environ.get(key):
            os.environ[key] = value
    return loaded


def default_model_id(region: str, base_model_id: str | None = None) -> str:
    """The inference profile to use in `region` for `base_model_id`."""
    base = (base_model_id or DEFAULT_BASE_MODEL_ID).strip()
    if region.startswith(("us-gov-", "cn-", "us-iso")):
        raise ValueError(
            f"No automatic model choice for {region}. Set MODEL_ID in .env to a model or inference profile "
            "that is available in that partition."
        )
    for geography, regions in GEO_PROFILE_REGIONS.items():
        if region in regions:
            return f"{geography}.{base}"
    return f"global.{base}"


def deployment_region() -> str | None:
    """AWS_REGION (shell or .env) wins over the CDK CLI's default Region."""
    return os.environ.get("AWS_REGION") or os.environ.get("CDK_DEFAULT_REGION") or None
