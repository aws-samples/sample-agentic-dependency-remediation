# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Amazon Bedrock AgentCore Runtime requires an arm64 image that serves HTTP on port 8080.
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY remediation_agent ./remediation_agent

# Run as a non-root user.
RUN useradd --create-home --uid 1000 agent
USER agent

EXPOSE 8080

# Container health check against the AgentCore Runtime ping endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/ping', timeout=4).status == 200 else 1)"]

# opentelemetry-instrument sends traces to AgentCore Observability (CloudWatch).
CMD ["opentelemetry-instrument", "python", "-m", "remediation_agent.main"]
