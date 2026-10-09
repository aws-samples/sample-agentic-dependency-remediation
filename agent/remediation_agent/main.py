# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Amazon Bedrock AgentCore Runtime entrypoint.

The trigger function invokes the agent after a source archive lands in
s3://<bucket>/requests/<project>/<run-id>/. The invocation returns immediately
with {"status": "ACCEPTED"}; the run continues in a background thread that is
registered as an async task, so AgentCore Runtime keeps the session alive
until it finishes. Results are written to s3://<bucket>/results/<project>/<run-id>/.
"""

from __future__ import annotations

import contextvars
import logging
import re
import tempfile
import threading
from pathlib import Path

import boto3
from bedrock_agentcore.runtime import BedrockAgentCoreApp

from .config import Settings
from .results import S3ResultSink
from .runner import run_remediation

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("remediation")

app = BedrockAgentCoreApp()
settings = Settings.from_env()

REQUEST_KEY = re.compile(r"^requests/(?P<project>[A-Za-z0-9][A-Za-z0-9._-]{0,99})/(?P<run_id>[A-Za-z0-9-]{8,64})/source\.(zip|tar\.gz|tgz)$")
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024


def _run_in_background(payload: dict, run_id: str, project: str, key: str, task_id: int) -> None:
    try:
        s3 = boto3.client("s3", region_name=settings.region)
        # Check the size before downloading anything, then stream to disk (never into memory).
        size = s3.head_object(Bucket=settings.artifact_bucket, Key=key)["ContentLength"]
        if size > MAX_ARCHIVE_BYTES:
            raise ValueError(f"Source archive is {size} bytes; the limit is {MAX_ARCHIVE_BYTES}.")
        sink = S3ResultSink(settings.artifact_bucket, f"results/{project}/{run_id}/", settings.region, settings.event_bus, settings.notification_topic_arn)
        with tempfile.TemporaryDirectory(prefix="remediation-src-") as tmp:
            archive = Path(tmp) / "source"
            s3.download_file(settings.artifact_bucket, key, str(archive))
            if archive.stat().st_size > MAX_ARCHIVE_BYTES:  # the object could have been replaced
                raise ValueError("Source archive is too large.")
            outcome = run_remediation(payload, run_id, settings, source_archive=archive, sink=sink)
        log.info("Run %s finished: %s", run_id, outcome.status)
    except Exception:
        log.exception("Run %s failed before the agent started", run_id)
        try:
            S3ResultSink(settings.artifact_bucket, f"results/{project}/{run_id}/", settings.region, settings.event_bus, settings.notification_topic_arn).write(
                {"run_id": run_id, "project": project, "status": "ERROR", "reason": "Could not load the source archive.", "fixed": [], "skipped": []},
                None,
                "The run failed before the agent started. See the agent logs.",
            )
        except Exception:
            log.exception("Could not write the error result for %s", run_id)
    finally:
        app.complete_async_task(task_id)


@app.entrypoint
def invoke(payload: dict, context=None) -> dict:
    # Only archives in this stack's own bucket, under requests/, are accepted.
    key = str(payload.get("source_key", ""))
    match = REQUEST_KEY.match(key)
    if not match:
        return {"status": "REJECTED", "reason": "source_key must be requests/<project>/<run-id>/source.zip"}
    run_id, project = match.group("run_id"), match.group("project")
    # Pass on only the options the caller actually set; unset ones fall back to remediation.json or defaults.
    options = {k: payload[k] for k in ("ecosystem", "app_dir", "packages", "ignore", "vulnerability_ids") if payload.get(k) not in (None, "", [])}
    options["project"] = project

    task_id = app.add_async_task("dependency-remediation", {"run_id": run_id, "project": project})
    worker = threading.Thread(
        target=contextvars.copy_context().run,
        args=(_run_in_background, options, run_id, project, key, task_id),
        name=f"remediation-{run_id}",
        daemon=True,
    )
    worker.start()
    return {"status": "ACCEPTED", "run_id": run_id, "results": f"s3://{settings.artifact_bucket}/results/{project}/{run_id}/"}


if __name__ == "__main__":
    app.run()
