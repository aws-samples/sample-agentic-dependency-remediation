# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Orchestrates one remediation run: load the source, run the agent, publish the results."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from strands import Agent
from strands.models import BedrockModel

from .audit import AuditLog
from .build_runner import make_runner
from .config import Settings
from .ecosystems import detect_adapter, get_adapter
from .memory_store import FixMemory
from .prompts import SYSTEM_PROMPT, task_prompt
from .report import build_report, build_result
from .tools import RemediationTask, RunState, ToolBudget, build_tools
from .workspace import Workspace, WorkspaceError

log = logging.getLogger(__name__)

REPO_CONFIG_FILE = "remediation.json"
REPO_CONFIG_KEYS = {"ecosystem", "app_dir", "packages", "ignore"}


@dataclass
class RunOutcome:
    run_id: str
    status: str
    reason: str
    fixed: list[dict]
    skipped: list[dict]
    build_attempts: int
    tool_calls: int
    input_tokens: int
    output_tokens: int
    duration_seconds: int
    changed_files: list[str]
    artifacts: dict = field(default_factory=dict)


def build_model(settings: Settings) -> BedrockModel:
    kwargs = {"model_id": settings.model_id, "region_name": settings.region, "temperature": 0.0, "max_tokens": 8192}
    if settings.guardrail_id and settings.guardrail_version:
        # Evaluate only the latest message on each turn, so that the guardrail does not
        # rescan (and repeatedly bill for) the whole conversation history.
        kwargs.update(
            guardrail_id=settings.guardrail_id,
            guardrail_version=settings.guardrail_version,
            guardrail_trace="enabled",
            guardrail_latest_message=True,
        )
    return BedrockModel(**kwargs)


def apply_repo_config(payload: dict, ws: Workspace) -> dict:
    """Merge remediation.json from the repository root. Values in the request take precedence."""
    payload = {k: v for k, v in payload.items() if v not in (None, "", [])}
    path = ws.root / REPO_CONFIG_FILE
    if not path.is_file() or path.stat().st_size > 20_000:
        return payload
    try:
        config = json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError):
        log.warning("Ignoring invalid %s", REPO_CONFIG_FILE)
        return payload
    if not isinstance(config, dict):
        return payload
    merged = {k: v for k, v in config.items() if k in REPO_CONFIG_KEYS}
    merged.update({k: v for k, v in payload.items() if v not in (None, "", [])})
    return merged


def run_remediation(
    payload: dict,
    run_id: str,
    settings: Settings,
    *,
    source_archive: bytes | Path | None = None,
    local_repo: Path | None = None,
    sink=None,
    model=None,
) -> RunOutcome:
    """Run the agent on one source tree and publish result.json, fix.patch, and report.md to `sink`."""
    started = time.time()
    audit = AuditLog(settings.runs_table, settings.region)
    audit.update(run_id, status="IN_PROGRESS", project=payload.get("project"), started_at=int(started))
    state = RunState()
    usage: dict = {}
    task = None
    adapter = None
    patch = None
    changed: list[str] = []

    with tempfile.TemporaryDirectory(prefix="remediation-ws-") as tmp:
        ws = Workspace(Path(tmp) / "repo", max_files_changed=settings.max_files_changed)
        try:
            if local_repo is not None:
                shutil.copytree(local_repo, ws.root, ignore=shutil.ignore_patterns("node_modules", "target", ".venv", ".git", "__pycache__"))
                ws.snapshot()
            elif source_archive is not None:
                ws.extract_archive(source_archive)
            else:
                raise ValueError("Provide a source archive or a local repository.")

            task = RemediationTask.from_payload(apply_repo_config(payload, ws), run_id)
            adapter = get_adapter(task.ecosystem) if task.ecosystem else detect_adapter(ws, task.app_dir)

            tools = build_tools(
                task=task,
                ws=ws,
                adapter=adapter,
                state=state,
                runner=make_runner(settings),
                memory=FixMemory(settings.memory_id, settings.region),
                max_build_attempts=settings.max_build_attempts,
            )
            agent = Agent(
                model=model or build_model(settings),
                system_prompt=SYSTEM_PROMPT,
                tools=tools,
                hooks=[ToolBudget(state, settings.max_tool_calls)],
                callback_handler=None,
                trace_attributes={"remediation.run_id": run_id, "remediation.project": task.project, "remediation.ecosystem": adapter.name},
            )
            result = agent(task_prompt(task, adapter.name))
            usage = result.metrics.accumulated_usage or {}
            if state.status == "IN_PROGRESS":
                state.status, state.reason = "INCOMPLETE", "The agent ended without submitting a fix or stopping explicitly."
        except Exception as exc:
            log.exception("Remediation run %s failed", run_id)
            state.status, state.reason = "ERROR", f"{type(exc).__name__}: {exc}"[:1000]

        if state.status in ("FIXED", "PARTIAL_FIX") and ws.fingerprint() == state.passing_fingerprint:
            try:
                patch = ws.unified_patch()
                changed = ws.changed_files()
            except WorkspaceError as exc:
                state.status, state.reason = "ERROR", f"The build passed but no valid patch could be produced: {exc}"
        elif state.status in ("FIXED", "PARTIAL_FIX"):
            state.status, state.reason = "ERROR", "Workspace changed after the passing build; no patch was published."

    task = task or RemediationTask(run_id=run_id, project=str(payload.get("project") or "default"))
    extra = {
        "tool_calls": state.tool_calls,
        "input_tokens": int(usage.get("inputTokens", 0)),
        "output_tokens": int(usage.get("outputTokens", 0)),
        "duration_seconds": int(time.time() - started),
        "changed_files": changed,
        "model_id": settings.model_id,
    }
    result = build_result(task, adapter.name if adapter else None, state, extra)
    log_tail = state.last_build.log_summary if state.last_build and not state.last_build.passed else None
    report = build_report(result, state.change_summary, patch, log_tail)
    artifacts = sink.write(result, patch, report) if sink else {}

    audit.update(run_id, status=state.status, reason=state.reason, project=task.project, build_attempts=state.attempts,
                 fixed=[f["package"] for f in result["fixed"]], artifacts=artifacts, **extra)
    return RunOutcome(
        run_id=run_id,
        status=state.status,
        reason=state.reason,
        fixed=result["fixed"],
        skipped=result["skipped"],
        build_attempts=state.attempts,
        tool_calls=state.tool_calls,
        input_tokens=extra["input_tokens"],
        output_tokens=extra["output_tokens"],
        duration_seconds=extra["duration_seconds"],
        changed_files=changed,
        artifacts=artifacts,
    )
