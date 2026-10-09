# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Strands tools for the remediation agent, bound to a single run.

Design rules:

* The model decides *what* to do; these tools decide *whether it is allowed*.
  Every tool validates its input and enforces a budget or precondition.
* Tool results are plain text that the model can reason about. Errors are
  returned as text (not raised) so the model can correct itself.
* Final run status is derived from tool state, never from the model's prose.
* The agent has no Git credentials. Its only output is a verified patch that
  the caller's pipeline applies and turns into a merge request or pull request.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from strands import tool
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

from . import advisories
from .build_runner import BuildResult
from .ecosystems import EcosystemAdapter, parse_version
from .memory_store import FixMemory
from .workspace import Workspace, WorkspaceError

log = logging.getLogger(__name__)

ALWAYS_ALLOWED_TOOLS = {"stop_remediation"}
MAX_SCANNED_DEPENDENCIES = 200
_NAME = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._:/-]{0,213}$")
_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_APP_DIR = re.compile(r"^[A-Za-z0-9._/-]{0,200}$")


@dataclass
class RemediationTask:
    run_id: str
    project: str
    ecosystem: str | None = None  # None = detect from the manifest
    app_dir: str = ""
    packages: list[str] = field(default_factory=list)  # empty = scan all declared dependencies
    ignore: list[str] = field(default_factory=list)
    vulnerability_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_payload(cls, payload: dict, run_id: str) -> "RemediationTask":
        project = str(payload.get("project") or "default")
        if not _PROJECT.match(project):
            raise ValueError("project may contain only letters, digits, '.', '_' and '-' (max 100 characters).")
        app_dir = str(payload.get("app_dir") or "").strip().strip("/")
        if app_dir == ".":
            app_dir = ""
        # The build script quotes APP_DIR, so shell metacharacters are never interpreted.
        # A strict character set is enforced anyway as a second layer.
        if not _APP_DIR.match(app_dir):
            raise ValueError("app_dir may contain only letters, digits, '.', '_', '-' and '/'.")
        if ".." in app_dir.split("/"):
            raise ValueError("app_dir must not contain '..'.")
        ecosystem = payload.get("ecosystem")
        packages = _names(payload.get("packages") or ([payload["package"]] if payload.get("package") else []))
        return cls(
            run_id=run_id,
            project=project,
            ecosystem=str(ecosystem).lower() if ecosystem else None,
            app_dir=app_dir,
            packages=packages,
            ignore=_names(payload.get("ignore") or []),
            vulnerability_ids=[str(v)[:50] for v in (payload.get("vulnerability_ids") or [])][:20],
        )


def _names(values) -> list[str]:
    if isinstance(values, str):
        values = [v.strip() for v in values.split(",")]
    names = [str(v).strip() for v in values if str(v).strip()][:50]
    bad = [n for n in names if not _NAME.match(n)]
    if bad:
        raise ValueError(f"Invalid package names: {', '.join(bad[:5])}")
    return names


@dataclass
class PackageFix:
    package: str
    from_version: str
    to_version: str | None = None
    advisories: list[str] = field(default_factory=list)
    status: str = "PENDING"  # PENDING, UPDATED, NO_SAFE_VERSION, SKIPPED
    note: str = ""


@dataclass
class RunState:
    status: str = "IN_PROGRESS"
    reason: str = ""
    packages: dict[str, PackageFix] = field(default_factory=dict)
    safe_versions: dict[str, set[str]] = field(default_factory=dict)
    scanned: bool = False
    attempts: int = 0
    last_build: BuildResult | None = None
    passing_fingerprint: str | None = None
    change_summary: str = ""
    tool_calls: int = 0

    def updated(self) -> list[PackageFix]:
        return [p for p in self.packages.values() if p.status == "UPDATED"]


class ToolBudget(HookProvider):
    """Caps the total number of tool calls in one run."""

    def __init__(self, state: RunState, max_calls: int):
        self.state = state
        self.max_calls = max_calls

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self._before_tool)

    def _before_tool(self, event: BeforeToolCallEvent) -> None:
        name = event.tool_use.get("name", "")
        if name in ALWAYS_ALLOWED_TOOLS:
            return
        self.state.tool_calls += 1
        if self.state.tool_calls > self.max_calls:
            event.cancel_tool = "Tool call budget exhausted. Call stop_remediation with a short explanation."
        elif self.state.status != "IN_PROGRESS":
            event.cancel_tool = f"The run has already finished with status {self.state.status}. Reply with a short summary."


def build_tools(
    *,
    task: RemediationTask,
    ws: Workspace,
    adapter: EcosystemAdapter,
    state: RunState,
    runner,
    memory: FixMemory,
    max_build_attempts: int,
):
    """Create the tool functions for one run. Closures keep per-run state out of globals."""

    def _norm(package: str) -> str:
        return adapter.normalize(package.strip())

    @tool
    def scan_dependencies() -> str:
        """Check every directly declared dependency against the OSV vulnerability database and list the vulnerable ones."""
        declared = {_norm(k): v for k, v in adapter.list_dependencies(ws, task.app_dir).items()}
        wanted = {_norm(p) for p in task.packages}
        ignored = {_norm(p) for p in task.ignore}
        candidates = {k: v for k, v in declared.items() if (not wanted or k in wanted) and k not in ignored}
        missing = sorted(wanted - set(declared))
        lines = []
        for package, version in list(candidates.items())[:MAX_SCANNED_DEPENDENCIES]:
            found = advisories.query(adapter, package, version)
            if found:
                fix = state.packages.setdefault(package, PackageFix(package, version))
                fix.advisories = sorted({a.id for a in found} | set(task.vulnerability_ids if wanted else []))
                summaries = "; ".join(f"{a.id}: {a.summary[:120]}" for a in found[:4])
                lines.append(f"- {package} {version}: {len(found)} advisories ({summaries})")
        state.scanned = True
        header = f"Scanned {len(candidates)} declared dependencies in {adapter.name}."
        if missing:
            header += f" Not declared directly (transitive or absent, not handled): {', '.join(missing)}."
        if not lines:
            return header + " No known vulnerabilities. Call stop_remediation with reason 'no vulnerabilities'."
        return header + f"\n{len(lines)} vulnerable:\n" + "\n".join(lines)

    @tool
    def recall_similar_fixes(query: str) -> str:
        """Search long-term memory for fixes that worked in earlier runs, such as library migration steps.

        Args:
            query: What to look for, for example "jinja2 3.x breaking changes Markup".
        """
        if not memory.enabled:
            return "Long-term memory is not configured for this run."
        records = memory.recall(query)
        return "\n".join(f"- {r}" for r in records) if records else "No similar fixes found."

    @tool
    def choose_target_version(package: str) -> str:
        """Find the lowest stable version of a vulnerable package that has no known vulnerabilities.

        Args:
            package: A package reported by scan_dependencies.
        """
        fix = state.packages.get(_norm(package))
        if not fix:
            return f"'{package}' is not in the list of vulnerable packages. Run scan_dependencies first."
        choice = advisories.choose_safe_version(adapter, fix.package, fix.from_version)
        if not choice.target:
            fix.status, fix.note = "NO_SAFE_VERSION", choice.note
            return f"No safe version of {fix.package} found. {choice.note} Remaining advisories: {', '.join(choice.remaining_advisories)}."
        state.safe_versions.setdefault(fix.package, set()).add(choice.target)
        major_note = " This is a MAJOR version change, so expect breaking API changes." if choice.major_change else ""
        return f"Recommended: {fix.package} {fix.from_version} -> {choice.target}.{major_note}"

    @tool
    def update_dependency_version(package: str, version: str) -> str:
        """Change the declared version of a vulnerable package in the manifest.

        Args:
            package: A package reported by scan_dependencies.
            version: The target version, normally the one returned by choose_target_version.
        """
        fix = state.packages.get(_norm(package))
        if not fix:
            return f"'{package}' is not in the list of vulnerable packages."
        version = version.strip()
        if version not in state.safe_versions.get(fix.package, set()):
            if parse_version(version) is None:
                return f"'{version}' is not a stable release version."
            if parse_version(version) <= parse_version(fix.from_version):
                return "The target version must be newer than the current version."
            if advisories.query(adapter, fix.package, version):
                return f"{fix.package} {version} still has known vulnerabilities. Choose another version."
            if version not in adapter.registry_versions(fix.package):
                return f"{fix.package} {version} is not published in the registry."
            state.safe_versions.setdefault(fix.package, set()).add(version)
        try:
            change = adapter.update_dependency(ws, task.app_dir, fix.package, version)
        except WorkspaceError as exc:
            return f"Could not update the manifest: {exc}"
        fix.to_version, fix.status = version, "UPDATED"
        state.passing_fingerprint = None
        return f"Updated {change.manifest}: {change.old_spec} -> {change.new_spec}"

    @tool
    def skip_package(package: str, reason: str) -> str:
        """Leave a vulnerable package unfixed in this run, for example when the upgrade needs a design decision.
        Revert any edits you made for it with revert_file first, then build again.

        Args:
            package: A package reported by scan_dependencies.
            reason: Short explanation for the developer.
        """
        fix = state.packages.get(_norm(package))
        if not fix:
            return f"'{package}' is not in the list of vulnerable packages."
        declared = adapter.current_version(ws, task.app_dir, fix.package)
        if declared != fix.from_version:
            return f"The manifest still declares {fix.package} {declared}. Revert that change first (revert_file on the manifest, then re-apply the other upgrades)."
        fix.status, fix.to_version, fix.note = "SKIPPED", None, reason.strip()[:500]
        state.passing_fingerprint = None
        return f"{fix.package} will be reported as not fixed."

    @tool
    def list_files(subdir: str = "") -> str:
        """List files in the repository (build output and dependency folders are excluded).

        Args:
            subdir: Optional folder to list, relative to the repository root.
        """
        files = ws.list_files(subdir)
        return "\n".join(files) if files else "No files found."

    @tool
    def read_file(path: str, start_line: int = 1, end_line: int = 0) -> str:
        """Read a text file with line numbers, up to 400 lines at a time.

        Args:
            path: File path relative to the repository root.
            start_line: First line to read (1-based).
            end_line: Last line to read. Use 0 to read to the end (subject to the 400-line limit).
        """
        try:
            return ws.read_file(path, start_line, end_line or None)
        except (WorkspaceError, UnicodeDecodeError) as exc:
            return f"Error: {exc}"

    @tool
    def search_code(pattern: str) -> str:
        """Search all text files for a regular expression and return matching lines.

        Args:
            pattern: A Python regular expression, for example "from jinja2 import".
        """
        try:
            hits = ws.search(pattern)
        except WorkspaceError as exc:
            return f"Error: {exc}"
        return "\n".join(hits) if hits else "No matches."

    @tool
    def replace_in_file(path: str, old_text: str, new_text: str) -> str:
        """Replace one exact, unique occurrence of text in a file. Prefer this over write_file for small edits.

        Args:
            path: File path relative to the repository root.
            old_text: Exact existing text, including indentation. It must occur exactly once.
            new_text: Replacement text.
        """
        try:
            ws.replace_in_file(path, old_text, new_text)
        except (WorkspaceError, UnicodeDecodeError) as exc:
            return f"Error: {exc}"
        state.passing_fingerprint = None
        return f"Edited {path}."

    @tool
    def write_file(path: str, content: str) -> str:
        """Create or overwrite a text file with the full content provided.

        Args:
            path: File path relative to the repository root.
            content: The complete new file content.
        """
        try:
            ws.write_file(path, content)
        except WorkspaceError as exc:
            return f"Error: {exc}"
        state.passing_fingerprint = None
        return f"Wrote {path}."

    @tool
    def revert_file(path: str) -> str:
        """Restore a file to its original content (or delete it if you created it).

        Args:
            path: File path relative to the repository root.
        """
        try:
            ws.revert_file(path)
        except WorkspaceError as exc:
            return f"Error: {exc}"
        for fix in state.packages.values():
            if fix.status == "UPDATED" and adapter.current_version(ws, task.app_dir, fix.package) == fix.from_version:
                fix.status, fix.to_version = "PENDING", None
        state.passing_fingerprint = None
        return f"Reverted {path}."

    @tool
    def run_build_and_tests() -> str:
        """Install dependencies, regenerate lockfiles, and run the unit tests in an isolated build environment."""
        if not state.updated():
            return "Upgrade at least one package with update_dependency_version first."
        if state.attempts >= max_build_attempts:
            return f"Build attempt budget ({max_build_attempts}) is exhausted. Call submit_fix if the last build passed, otherwise stop_remediation."
        state.attempts += 1
        result = runner.run(ws, adapter.name, task.app_dir, adapter.lockfiles, task.run_id, state.attempts)
        state.last_build = result
        remaining = max_build_attempts - state.attempts
        if result.passed:
            state.passing_fingerprint = ws.fingerprint()
            extra = f" Regenerated: {', '.join(result.lockfiles_updated)}." if result.lockfiles_updated else ""
            return f"BUILD PASSED on attempt {state.attempts} in {result.duration_seconds}s.{extra} Call submit_fix when every package is updated or skipped."
        state.passing_fingerprint = None
        return (
            f"BUILD {result.status} on attempt {state.attempts} ({remaining} attempts left).\n"
            "Diagnose the root cause from the log, fix the code, and run the build again.\n"
            f"{result.log_summary}"
        )

    @tool
    def submit_fix(change_summary: str) -> str:
        """Finish the run and publish the verified patch. Only allowed when the latest build passed with no later edits.

        Args:
            change_summary: Markdown bullet list explaining each code change and why the new version required it.
        """
        pending = [p.package for p in state.packages.values() if p.status == "PENDING"]
        if pending:
            return f"These packages are neither updated nor skipped: {', '.join(pending)}. Update or skip each one."
        if not state.updated():
            return "No package was upgraded. Call stop_remediation instead."
        if not state.passing_fingerprint:
            return "The latest build did not pass, or files changed after it. Run run_build_and_tests until it passes."
        if ws.fingerprint() != state.passing_fingerprint:
            return "Files changed after the last passing build. Run run_build_and_tests again."
        state.change_summary = change_summary.strip()[:4000]
        skipped = [p for p in state.packages.values() if p.status in ("SKIPPED", "NO_SAFE_VERSION")]
        state.status = "PARTIAL_FIX" if skipped else "FIXED"
        for fix in state.updated():
            memory.remember(
                session_id=task.run_id,
                task=f"Upgrade {adapter.name} package {fix.package} from {fix.from_version} to {fix.to_version} to fix {', '.join(fix.advisories) or 'a vulnerability'}.",
                outcome=f"The build passed after {state.attempts} attempt(s). Code changes that were required:\n{state.change_summary[:3000]}",
            )
        return f"Fix submitted with status {state.status}. Reply with a one-paragraph summary."

    @tool
    def stop_remediation(reason: str) -> str:
        """Stop without a patch, for example when there are no vulnerabilities, no safe version exists, or the fix needs a human.

        Args:
            reason: A short explanation for the developer who will pick this up.
        """
        if state.status == "IN_PROGRESS":
            if state.scanned and not state.packages:
                state.status = "NO_VULNERABILITIES"
            elif state.attempts >= max_build_attempts:
                state.status = "BUDGET_EXHAUSTED"
            else:
                state.status = "NOT_FIXED"
            state.reason = reason.strip()[:1000]
        return "Recorded. Reply with a one-paragraph summary."

    return [
        scan_dependencies,
        recall_similar_fixes,
        choose_target_version,
        update_dependency_version,
        skip_package,
        list_files,
        read_file,
        search_code,
        replace_in_file,
        write_file,
        revert_file,
        run_build_and_tests,
        submit_fix,
        stop_remediation,
    ]
