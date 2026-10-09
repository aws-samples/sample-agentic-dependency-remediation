# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Guards in the agent tools, tested without network access or a model."""

from types import SimpleNamespace

import pytest

from remediation_agent import advisories
from remediation_agent.build_runner import BuildResult, summarize_log
from remediation_agent.ecosystems import get_adapter
from remediation_agent.memory_store import FixMemory
from remediation_agent.tools import RemediationTask, RunState, ToolBudget, build_tools
from remediation_agent.workspace import Workspace


class FakeRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def run(self, *args, **kwargs):
        self.calls += 1
        passed = self.results.pop(0)
        return BuildResult(passed, "SUCCEEDED" if passed else "FAILED", "E   ImportError: cannot import name 'Markup'", "b-1", 1, [])


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "requirements.txt").write_text("Jinja2==2.11.3\nrequests==2.32.3\n")
    (root / "app" / "render.py").write_text("from jinja2 import Markup\n")
    ws = Workspace(root)
    ws.snapshot()

    # No network: jinja2 < 3.1.6 is vulnerable; requests is clean.
    def fake_query(adapter, pkg, version):
        if pkg == "jinja2" and version != "3.1.6":
            return [advisories.Advisory("GHSA-x", [], "bad", ["3.1.6"])]
        return []

    monkeypatch.setattr(advisories, "query", fake_query)
    adapter = get_adapter("python")
    monkeypatch.setattr(adapter, "registry_versions", lambda pkg: ["2.11.3", "3.0.0", "3.1.6"])

    def make(results, attempts=2, payload=None):
        task = RemediationTask.from_payload(payload or {"project": "demo"}, "run-1")
        state = RunState()
        runner = FakeRunner(results)
        tools = build_tools(task=task, ws=ws, adapter=adapter, state=state, runner=runner, memory=FixMemory(None, "us-east-1"),
                            max_build_attempts=attempts)
        return {t.tool_name: t for t in tools}, state, runner

    return ws, make


def test_scan_finds_only_vulnerable_packages(setup):
    _, make = setup
    tools, state, _ = make([])
    out = tools["scan_dependencies"]()
    assert "jinja2 2.11.3" in out and "requests" not in out.split("vulnerable:")[1]
    assert list(state.packages) == ["jinja2"]


def test_scan_respects_ignore(setup):
    _, make = setup
    tools, state, _ = make([], payload={"project": "demo", "ignore": ["Jinja2"]})
    assert "No known vulnerabilities" in tools["scan_dependencies"]()
    tools["stop_remediation"](reason="nothing to do")
    assert state.status == "NO_VULNERABILITIES"


def test_choose_target_jumps_to_fixed_version(setup):
    _, make = setup
    tools, state, _ = make([])
    tools["scan_dependencies"]()
    assert "3.1.6" in tools["choose_target_version"](package="Jinja2")


def test_rejects_vulnerable_or_unscanned_target(setup):
    _, make = setup
    tools, state, _ = make([])
    assert "not in the list" in tools["update_dependency_version"](package="jinja2", version="3.1.6")
    tools["scan_dependencies"]()
    assert "still has known vulnerabilities" in tools["update_dependency_version"](package="jinja2", version="3.0.0")
    assert not state.updated()


def test_build_requires_dependency_update(setup):
    _, make = setup
    tools, _, runner = make([True])
    assert "Upgrade at least one package" in tools["run_build_and_tests"]()
    assert runner.calls == 0


def test_submit_requires_passing_build_on_current_tree(setup):
    ws, make = setup
    tools, state, _ = make([False, True])
    tools["scan_dependencies"]()
    tools["update_dependency_version"](package="jinja2", version="3.1.6")
    assert "FAILED" in tools["run_build_and_tests"]()
    assert "did not pass" in tools["submit_fix"](change_summary="s")
    tools["replace_in_file"](path="app/render.py", old_text="from jinja2 import Markup", new_text="from markupsafe import Markup")
    assert "PASSED" in tools["run_build_and_tests"]()
    tools["write_file"](path="app/extra.py", content="x = 1\n")
    assert "did not pass" in tools["submit_fix"](change_summary="s")
    tools["revert_file"](path="app/extra.py")
    assert not (ws.root / "app/extra.py").exists()
    # Any edit, including a revert, requires a new passing build before submitting.
    assert "did not pass" in tools["submit_fix"](change_summary="s")


def test_full_fix_produces_applicable_patch(setup):
    ws, make = setup
    tools, state, _ = make([True])
    tools["scan_dependencies"]()
    tools["update_dependency_version"](package="jinja2", version="3.1.6")
    tools["replace_in_file"](path="app/render.py", old_text="from jinja2 import Markup", new_text="from markupsafe import Markup")
    tools["run_build_and_tests"]()
    assert "FIXED" in tools["submit_fix"](change_summary="- use markupsafe")
    patch = ws.unified_patch()
    assert "diff --git a/requirements.txt b/requirements.txt" in patch
    assert "-Jinja2==2.11.3" in patch and "+Jinja2==3.1.6" in patch
    assert "+from markupsafe import Markup" in patch


def test_skip_requires_revert(setup):
    _, make = setup
    tools, state, _ = make([])
    tools["scan_dependencies"]()
    tools["update_dependency_version"](package="jinja2", version="3.1.6")
    assert "Revert that change first" in tools["skip_package"](package="jinja2", reason="needs redesign")
    tools["revert_file"](path="requirements.txt")
    assert "reported as not fixed" in tools["skip_package"](package="jinja2", reason="needs redesign")
    assert "No package was upgraded" in tools["submit_fix"](change_summary="s")


def test_build_attempt_budget(setup):
    _, make = setup
    tools, state, runner = make([False, False, False], attempts=2)
    tools["scan_dependencies"]()
    tools["update_dependency_version"](package="jinja2", version="3.1.6")
    tools["run_build_and_tests"]()
    tools["run_build_and_tests"]()
    assert "budget" in tools["run_build_and_tests"]()
    assert runner.calls == 2
    tools["stop_remediation"](reason="needs a human")
    assert state.status == "BUDGET_EXHAUSTED"


def test_tool_call_budget_hook():
    state = RunState()
    hook = ToolBudget(state, max_calls=2)
    events = [SimpleNamespace(tool_use={"name": "read_file"}, cancel_tool=False) for _ in range(3)]
    for event in events:
        hook._before_tool(event)
    assert events[0].cancel_tool is False and events[1].cancel_tool is False
    assert "budget exhausted" in events[2].cancel_tool
    stop = SimpleNamespace(tool_use={"name": "stop_remediation"}, cancel_tool=False)
    hook._before_tool(stop)
    assert stop.cancel_tool is False


def test_payload_validation():
    with pytest.raises(ValueError, match=r"\.\."):
        RemediationTask.from_payload({"app_dir": "../etc"}, "r")
    with pytest.raises(ValueError, match="project"):
        RemediationTask.from_payload({"project": "a/b"}, "r")
    with pytest.raises(ValueError, match="Invalid package"):
        RemediationTask.from_payload({"packages": ["ok", "bad name;rm"]}, "r")
    task = RemediationTask.from_payload({"packages": "a, b", "app_dir": "./"}, "r")
    assert task.packages == ["a", "b"]


def test_log_summary_keeps_errors_and_tail():
    log = "\n".join([f"line {i}" for i in range(500)] + ["E   ImportError: boom"] + [f"tail {i}" for i in range(10)])
    summary = summarize_log(log, tail_lines=5)
    assert "ImportError: boom" in summary
    assert "tail 9" in summary
    assert "line 3\n" not in summary


def test_payload_with_unset_options_from_the_trigger(tmp_path):
    """Regression: the deployed trigger sends unset options as None (first live run failed with TypeError)."""
    from remediation_agent.runner import apply_repo_config

    root = tmp_path / "repo"
    root.mkdir()
    ws = Workspace(root)
    ws.snapshot()
    options = {k: None for k in ("ecosystem", "app_dir", "packages", "ignore", "vulnerability_ids")}
    options["project"] = "python-jinja2"
    task = RemediationTask.from_payload(apply_repo_config(options, ws), "run-1")
    assert task.app_dir == ""  # not the string "None"
    assert task.packages == [] and task.ignore == [] and task.vulnerability_ids == []
    assert task.ecosystem is None and task.project == "python-jinja2"

    direct = RemediationTask.from_payload(options, "run-2")  # without the config merge as well
    assert direct.app_dir == "" and direct.vulnerability_ids == []
