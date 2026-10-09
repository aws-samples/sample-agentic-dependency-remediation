# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.


## Reporting Bugs/Feature Requests

We welcome you to use the project's issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

Do not include source code, credentials, or `result.json` / `report.md` files from private projects in an issue.


## Contributing via Pull Requests
Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Ensure local tests pass (see *Development setup* below).
4. Commit to your fork using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Development setup

```bash
uv sync                    # install the pinned dependencies
uv run pytest              # unit, security, and infrastructure tests (no AWS access needed)
uv run cdk synth           # check that the stack still synthesizes

# Security scan (AWS Automated Security Helper). Must pass with no actionable findings.
uvx --from git+https://github.com/awslabs/automated-security-helper.git@v3.5.8 ash --mode container
```

If ASH reports a finding, fix it. Suppress it in `.ash/.ash.yaml` only with a written reason, and add or update the
matching item in [SECURITY.md](SECURITY.md) for infrastructure findings. Refresh the reports in `docs/security/` when
you change the code.

When you change the agent:

* Keep every guard in code, not in the prompt. Tools validate their input and enforce budgets; the model only decides what to try.
* Add a regression test in `tests/` for every bug fix and every new guard.
* To add an ecosystem, implement `EcosystemAdapter` in `agent/remediation_agent/ecosystems/`, register it in
  `ecosystems/__init__.py`, and add its commands to `BUILD_SCRIPT` in `build_runner.py`.
* Pin new dependencies to exact versions in `pyproject.toml`, `agent/requirements.txt`, or
  `functions/trigger/requirements.txt`, and run `uv lock`.
* Add the SPDX header to new source files:
  ```
  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
  # SPDX-License-Identifier: MIT-0
  ```


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the
default issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted'
issues is a great place to start.


## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.


## Security issue notifications
If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a
public issue. See [SECURITY.md](SECURITY.md) for details.


## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.
