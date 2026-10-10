#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Generic script for any CI system or a developer laptop (Jenkins, Bitbucket Pipelines, AWS CodePipeline, ...).
#
# Runs the agent on the current repository and, when a verified fix is produced, commits it on a
# new local branch. Pushing and opening the review is left to your tool of choice, for example:
#   git push origin HEAD && glab mr create --fill --description "$(cat remediation-output/report.md)"
#   git push origin HEAD && gh pr create --body-file remediation-output/report.md
#
# Usage: ci-templates/remediate-branch.sh [extra remediate options, for example --package jinja2]
set -euo pipefail

OUT="${REMEDIATION_OUT:-remediation-output}"
status=0
remediate --out "$OUT" "$@" || status=$?

if [ ! -f "$OUT/fix.patch" ]; then
  echo "No patch produced (exit $status)."
  [ -f "$OUT/report.md" ] && cat "$OUT/report.md"
  exit "$status"
fi

BRANCH="remediation/deps-$(date +%Y%m%d%H%M%S)"
git checkout -b "$BRANCH"
git apply --index "$OUT/fix.patch"
git -c user.name="Dependency Remediation Bot" -c user.email="noreply@example.com" \
  commit -m "fix(deps): remediate vulnerable dependencies"
echo "Committed the fix on branch $BRANCH. Review description: $OUT/report.md"
