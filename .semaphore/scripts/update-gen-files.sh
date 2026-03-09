#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Regenerates version mappings and generated files, then opens a PR
# if anything changed. The PR is automatically approved and merged.
#
# Required environment:
#   GITHUB_TOKEN - Marvin bot's GitHub token (from marvin-github-token secret).
#                  Used to push the branch, create the PR, and enable auto-merge.

set -euo pipefail

BRANCH_NAME="auto-gen-files-update"
BASE_BRANCH="master"
REPO="tigera/operator"

# Configure git as marvin bot for committing.
git config user.name "marvin-tigera"
git config user.email "marvin-tigera@users.noreply.github.com"

# Ensure we're on the base branch and up to date.
git checkout "${BASE_BRANCH}"
git pull origin "${BASE_BRANCH}"

# Run the generation targets.
make gen-versions gen-files

# Check if anything changed.
if git diff --quiet && [ -z "$(git status --porcelain)" ]; then
    echo "No changes detected after regeneration. Nothing to do."
    exit 0
fi

echo "Changes detected:"
git diff --stat
git status --porcelain

# Create or reset the branch.
git checkout -B "${BRANCH_NAME}"
git add -A
git commit -m "chore: update generated files

Run 'make gen-versions gen-files' to pick up upstream changes.

Automated by Semaphore CI scheduled pipeline."

# Force-push the branch (we own this branch, it's always recreated from master).
git push --force origin "${BRANCH_NAME}"

# Close any existing PR from this branch so we don't accumulate stale ones.
existing_pr=$(gh pr list --head "${BRANCH_NAME}" --base "${BASE_BRANCH}" --repo "${REPO}" --json number --jq '.[0].number // empty')
if [ -n "${existing_pr}" ]; then
    echo "Closing existing PR #${existing_pr}"
    gh pr close "${existing_pr}" --repo "${REPO}" --delete-branch=false
fi

# Create the PR.
pr_url=$(gh pr create \
    --repo "${REPO}" \
    --base "${BASE_BRANCH}" \
    --head "${BRANCH_NAME}" \
    --title "chore: update generated files" \
    --body "$(cat <<'EOF'
## Summary
- Automated regeneration of version mappings and generated files via `make gen-versions gen-files`.
- Triggered by scheduled CI pipeline.

## Test plan
- CI will validate that the generated files are consistent (`dirty-check`).
- No functional changes; only regenerated outputs.
EOF
)")

echo "Created PR: ${pr_url}"

# Enable auto-merge. Once required status checks pass, GitHub will merge.
# Note: The PR is authored by marvin-tigera. If branch protection requires
# approvals, either:
#   1. Add marvin-tigera to a bypass list in branch protection rules, or
#   2. Have a second bot/human approve (can be added as a follow-up).
gh pr merge "${pr_url}" --repo "${REPO}" --squash --auto

echo "Auto-merge enabled: ${pr_url}"
