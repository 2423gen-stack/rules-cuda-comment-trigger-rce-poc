# [CRITICAL] Missing Authorization Check on Comment-Triggered Build Allows Unauthenticated Arbitrary Code Execution in `bazel-contrib/rules_cuda`

## Summary

`bazel-contrib/rules_cuda`'s `.github/workflows/integration-tests.yaml` runs
a Bazel build of the PR's own code whenever anyone comments `/test` on a
pull request:

```yaml
on:
  workflow_dispatch:
  issue_comment:
    types: [created]

jobs:
  pre-test-comment:
    if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')
    ...
  test-comment:
    needs: [pre-test-comment]
    steps:
      - uses: xt0rted/pull-request-comment-branch@v2
        id: comment-branch
      - uses: actions/checkout@v6
        with:
          ref: ${{ steps.comment-branch.outputs.head_ref }}
      ...
      - run: cd examples && bazelisk build --verbose_failures --cuda_archs='compute_80,sm_80' @rules_cuda_examples//nccl:perf_binaries
```

Unlike every other comment-triggered automation examined in this research
effort (`flutter/samples`, `google/android-cuttlefish`,
`GoogleCloudPlatform/vertex-ai-creative-studio`,
`bazelbuild/bazel-central-registry`'s `handle_comment.yml`), which all
gate on `github.event.comment.author_association` being
`OWNER`/`MEMBER`/`COLLABORATOR`, **this workflow has no
author_association check anywhere** (confirmed via `grep` — zero matches
for `author_association` or `permissions` in the entire 165-line file).
`issue_comment` events, like `pull_request_target`, always run in the
base repository's context/permission scope, even when the comment is on a
fork PR — so this is not merely "the build runs," it runs with whatever
secrets and token scope this workflow is granted.

**Any GitHub account — including the PR author themselves, with zero
review, zero collaborator status, and zero prior relationship to the
repository — can comment `/test` on their own fork PR and cause
`bazelisk build` to execute arbitrary build actions (`genrule` commands,
custom rule implementations, etc.) defined in that PR's own
`examples/` tree, on a GitHub-hosted runner, in the base repository's
workflow context.**

I verified, using the real, unmodified `bazelisk`/Bazel toolchain, that a
malicious `genrule` placed in a local stand-in for such a fork PR's
`examples/BUILD.bazel` does execute its `cmd=` shell script as part of
`bazel build` resolving that target — reproduced on 2 independent runs.

## Vulnerability Details

### No authorization gate on the comment trigger

The entire authorization logic for this workflow is:

```yaml
pre-test-comment:
  if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')
```

This checks only that (a) the comment is on a PR, and (b) the comment
body contains the literal string `/test`. There is no check on who
posted the comment. The workflow has no top-level `permissions:` block
either, so the `GITHUB_TOKEN` scope granted to this run is whatever the
repository/organization's default workflow permissions are configured to
— information I could not verify externally with a read-only API token,
but which is a separate question from the core vulnerability: regardless
of `GITHUB_TOKEN`'s specific scope, this workflow already grants full
arbitrary code execution on a GitHub-hosted runner to any commenter.

### The build step executes attacker-controlled code

```yaml
- name: Get PR branch
  uses: xt0rted/pull-request-comment-branch@v2
  id: comment-branch
- name: Checkout PR branch
  uses: actions/checkout@v6
  with:
    ref: ${{ steps.comment-branch.outputs.head_ref }}
...
- run: cd examples && bazelisk build --verbose_failures --cuda_archs='compute_80,sm_80' @rules_cuda_examples//nccl:perf_binaries
```

`xt0rted/pull-request-comment-branch@v2` resolves the PR associated with
the triggering comment and outputs its head ref (for a fork PR, this
resolves via GitHub's special `refs/pull/<N>/head` ref, which exists on
the base repository for any open PR regardless of fork origin).
`actions/checkout@v6` then checks out that ref — 100% attacker-authored
content for a fork PR. `bazelisk build` then resolves the
`@rules_cuda_examples//nccl:perf_binaries` target, executing whatever
build actions (`genrule` commands, custom Starlark rule implementations,
`repository_rule`s, etc.) are reachable from that target as defined in
the checked-out `examples/` tree.

## Impact

An attacker needs only a GitHub account and the ability to open a pull
request and comment on it (both zero-privilege actions on a public
repository):

1. Open a PR from a fork containing a malicious `examples/BUILD.bazel`
   (or a malicious dependency in `examples/MODULE.bazel`/`WORKSPACE`, or
   a malicious `repository_rule` invoked during dependency resolution).
2. Comment `/test` on that PR.
3. `test-comment` runs with no review, no approval, and no
   collaborator-status requirement, executing the attacker's build
   actions on a GitHub-hosted runner in the base repository's workflow
   context.

This grants the attacker arbitrary code execution as a normal, expected
consequence of the workflow's own design — not a bypass of a check that
exists elsewhere, since no such check exists. Concrete consequences
include:

- **Compute abuse**: cryptomining, network relaying, or other abuse of
  GitHub-hosted runner compute, launched from GitHub's own IP space.
- **Cache poisoning**: the job mounts `~/.cache/bazel` via
  `actions/cache` with a coarse, non-PR-scoped key
  (`${{ matrix.cases.toolchain }}-${{ matrix.cases.toolchain-version }}`).
  A malicious build action could write poisoned artifacts into this
  shared cache, which may be restored and consumed by later, legitimate
  CI runs sharing the same cache key.
- **Credential/token exposure**: whatever `GITHUB_TOKEN` scope this
  workflow run is granted (unknown to me externally, but present
  regardless) is reachable to any process running as part of this job,
  including via the GitHub Actions runtime token metadata endpoint
  (typically reachable over local network from within a job, independent
  of whether Bazel's own sandbox strips inherited shell environment
  variables — see note below), and any other secrets referenced
  elsewhere in the same job.

### Note on Bazel's sandbox and environment variables (reported honestly)

My local PoC confirmed unambiguous **arbitrary command execution** via a
malicious `genrule`. I also tested whether a bare shell environment
variable is inherited into that `genrule`'s sandboxed execution, and
found that **it is not** — Bazel's default genrule sandbox clears the
process environment (`exec env - PATH=...`) before running the command,
so a naive `echo $SOME_TOKEN` inside a `genrule.cmd` does not see values
present in the outer CI job's environment. This means credential
exfiltration via the most naive possible payload is not as trivial here
as in non-Bazel findings. However, this does **not** reduce the severity
of the core finding: arbitrary code execution on the runner is itself
Critical-severity regardless of how straightforward secret exfiltration
specifically is, and Bazel's sandboxing does not restrict outbound
network access by default, leaving network-based exfiltration (e.g., a
direct HTTP call to the Actions runtime token endpoint, or to an
attacker-controlled server) as a plausible channel that I did not
exercise in this PoC to keep it non-destructive and free of any real
network call.

## Steps to Reproduce

I verified this against the **real, unmodified `bazelisk`/Bazel
toolchain** (installed via the standard `go install
github.com/bazelbuild/bazelisk@latest`, a normal public tool unrelated to
`rules_cuda`), using a local directory standing in for what a fork PR's
checked-out `examples/` tree would contain. Provided in this directory:

- `run_poc.sh` — the PoC script.
- `attacker_fork_pr/` — a minimal Bazel workspace (`MODULE.bazel` +
  `examples/BUILD.bazel`) modeling the attacker-controlled content a fork
  PR would supply.
- `bazel_build_output_run1.log`, `bazel_build_output_run2.log` — two
  independent, full verified transcripts.

Run (requires `bazelisk`/`bazel` on `PATH`; no network access to any real
CI/CD system, no credentials required):
```bash
./run_poc.sh
```

Observed output (verified, reproduced across two independent runs):
```
INFO: From Executing genrule //examples:perf_binaries:
=== ATTACKER-CONTROLLED BUILD ACTION EXECUTING ON THE CI RUNNER ===
whoami: gen, pwd: /home/gen/.cache/bazel/_bazel_gen/.../execroot/_main
Attempting to read MOCK_GITHUB_TOKEN from process environment:
MOCK_GITHUB_TOKEN=<not inherited into bazel genrule sandbox by default>
INFO: Build completed successfully, ...
```

The attacker-controlled genrule command executed as an ordinary
consequence of `bazel build` resolving the target — exactly the
mechanism the real `integration-tests.yaml` would trigger against a
fork PR's own content, reachable by any commenter with no
authorization check at all.

## Recommended Fix

1. **Add an `author_association` gate**, matching every other
   comment-triggered workflow in the Bazel ecosystem examined in this
   research (e.g., `bazel-central-registry`'s `handle_comment.yml`,
   `rules_python`'s `on_comment.yaml`):
   ```yaml
   if: >
     github.event.issue.pull_request &&
     contains(github.event.comment.body, '/test') &&
     contains(fromJson('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association)
   ```
2. **Add an explicit top-level `permissions:` block** scoped to the
   minimum required (this workflow currently has none, leaving its
   actual `GITHUB_TOKEN` scope implicit and dependent on
   repository/organization defaults).
3. **Scope the Bazel cache key to the PR/commit**, not just
   toolchain/version, to prevent cross-PR cache poisoning even after the
   authorization gate is added (defense in depth, since maintainers can
   still trigger builds of externally-authored code by design once a PR
   is legitimately opened for review).
4. Consider whether `test-comment` needs `secrets`/a real `GITHUB_TOKEN`
   at all for a build-only integration test — if the job's only output
   is a pass/fail status, a token scoped to `statuses: write` only
   (rather than whatever the repository default grants) would limit
   blast radius even after adding the author_association gate.

## Supporting Files

- PoC script, workspace, and full verified transcripts: this directory
  (`run_poc.sh`, `attacker_fork_pr/`, `bazel_build_output_run1.log`,
  `bazel_build_output_run2.log`)
- Target workflow source: `bazel-contrib/rules_cuda`,
  `.github/workflows/integration-tests.yaml` (fetched via GitHub
  Contents API, default branch `main`, file SHA
  `a4ffa495f01342b649fc5b0ee89d8b9634763be9`, 2026-08-12)
