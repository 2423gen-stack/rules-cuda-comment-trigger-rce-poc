# Comment-Triggered RCE PoC — `bazel-contrib/rules_cuda`

This repository contains a responsible, local-only PoC accompanying a
vulnerability report submitted to Google's Bug Hunters program (OSS VRP).

**Full report:** [`TRIAGE_REPORT_COMMENT_TRIGGER_RCE.md`](./TRIAGE_REPORT_COMMENT_TRIGGER_RCE.md)

## Summary

`bazel-contrib/rules_cuda`'s `.github/workflows/integration-tests.yaml`
runs `bazelisk build` on a PR's own `examples/` tree whenever **anyone**
comments `/test` on that PR — with **no `author_association` check at
all** (unlike every other comment-triggered automation examined in this
research effort, which all gate on `OWNER`/`MEMBER`/`COLLABORATOR`).
`issue_comment` events run in the base repository's context even for
fork PRs, so this grants arbitrary code execution on a GitHub-hosted
runner to any GitHub account, with zero review, zero collaborator
status, and zero prior relationship to the repository.

This PoC verifies, using the **real, unmodified `bazelisk`/Bazel
toolchain**, that a malicious `genrule` placed in a local stand-in for
such a fork PR's `examples/BUILD.bazel` executes its `cmd=` shell script
as an ordinary consequence of `bazel build` resolving that target —
reproduced on 2 independent runs.

**Honesty note**: Bazel's default genrule sandbox clears the process
environment before running commands, so a naive `echo $TOKEN` inside a
`genrule` does not see the outer job's environment variables — this is
reported transparently in the full report. The core finding (arbitrary
command execution) stands regardless; Bazel's sandbox does not restrict
outbound network by default, leaving other exfiltration channels
plausible but intentionally untested here to keep this PoC
non-destructive.

This does **not** touch `rules_cuda`, GitHub Actions, the real
`xt0rted/pull-request-comment-branch`/`actions/checkout` actions, or any
real credential. It uses only the real, public `bazelisk`/Bazel
toolchain (installed via `go install
github.com/bazelbuild/bazelisk@latest`) against a local, self-contained
Bazel workspace standing in for attacker-controlled fork PR content.

## Files

- `run_poc.sh` — the PoC script (requires `bazelisk`/`bazel` on `PATH`)
- `attacker_fork_pr/` — minimal Bazel workspace modeling the
  attacker-controlled content a fork PR would supply
- `bazel_build_output_run1.log`, `bazel_build_output_run2.log` — full
  transcripts of two independent verified runs
- `TRIAGE_REPORT_COMMENT_TRIGGER_RCE.md` — the full vulnerability report

## Running it

```bash
./run_poc.sh
```

Expected output includes the attacker-controlled genrule's marker line
appearing in the real Bazel build log:

```
INFO: From Executing genrule //examples:perf_binaries:
=== ATTACKER-CONTROLLED BUILD ACTION EXECUTING ON THE CI RUNNER ===
...
INFO: Build completed successfully, ...
```

## Responsible disclosure

This vulnerability was reported to Google's Bug Hunters program
(OSS VRP) for `bazel-contrib/rules_cuda`. This repository exists solely
to provide a reproducible, verifiable PoC for that report. No real
`rules_cuda` infrastructure, credentials, or data were accessed or
affected in the creation of this PoC.
