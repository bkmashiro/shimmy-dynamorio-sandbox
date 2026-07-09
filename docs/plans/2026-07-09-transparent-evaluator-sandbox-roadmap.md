# Transparent Evaluator Sandbox Roadmap

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Turn the DynamoRIO prototype into a transparent evaluator sandbox that existing evaluator systems can enable with one environment variable or config flag, without adopting a new RPC protocol or judge schema.

**Architecture:** The caller keeps its current evaluator contract: argv, env, cwd, stdin, stdout, stderr, files, and exit code. The integration layer auto-prepends `drrun -c syscall_filter.so --` when enabled; DynamoRIO is only an attach/interpose layer for resource guards, filesystem/network policy, and side-channel audit. Docker/Lambda/CodeBuild are carriers only; core policy remains in the DR client.

**Tech Stack:** C DynamoRIO client (`syscall_filter.c`), Go transparent wrapper (`cmd/dynamorio-sandbox`), Makefile smoke tests, Docker/CodeBuild x86_64 runtime gate, optional Lambda carrier.

---

## Non-goals

- No OJ RPC runner protocol.
- No submission/testcase/scoring JSON schema.
- No queue, contest mode, rejudge service, or problem data management.
- No evaluator daemon.
- No replacement of the caller's stdout/stderr/exit-code semantics.

The product promise is narrower: **if an evaluator already works, setting one env/config should run it under DR with the same observable contract, plus limits and audit.**

## Current baseline

Already available:

- DR-only path policy and private temp/cache remapping.
- DR-only network/exec/PROT_EXEC/file-write policy switches.
- DR allocation budget for `mmap`/`mremap`/`brk` growth.
- DR process-count guard for `fork`/new-process `clone`.
- FD shadow table for path-derived write blocking.
- IPv4 network allow/block policy for `connect`/`bind`/`sendto`.
- Semantic JSONL audit events for open/fd/write/socket/connect-style operations.
- CodeBuild native x86_64 smoke as authoritative runtime gate.

Known constraints:

- Local Apple Silicon Docker amd64 emulation can crash DynamoRIO with `SIGBUS`; do not use it as a runtime correctness gate.
- Current Go wrapper is still Docker-shaped; transparent auto-attach for arbitrary evaluator launchers is not yet first-class.
- Current timeout is external `timeout`/Go context; DR-side/resource-side timeout and process-tree cleanup need hardening.

## Integration model

Target user-facing contract:

```bash
# Existing evaluator invocation remains unchanged at the application level.
EVALUATOR_SANDBOX=dr evaluator arg1 arg2 < input.txt > output.txt
```

or config-equivalent:

```yaml
evaluator:
  sandbox: dynamorio
  sandbox_config: /etc/evaluator-sandbox/policy.yaml
```

Under the hood, launch is rewritten to:

```bash
drrun -c /path/to/syscall_filter.so -- evaluator arg1 arg2
```

Required transparency rules:

- Preserve argv exactly.
- Preserve cwd unless explicitly configured.
- Preserve stdin/stdout/stderr streams.
- Preserve evaluator exit code when it exits normally.
- On sandbox kill/timeout/OLE/MLE-style guard, return deterministic wrapper exit codes and write details to side-channel metrics/audit.
- Audit/metrics must never corrupt the evaluator's stdout protocol.

---

## Phase 0 — Roadmap and terminology cleanup

**Objective:** Lock the project direction as transparent evaluator sandbox, not OJ runner.

**Files:**
- Modify: `README.md`
- Create/modify: `docs/plans/2026-07-09-transparent-evaluator-sandbox-roadmap.md`

**Tasks:**

1. Add a short README section named `Transparent evaluator mode`.
2. State that DR is an attach/interpose layer, not an RPC or judge protocol.
3. Document non-goals in the README.
4. Add this roadmap and link it from README.
5. Run:
   ```bash
   git diff --check
   ```
6. Commit:
   ```bash
   git add README.md docs/plans/2026-07-09-transparent-evaluator-sandbox-roadmap.md
   git commit -S -m "docs: add transparent evaluator sandbox roadmap"
   ```

**Done when:** README and roadmap both make the transparent/no-RPC boundary unambiguous.

---

## Phase 1 — Transparent launcher contract

**Status:** Initial Docker-carrier slice implemented. The wrapper now accepts `dynamorio-sandbox [flags] -- evaluator args...`, loads env-style policy files, passes explicit evaluator env values, bind-mounts/uses the evaluator workdir, stays quiet by default, and has CodeBuild smokes for stdio, exit-code, cwd, and env transparency.

**Objective:** Make enabling DR a one-env/config change around an existing evaluator command.

**Files:**
- Modify: `cmd/dynamorio-sandbox/main.go`
- Add tests/smokes in `Makefile`
- Possibly add helper script: `scripts/dr-evaluator-launch`

**Acceptance criteria:**

- A command can be launched as `dynamorio-sandbox -- evaluator args...` without `--exec`/`--args` string splitting.
- stdin is passed through byte-for-byte.
- stdout is passed through byte-for-byte.
- stderr is passed through without artificial prefixes by default.
- Normal exit code is preserved.
- Audit and metrics go to explicit side-channel files when enabled.

**Tasks:**

1. Add a failing smoke that runs a tiny evaluator through the wrapper using positional command syntax:
   ```bash
   printf input | dynamorio-sandbox -- /bin/sh -c 'cat; echo err >&2; exit 7'
   ```
   Expected: stdout `input`, stderr contains `err`, exit code `7`.

2. Change the Go CLI parsing to support:
   ```bash
   dynamorio-sandbox [flags] -- <program> [args...]
   ```
   Keep `--exec` for backward compatibility, but treat positional command as preferred.

3. Remove any default stderr prefixing or duplicate writers. The wrapper may print its own status only when `--verbose` is set or to a separate status file.

4. Add env/config auto-enable shape:
   ```bash
   EVALUATOR_SANDBOX=dr
   EVALUATOR_SANDBOX_CONFIG=/path/to/policy.env
   ```
   The wrapper should be able to load policy env files without changing evaluator arguments.

5. Add smoke targets:
   - `smoke-transparent-stdio`
   - `smoke-transparent-exit-code`
   - `smoke-transparent-cwd-env`

6. Verify:
   ```bash
   go build ./cmd/dynamorio-sandbox
   make docker-build
   make smoke-transparent-stdio
   make smoke-transparent-exit-code
   make smoke-transparent-cwd-env
   ./codebuild-smoke/run_codebuild_smoke.sh
   ```

**Done when:** an existing evaluator can be wrapped without changing its protocol or command shape beyond launcher injection.

---

## Phase 2 — Resource guard closure

**Objective:** Finish the sandbox/runner core that matters for transparent evaluator execution.

### 2.1 Wall timeout and process-tree cleanup

**Files:**
- Modify: `cmd/dynamorio-sandbox/main.go`
- Modify: `Makefile`
- Optional: `syscall_filter.c` for cooperative timeout audit

**Tasks:**

1. Add a smoke evaluator that sleeps longer than the limit and spawns a child.
2. Verify current behavior leaves no orphan process in the carrier.
3. Implement process-group/session kill for local/Docker carrier.
4. Define timeout exit code, probably `124`, matching GNU `timeout`.
5. Write timeout reason to metrics/audit side-channel.
6. CodeBuild gate must prove no leaked process after timeout.

**Done when:** timeout reliably kills the whole evaluator tree and reports a deterministic exit code.

### 2.2 CPU-ish time limit

**Files:**
- Modify: `syscall_filter.c`
- Modify: `cmd/dynamorio-sandbox/main.go`
- Modify: `Makefile`

**Tasks:**

1. Add env: `DR_MAX_CPU_MS`.
2. Add a spin-loop evaluator smoke.
3. Implement periodic user-space checks where feasible:
   - syscall-bound path: check elapsed CPU/wall on pre-syscall.
   - low-syscall tight loops: rely on outer watchdog first; optionally add DR basic-block instrumentation later only if needed.
4. Emit audit event `resource:cpu-timeout`.
5. Keep wall timeout as the correctness fallback.

**Done when:** syscall-active CPU hogs are killed/failed by DR policy, and syscall-inactive hogs are still killed by outer wall watchdog.

### 2.3 Output limit

**Files:**
- Modify: `syscall_filter.c`
- Modify: `test_runtime_controls.c`
- Modify: `Makefile`

**Tasks:**

1. Add envs:
   - `DR_MAX_STDOUT_BYTES`
   - `DR_MAX_STDERR_BYTES`
   - `DR_OUTPUT_LIMIT_ACTION=truncate|fail`
2. Track bytes written to fd `1` and `2` through fd shadow/write hooks.
3. In `fail` mode, return `EFBIG` or terminate with a deterministic reason once over limit.
4. In `truncate` mode, shrink individual write length or no-op after cap.
5. Add smokes for stdout OLE and stderr OLE.

**Done when:** evaluator cannot flood stdout/stderr beyond configured caps without corrupting audit semantics.

### 2.4 Memory limit hardening

**Files:**
- Modify: `syscall_filter.c`
- Modify: `test_runtime_controls.c`
- Modify: `Makefile`

**Tasks:**

1. Expand `DR_MAX_ALLOC_BYTES` tests to cover:
   - `mmap`
   - `mremap` growth
   - `brk` growth
   - `munmap` budget release
2. Add lazy allocation note: this is userspace allocation intent, not RSS/cgroup accounting.
3. Decide if RSS sampling belongs in carrier metrics, not DR enforcement.
4. Add metrics fields:
   - requested alloc bytes
   - current tracked alloc bytes
   - peak tracked alloc bytes

**Done when:** memory guard behavior is predictable and documented as allocation-budget guard, with tests for release/growth paths.

---

## Phase 3 — FD and syscall semantic completeness

**Objective:** Make policy follow descriptors, not just original path syscalls.

**Files:**
- Modify: `syscall_filter.c`
- Modify: `test_runtime_controls.c`
- Modify: `Makefile`

**Tasks:**

1. Add fd shadow inheritance for:
   - `dup`
   - `dup2`
   - `dup3`
   - `fcntl(F_DUPFD)`
   - `fcntl(F_DUPFD_CLOEXEC)`
2. Add fd classification:
   - file
   - pipe
   - socket
   - stdio
   - unknown
3. Track `pipe2` and `socket/socketpair` descriptors.
4. Audit semantic events for:
   - `read`
   - `write`
   - `ioctl`
   - `fstat/newfstatat`
   - `readlink/readlinkat`
   - `rename/unlink/mkdir/rmdir`
5. Add tests that write through duplicated fds and verify policy still applies.

**Done when:** once a path/network policy attaches to an fd, common fd transformations do not bypass it.

---

## Phase 4 — Policy config as a stable interface

**Objective:** Let integrators enable sandboxing with a config file or env file, without learning every DR env var.

**Files:**
- Modify: `cmd/dynamorio-sandbox/main.go`
- Create: `examples/policies/evaluator-observe.env`
- Create: `examples/policies/evaluator-strict.env`
- Create: `examples/policies/evaluator-lambda.env`
- Modify: `README.md`

**Tasks:**

1. Define a minimal env-file format:
   ```env
   DR_SANDBOX_MODE=observe
   DR_REDIRECT_TMP=1
   DR_NETWORK_POLICY=block:*
   DR_MAX_ALLOC_BYTES=256m
   DR_MAX_STDOUT_BYTES=10m
   DR_MAX_STDERR_BYTES=2m
   DR_AUDIT_PATH=/tmp/evaluator-audit.jsonl
   ```
2. Add `--policy-file path.env` to the wrapper.
3. Add config validation: unknown keys warn or fail depending on `--strict-config`.
4. Add example configs for observe, strict, Lambda carrier.
5. Add docs for the one-env integration pattern:
   ```bash
   EVALUATOR_SANDBOX=dr
   EVALUATOR_SANDBOX_POLICY=/etc/evaluator-sandbox/evaluator-observe.env
   ```

**Done when:** a host system can flip one env/config switch and get predictable DR policy without changing evaluator business logic.

---

## Phase 5 — Carrier split: local, Docker, Lambda

**Objective:** Keep policy in DR while making launch carriers interchangeable.

**Files:**
- Modify: `cmd/dynamorio-sandbox/main.go`
- Possibly create: `cmd/dr-evaluator-bootstrap/main.go`
- Create: `lambda/` bootstrap examples only if needed
- Modify: `codebuild-smoke/buildspec.yml`

**Tasks:**

1. Split wrapper into launch modes:
   - `--carrier=local`: direct `drrun` on host/container image.
   - `--carrier=docker`: current Docker carrier for dev/smoke.
   - `--carrier=lambda`: bootstrap conventions, no Docker-only policy assumptions.
2. Ensure every carrier uses the same DR env policy keys.
3. Add `dry-run` for each carrier showing exact command/env.
4. Add CodeBuild smoke for local-in-container carrier, not only Docker-in-Docker.
5. Document which carrier owns what:
   - Carrier: launch, packaging, timeout fallback, collection.
   - DR client: syscall policy, fd policy, resource guards, audit.

**Done when:** changing carrier does not change sandbox policy semantics.

---

## Phase 6 — Compatibility suite for real evaluators

**Objective:** Prove transparent behavior across representative evaluator shapes.

**Files:**
- Create: `tests/evaluators/`
- Modify: `Makefile`
- Modify: `codebuild-smoke/buildspec.yml`

**Evaluator fixtures:**

1. `stdio_echo`: reads stdin, writes stdout/stderr, exits with custom code.
2. `file_scratch`: writes temp/cache files and reads them back.
3. `network_probe`: tries allowed and blocked endpoints.
4. `fork_child`: creates child process and exits cleanly.
5. `output_flood`: triggers output limit.
6. `alloc_hog`: triggers allocation budget.
7. `sleep_forever`: triggers timeout.
8. `dynamic_runtime`: `/bin/bash` or Python if available; JVM later only if needed.

**Tasks:**

1. For every fixture, run baseline without DR.
2. Run with DR observe mode and compare transparent outputs/exit behavior.
3. Run with selected policy limits and assert deterministic guard behavior.
4. Save audit JSONL separately from evaluator output.
5. Add result summary JSON for CI debugging, but do not make it the evaluator protocol.

**Done when:** regressions in transparency or guard semantics fail CodeBuild.

---

## Phase 7 — Documentation and integration examples

**Objective:** Make adoption obvious for another evaluator owner.

**Files:**
- Modify: `README.md`
- Create: `docs/integration.md`
- Create: `docs/policy-reference.md`
- Create: `docs/metrics-and-audit.md`

**Tasks:**

1. Write a 5-minute integration guide:
   - set env/config
   - wrap command
   - collect audit/metrics
   - interpret timeout/output/memory guard exit codes
2. Document every env key and default.
3. Document side-channel files and schemas.
4. Document known non-transparency cases:
   - blocked syscalls return synthetic errno
   - timeout/guard exits are wrapper-defined
   - local Apple Silicon DR runtime is not authoritative
5. Add troubleshooting section for common evaluator runtime issues.

**Done when:** an external user can integrate without reading `syscall_filter.c`.

---

## Recommended execution order

1. Phase 0: terminology/doc reset.
2. Phase 1: transparent launcher contract.
3. Phase 2.1 + 2.3: wall timeout/process cleanup and output limit.
4. Phase 3: fd inheritance completeness.
5. Phase 2.4: memory hardening.
6. Phase 4: policy config file.
7. Phase 5: carrier split and Lambda bootstrap.
8. Phase 6: compatibility suite.
9. Phase 7: docs polish.

## Always-run gates before push

Use CodeBuild x86_64 as runtime authority:

```bash
git diff --check
go build ./cmd/dynamorio-sandbox
make docker-build
./codebuild-smoke/run_codebuild_smoke.sh
```

Local Apple Silicon Docker runtime failures under DynamoRIO are not release blockers if CodeBuild native x86_64 passes.

## Definition of done for this roadmap

- Existing evaluator owners can enable DR with one env/config switch.
- No new business/RPC protocol is introduced.
- stdout/stderr/stdin/argv/cwd/exit-code transparency is tested.
- Resource guards cover timeout, output, process tree, fd policy, network, exec, allocation budget.
- Audit/metrics are complete enough for debugging and never corrupt evaluator output.
- Docker and Lambda carriers share the same DR policy semantics.
- CodeBuild native x86_64 gate passes for every core behavior.
