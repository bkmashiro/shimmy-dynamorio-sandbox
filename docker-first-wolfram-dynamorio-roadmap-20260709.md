# Docker-first DynamoRIO policy layer for Wolfram/LambdaFeedback-style runtimes

Date: 2026-07-09

## Current direction

The target is no longer “make Wolfram run inside AWS Lambda.” The target is a regular Docker/container runtime closer to LambdaFeedback's real Google-cloud deployment. DynamoRIO should be used as a transparent, configurable syscall/policy layer around that runtime.

Priority order:

1. **Correct transparent execution** under DynamoRIO.
2. **Observe mode** audit logs for filesystem/process/network behavior.
3. **Disposable side effects** through per-run private scratch paths, starting with ordinary `/tmp`, `/var/tmp`, `$HOME/.Wolfram`, and cache paths, while preserving shared rendezvous paths such as `/tmp/MathLink` and `/dev/shm`.
4. Enforce/deny profiles only after traces show what a real runtime needs.
5. Cold/warm timing only after correctness is stable; memory snapshot/restore is out of scope for now.

## Implemented slice: observe mode + private tmp smoke

`proto-d-dynamorio/syscall_filter.c` now has two modes:

- `DR_SANDBOX_MODE=observe` — compatibility-first mode. It logs syscalls, passes most calls through, and can redirect selected private writable paths.
- `DR_SANDBOX_MODE=strict` / `enforce` — original deny-by-default prototype behavior.

`DR_REDIRECT_TMP=1` enables private path redirection for opens and common path syscalls (`mkdir`, `access`, `stat`, `rename`, `unlink`, `rmdir`, plus `*at` variants) under:

- ordinary `/tmp`
- `/var/tmp`
- paths containing `/.Wolfram`
- paths containing `/.cache`

`/tmp/MathLink` and `/dev/shm` are deliberately left pass-through in observe mode because the Wolfram evaluator uses them for MathLink/shared-memory rendezvous between child processes. Blanket-remapping them can break the evaluator before useful policy evidence is collected.

The redirected path is under:

```text
/tmp/dr-sandbox/<session-id>/...
```

`DR_AUDIT_JSONL=1` emits machine-readable JSONL audit events for path/syscall observations. This is the feed for deriving later candidate policies from real Wolfram traces instead of hand-guessing syscall allowlists.

## Verification

Local Docker Desktop on Apple Silicon is useful for building the image but **not** for running the x86_64 DynamoRIO runtime. `drrun` crashes under amd64 emulation there, even without a client. Runtime gates must run on native x86_64 Linux or CodeBuild.

Verified on AWS CodeBuild native x86_64 Linux:

```text
BUILD_ID=shimmy-dynamorio-docker-smoke:fc9f0ac4-8f04-44e9-8c85-b20bf2166f08
status=passed
checks:
  - make docker-build
  - make smoke-private-tmp
  - make smoke-audit-jsonl
  - make smoke-wolfram-path-policy
  - make smoke-dynamic-shell
  - make demo
```

Important observed smoke output:

```text
[dr-sandbox][tmp-smoke] mode=observe redirect_tmp=true audit_jsonl=false
[dr-sandbox][tmp-smoke] REMAP mkdir syscall=83 param=0: /tmp/shimmy-dr-vfs -> /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs
[dr-sandbox][tmp-smoke] REMAP private open: /tmp/shimmy-dr-vfs/side-effect.txt -> /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs/side-effect.txt flags=0x241
[dr-sandbox][tmp-smoke] REMAP rename-old syscall=82 param=0: /tmp/shimmy-dr-vfs/side-effect.txt -> /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs/side-effect.txt
[dr-sandbox][tmp-smoke] REMAP path syscall=87 param=0: /tmp/shimmy-dr-vfs/renamed.txt -> /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs/renamed.txt
```

The smoke asserted:

- original `/tmp/shimmy-dr-vfs` did not exist after the run;
- redirected `/tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs` was also removed after the private VFS lifecycle;
- `DR_AUDIT_JSONL=1` produced parseable/remappable JSONL evidence (`audit jsonl ok 12`);
- the Wolfram-style path policy smoke preserved `/tmp/MathLink` and `/dev/shm` while still remapping an ordinary `/tmp` file, and validated the separate `DR_AUDIT_PATH` JSONL file;
- a real dynamic `/bin/bash` process ran under observe mode and produced a much larger audit trace (`dynamic shell ok 322`).

Strict-mode legacy smoke also passed:

```text
[dr-sandbox][demo-session] BLOCK open: /etc/passwd
test_open: open() returned EPERM (errno=1) - correctly blocked!
```

## Next executable slices

1. Feed the JSONL audit output from real Wolfram traces into a candidate profile summarizer.
2. Re-run the Wolfram/LambdaFeedback Docker probe with a licensing environment that makes the evaluator baseline pass, then promote evaluator parity to required.
3. Expand private path coverage beyond temp/cache if Wolfram traces reveal other mutable state roots.
4. Only after correctness: collect rough cold container vs warm process timing.

The first Docker Wolfram/LambdaFeedback probe skeleton now lives under `probe-docker/wolfram-lf-dynamorio-observe/`; the first required-gate run passed launcher parity (`wolframscript -version`) and produced JSONL audit rows, while evaluator startup failed equally with and without DR due to missing activation/license in generic CI.

## Non-goals unless explicitly requested

- AWS Lambda porting.
- CRIU/Firecracker/memory snapshot restore.
- Full malicious-code security boundary using DynamoRIO alone. Docker/container remains the outer boundary; DR is the transparent policy/virtualization layer.
