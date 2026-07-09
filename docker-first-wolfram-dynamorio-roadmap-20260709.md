# Docker-first DynamoRIO policy layer for Wolfram/LambdaFeedback-style runtimes

Date: 2026-07-09

## Current direction

The target is no longer “make Wolfram run inside AWS Lambda.” The target is a regular Docker/container runtime closer to LambdaFeedback's real Google-cloud deployment. DynamoRIO should be used as a transparent, configurable syscall/policy layer around that runtime.

Priority order:

1. **Correct transparent execution** under DynamoRIO.
2. **Observe mode** audit logs for filesystem/process/network behavior.
3. **Disposable side effects** through per-run private scratch paths, starting with `/tmp`, `/var/tmp`, `$HOME/.Wolfram`, and cache paths.
4. Enforce/deny profiles only after traces show what a real runtime needs.
5. Cold/warm timing only after correctness is stable; memory snapshot/restore is out of scope for now.

## Implemented slice: observe mode + private tmp smoke

`proto-d-dynamorio/syscall_filter.c` now has two modes:

- `DR_SANDBOX_MODE=observe` — compatibility-first mode. It logs syscalls, passes most calls through, and can redirect selected private writable paths.
- `DR_SANDBOX_MODE=strict` / `enforce` — original deny-by-default prototype behavior.

`DR_REDIRECT_TMP=1` enables private path redirection for opens and common path syscalls (`mkdir`, `access`, `stat`, `rename`, `unlink`, `rmdir`, plus `*at` variants) under:

- `/tmp`
- `/var/tmp`
- paths containing `/.Wolfram`
- paths containing `/.cache`

The redirected path is under:

```text
/tmp/dr-sandbox/<session-id>/...
```

`DR_AUDIT_JSONL=1` emits machine-readable JSONL audit events for path/syscall observations. This is the feed for deriving later candidate policies from real Wolfram traces instead of hand-guessing syscall allowlists.

## Verification

Local Docker Desktop on Apple Silicon is useful for building the image but **not** for running the x86_64 DynamoRIO runtime. `drrun` crashes under amd64 emulation there, even without a client. Runtime gates must run on native x86_64 Linux or CodeBuild.

Verified on AWS CodeBuild native x86_64 Linux:

```text
BUILD_ID=shimmy-dynamorio-docker-smoke:baac6a86-7237-4ceb-bf57-e178b7fa94b4
status=passed
checks:
  - make docker-build
  - make smoke-private-tmp
  - make smoke-audit-jsonl
  - make demo
```

Important observed smoke output:

```text
[dr-sandbox][tmp-smoke] mode=observe redirect_tmp=true
[dr-sandbox][tmp-smoke] REMAP private-write open: /tmp/shimmy-dr-tmp-side-effect.txt -> /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-tmp-side-effect.txt flags=0x241
```

The smoke asserted:

- original `/tmp/shimmy-dr-tmp-side-effect.txt` did not exist after the run;
- redirected `/tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-tmp-side-effect.txt` did exist.

Strict-mode legacy smoke also passed:

```text
[dr-sandbox][demo-session] BLOCK open: /etc/passwd
test_open: open() returned EPERM (errno=1) - correctly blocked!
```

## Next executable slices

1. Add observe-mode path handling for `statx`, `newfstatat`, `access/faccessat`, `mkdirat`, `unlinkat`, `renameat`, and `readlinkat` so virtual paths have a coherent view, not only write-open remapping.
2. Add an audit log format that can be consumed as JSONL or summarized into a candidate policy profile.
3. Add a Docker smoke that runs a non-trivial dynamic executable under observe mode (`python3 -c`, package import, cache write) before trying Wolfram.
4. Add a Wolfram/LambdaFeedback Docker probe that compares no-DR vs DR observe mode for the same handler input/output.
5. Only after correctness: collect rough cold container vs warm process timing.

## Non-goals unless explicitly requested

- AWS Lambda porting.
- CRIU/Firecracker/memory snapshot restore.
- Full malicious-code security boundary using DynamoRIO alone. Docker/container remains the outer boundary; DR is the transparent policy/virtualization layer.
