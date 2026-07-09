# Makefile for DynamoRIO syscall virtualization prototype
#
# Targets:
#   client      – build syscall_filter.so (inside Docker)
#   test-prog   – build test_open/test_tmp_write/test_runtime_controls static binaries (inside Docker)
#   docker-build – build the Docker image
#   docker-run   – run a command under DynamoRIO in Docker
#   demo        – full end-to-end demo
#   clean       – remove artifacts

DYNAMORIO_HOME ?= /opt/dynamorio
CC             := gcc
CFLAGS         := -shared -fPIC -O2 -Wall -Wextra \
                  -I$(DYNAMORIO_HOME)/include \
                  -I$(DYNAMORIO_HOME)/ext/include

IMAGE_NAME     ?= dynamorio-sandbox
SESSION_ID     ?= $(shell cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "session-$(shell date +%s)")
EXEC           ?= /bin/echo
EXEC_ARGS      ?= hello from sandbox
TIMEOUT        ?= 30
DR_MODE        ?= observe
DR_REDIRECT_TMP ?= 1
DR_PATH_POLICY ?=
DR_NETWORK     ?=
DR_NETWORK_POLICY ?=
DR_EXEC        ?=
DR_PROT_EXEC   ?=
DR_FILE_WRITE  ?=
DR_FD_WRITE_POLICY ?=
DR_SEMANTIC_AUDIT ?=
DR_MAX_READ_BYTES ?=
DR_MAX_ALLOC_BYTES ?=
DR_MAX_PROCS   ?=

.PHONY: all client test-prog docker-build docker-run demo smoke-private-tmp smoke-audit-jsonl smoke-dynamic-shell smoke-wolfram-path-policy smoke-policy-config smoke-runtime-config clean

all: client test-prog

## ── in-container build targets (called by Dockerfile) ──────────

client: syscall_filter.so

syscall_filter.so: syscall_filter.c
	$(CC) $(CFLAGS) \
	    -ldrcontainers \
	    -Wl,-rpath,$(DYNAMORIO_HOME)/lib64 \
	    -o $@ $< \
	    -L$(DYNAMORIO_HOME)/lib64/release \
	    -ldynamorio

test-prog: test_open test_tmp_write test_runtime_controls

test_open: test_open.c
	$(CC) -static -O2 -o $@ $<

test_tmp_write: test_tmp_write.c
	$(CC) -static -O2 -o $@ $<

test_runtime_controls: test_runtime_controls.c
	$(CC) -static -O2 -o $@ $<

## ── Docker targets ──────────────────────────────────────────────

docker-build:
	docker build -t $(IMAGE_NAME) .

# Run an arbitrary command under DynamoRIO in a fresh sandbox session.
# Usage:  make docker-run EXEC=/bin/ls EXEC_ARGS="/tmp"
docker-run:
	docker run --rm \
	    -e DR_SESSION_ID=$(SESSION_ID) \
	    -e DR_SANDBOX_MODE=$(DR_MODE) \
	    -e DR_REDIRECT_TMP=$(DR_REDIRECT_TMP) \
	    -e DR_PATH_POLICY='$(DR_PATH_POLICY)' \
	    -e DR_NETWORK='$(DR_NETWORK)' \
	    -e DR_NETWORK_POLICY='$(DR_NETWORK_POLICY)' \
	    -e DR_EXEC='$(DR_EXEC)' \
	    -e DR_PROT_EXEC='$(DR_PROT_EXEC)' \
	    -e DR_FILE_WRITE='$(DR_FILE_WRITE)' \
	    -e DR_FD_WRITE_POLICY='$(DR_FD_WRITE_POLICY)' \
	    -e DR_SEMANTIC_AUDIT='$(DR_SEMANTIC_AUDIT)' \
	    -e DR_MAX_READ_BYTES='$(DR_MAX_READ_BYTES)' \
	    -e DR_MAX_ALLOC_BYTES='$(DR_MAX_ALLOC_BYTES)' \
	    -e DR_MAX_PROCS='$(DR_MAX_PROCS)' \
	    --security-opt seccomp=unconfined \
	    --cap-drop ALL \
	    $(IMAGE_NAME) \
	    timeout $(TIMEOUT) \
	    $(DYNAMORIO_HOME)/bin64/drrun \
	        -c /opt/sandbox/syscall_filter.so \
	        -- $(EXEC) $(EXEC_ARGS)

# Run the built-in test binary
# NOTE: DynamoRIO x86_64 currently crashes under Docker Desktop's amd64-on-arm64
# emulation on Apple Silicon. Use this on native x86_64 Linux or CodeBuild.
demo: docker-build
	@echo "=== Running test_open WITHOUT DynamoRIO ==="
	docker run --rm $(IMAGE_NAME) /opt/sandbox/test_open
	@echo ""
	@echo "=== Running test_open WITH DynamoRIO strict mode (syscall virtualization) ==="
	docker run --rm \
	    -e DR_SESSION_ID=demo-session \
	    -e DR_SANDBOX_MODE=strict \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun \
	        -c /opt/sandbox/syscall_filter.so \
	        -- /opt/sandbox/test_open

# Verify observe-mode private tmp redirection. Intended for native x86_64 Linux
# or CodeBuild; Docker Desktop's amd64 emulation is not a valid DR runtime gate.
smoke-private-tmp: docker-build
	docker run --rm \
	    -e DR_SESSION_ID=tmp-smoke \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_REDIRECT_TMP=1 \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    bash -lc 'rm -rf /tmp/shimmy-dr-vfs /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs; $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_tmp_write; test ! -e /tmp/shimmy-dr-vfs; test ! -e /tmp/dr-sandbox/tmp-smoke/tmp/shimmy-dr-vfs'

# Verify machine-readable JSONL audit output for downstream profile generation.
smoke-audit-jsonl: docker-build
	docker run --rm \
	    -e DR_SESSION_ID=audit-smoke \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_REDIRECT_TMP=1 \
	    -e DR_AUDIT_JSONL=1 \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    bash -lc 'rm -rf /tmp/shimmy-dr-vfs /tmp/dr-sandbox/audit-smoke/tmp/shimmy-dr-vfs; $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_tmp_write 2>/tmp/audit.log; grep -q "^{\"type\":\"path\"" /tmp/audit.log; grep -q "\"action\":\"remap\"" /tmp/audit.log; grep -q "\"path\":\"/tmp/shimmy-dr-vfs\"" /tmp/audit.log; grep -q "\"path\":\"/tmp/shimmy-dr-vfs/side-effect.txt\"" /tmp/audit.log; grep -q "\"remapped\":\"/tmp/dr-sandbox/audit-smoke/" /tmp/audit.log; echo audit jsonl ok $$(grep -c "^{" /tmp/audit.log)'

# Wolfram-style path policy smoke: MathLink and shared-memory rendezvous paths
# must stay shared/pass-through, while ordinary /tmp writes remain private.
smoke-wolfram-path-policy: docker-build
	docker run --rm \
	    -e DR_SESSION_ID=wolfram-path \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_REDIRECT_TMP=1 \
	    -e DR_AUDIT_JSONL=1 \
	    -e DR_AUDIT_PATH=/tmp/dr-audit.jsonl \
	    -e DR_HUMAN_LOG=0 \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    bash -lc 'rm -rf /tmp/shimmy-dr-normal /tmp/MathLink /tmp/dr-sandbox/wolfram-path /tmp/dr-audit.jsonl; mkdir -p /tmp/MathLink; $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /bin/bash -lc "printf normal >/tmp/shimmy-dr-normal && printf link >/tmp/MathLink/ml-test.rec && printf shm >/dev/shm/shimmy-dr-shm-test"; test ! -e /tmp/shimmy-dr-normal; test -f /tmp/MathLink/ml-test.rec; test -f /dev/shm/shimmy-dr-shm-test; grep -q "\"path\":\"/tmp/shimmy-dr-normal\"" /tmp/dr-audit.jsonl; grep -q "\"remapped\":\"/tmp/dr-sandbox/wolfram-path/tmp/shimmy-dr-normal\"" /tmp/dr-audit.jsonl; grep -q "\"path\":\"/tmp/MathLink/ml-test.rec\"" /tmp/dr-audit.jsonl; ! grep -q "\"remapped\":\"/tmp/dr-sandbox/wolfram-path/tmp/MathLink" /tmp/dr-audit.jsonl; grep -q "\"path\":\"/dev/shm/shimmy-dr-shm-test\"" /tmp/dr-audit.jsonl; ! grep -q "\"remapped\":\"/tmp/dr-sandbox/wolfram-path/dev/shm" /tmp/dr-audit.jsonl; python3 -c "import json; [json.loads(line) for line in open(\"/tmp/dr-audit.jsonl\")]"; rm -f /tmp/MathLink/ml-test.rec /dev/shm/shimmy-dr-shm-test; echo wolfram path policy ok $$(wc -l </tmp/dr-audit.jsonl)'

# Dynamic-loader smoke: run a real dynamic /bin/bash process under observe mode.
smoke-dynamic-shell: docker-build
	docker run --rm \
	    -e DR_SESSION_ID=dynamic-shell \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_REDIRECT_TMP=1 \
	    -e DR_AUDIT_JSONL=1 \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    bash -lc 'rm -rf /tmp/shimmy-dr-dynamic /tmp/dr-sandbox/dynamic-shell/tmp/shimmy-dr-dynamic; $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /bin/bash -lc "mkdir -p /tmp/shimmy-dr-dynamic/cache && printf dynamic >/tmp/shimmy-dr-dynamic/cache/value.txt && test -f /tmp/shimmy-dr-dynamic/cache/value.txt && grep -q dynamic /tmp/shimmy-dr-dynamic/cache/value.txt && mv /tmp/shimmy-dr-dynamic/cache/value.txt /tmp/shimmy-dr-dynamic/cache/value2.txt && rm /tmp/shimmy-dr-dynamic/cache/value2.txt && rmdir /tmp/shimmy-dr-dynamic/cache && rmdir /tmp/shimmy-dr-dynamic" 2>/tmp/dynamic-audit.log; test ! -e /tmp/shimmy-dr-dynamic; grep -q "\"path\":\"/tmp/shimmy-dr-dynamic/cache/value.txt\"" /tmp/dynamic-audit.log; echo dynamic shell ok $$(grep -c "^{" /tmp/dynamic-audit.log)'

# Configurable path policy smoke: first-match DR_PATH_POLICY rules can make
# arbitrary roots read-only, shared read-write, private/remapped, or blocked.
smoke-policy-config: docker-build
	docker run --rm \
	    -e DR_SESSION_ID=policy-config \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_REDIRECT_TMP=0 \
	    -e DR_AUDIT_JSONL=1 \
	    -e DR_AUDIT_PATH=/tmp/dr-policy-audit.jsonl \
	    -e DR_HUMAN_LOG=0 \
	    -e 'DR_PATH_POLICY=ro:/tmp/dr-ro;rw:/tmp/dr-rw;private:/tmp/dr-private;block:/tmp/dr-block' \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    bash -euo pipefail -lc 'rm -rf /tmp/dr-ro /tmp/dr-rw /tmp/dr-private /tmp/dr-block /tmp/dr-sandbox/policy-config /tmp/dr-policy-audit.jsonl; mkdir -p /tmp/dr-ro /tmp/dr-rw /tmp/dr-private /tmp/dr-block; printf readable >/tmp/dr-ro/input.txt; printf secret >/tmp/dr-block/input.txt; $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /bin/bash -lc "grep -q readable /tmp/dr-ro/input.txt && ! printf nope >/tmp/dr-ro/out.txt && printf shared >/tmp/dr-rw/out.txt && printf private >/tmp/dr-private/out.txt && ! cat /tmp/dr-block/input.txt >/dev/null"; grep -q shared /tmp/dr-rw/out.txt; test ! -e /tmp/dr-private/out.txt; grep -q private /tmp/dr-sandbox/policy-config/tmp/dr-private/out.txt; grep -q "\"action\":\"readonly\"" /tmp/dr-policy-audit.jsonl; grep -q "\"action\":\"block\"" /tmp/dr-policy-audit.jsonl; grep -q "\"action\":\"remap\"" /tmp/dr-policy-audit.jsonl; echo policy config ok $$(wc -l </tmp/dr-policy-audit.jsonl)'

# Runtime-control smoke: configurable traditional-sandbox style knobs for read
# caps, network syscalls, executable memory, and memory allocation work in
# observe mode too. These are DR controls, not Docker/kernel resource limits.
smoke-runtime-config: docker-build
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-read \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_REDIRECT_TMP=0 \
	    -e DR_MAX_READ_BYTES=4 \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls readcap
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-net \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_NETWORK=block \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls socket
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-protexec \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_PROT_EXEC=block \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls prot_exec
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-alloc \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_MAX_ALLOC_BYTES=1m \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls mmap_alloc
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-fd \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_FD_WRITE_POLICY=block:/tmp/dr-fd-shadow-policy.txt \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls fd_write_policy
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-netpolicy \
	    -e DR_SANDBOX_MODE=observe \
	    -e 'DR_NETWORK_POLICY=allow:127.0.0.1:9;block:*' \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls network_policy
	docker run --rm \
	    -e DR_SESSION_ID=runtime-config-semaudit \
	    -e DR_SANDBOX_MODE=observe \
	    -e DR_FD_WRITE_POLICY=block:/tmp/dr-fd-shadow-policy.txt \
	    -e DR_SEMANTIC_AUDIT=1 \
	    -e DR_AUDIT_PATH=/tmp/dr-semantic-audit.jsonl \
	    -e DR_HUMAN_LOG=0 \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    bash -euo pipefail -lc 'rm -f /tmp/dr-semantic-audit.jsonl /tmp/dr-fd-shadow-policy.txt; $(DYNAMORIO_HOME)/bin64/drrun -c /opt/sandbox/syscall_filter.so -- /opt/sandbox/test_runtime_controls fd_write_policy; grep -q "\"type\":\"semantic\"" /tmp/dr-semantic-audit.jsonl; grep -q "\"name\":\"open\"" /tmp/dr-semantic-audit.jsonl; grep -q "\"name\":\"write\"" /tmp/dr-semantic-audit.jsonl; grep -q "\"action\":\"block\"" /tmp/dr-semantic-audit.jsonl; echo semantic audit ok $$(wc -l </tmp/dr-semantic-audit.jsonl)'

## ── Go wrapper ──────────────────────────────────────────────────

go-build:
	cd cmd/dynamorio-sandbox && go build -o ../../bin/dynamorio-sandbox .

## ── cleanup ─────────────────────────────────────────────────────

clean:
	rm -f syscall_filter.so test_open test_tmp_write test_runtime_controls bin/dynamorio-sandbox
	docker rmi -f $(IMAGE_NAME) 2>/dev/null || true
