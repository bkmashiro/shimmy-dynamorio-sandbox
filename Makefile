# Makefile for DynamoRIO syscall virtualization prototype
#
# Targets:
#   client      – build syscall_filter.so (inside Docker)
#   test-prog   – build test_open/test_tmp_write static binaries (inside Docker)
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
MAX_MEM        ?= 256m
MAX_PROCS      ?= 5
DR_MODE        ?= observe
DR_REDIRECT_TMP ?= 1

.PHONY: all client test-prog docker-build docker-run demo smoke-private-tmp smoke-audit-jsonl smoke-dynamic-shell clean

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

test-prog: test_open test_tmp_write

test_open: test_open.c
	$(CC) -static -O2 -o $@ $<

test_tmp_write: test_tmp_write.c
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
	    --memory=$(MAX_MEM) \
	    --pids-limit=$(MAX_PROCS) \
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

## ── Go wrapper ──────────────────────────────────────────────────

go-build:
	cd cmd/dynamorio-sandbox && go build -o ../../bin/dynamorio-sandbox .

## ── cleanup ─────────────────────────────────────────────────────

clean:
	rm -f syscall_filter.so test_open bin/dynamorio-sandbox
	docker rmi -f $(IMAGE_NAME) 2>/dev/null || true
