# Makefile for DynamoRIO syscall virtualization prototype
#
# Targets:
#   client      – build syscall_filter.so (inside Docker)
#   test-prog   – build test_open static binary (inside Docker)
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

.PHONY: all client test-prog docker-build docker-run demo clean

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

test-prog: test_open

test_open: test_open.c
	$(CC) -static -O2 -o $@ $<

## ── Docker targets ──────────────────────────────────────────────

docker-build:
	docker build -t $(IMAGE_NAME) .

# Run an arbitrary command under DynamoRIO in a fresh sandbox session.
# Usage:  make docker-run EXEC=/bin/ls EXEC_ARGS="/tmp"
docker-run:
	docker run --rm \
	    -e DR_SESSION_ID=$(SESSION_ID) \
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
demo: docker-build
	@echo "=== Running test_open WITHOUT DynamoRIO ==="
	docker run --rm $(IMAGE_NAME) /opt/sandbox/test_open
	@echo ""
	@echo "=== Running test_open WITH DynamoRIO (syscall virtualization) ==="
	docker run --rm \
	    -e DR_SESSION_ID=demo-session \
	    --security-opt seccomp=unconfined \
	    $(IMAGE_NAME) \
	    $(DYNAMORIO_HOME)/bin64/drrun \
	        -c /opt/sandbox/syscall_filter.so \
	        -- /opt/sandbox/test_open

## ── Go wrapper ──────────────────────────────────────────────────

go-build:
	cd cmd/dynamorio-sandbox && go build -o ../../bin/dynamorio-sandbox .

## ── cleanup ─────────────────────────────────────────────────────

clean:
	rm -f syscall_filter.so test_open bin/dynamorio-sandbox
	docker rmi -f $(IMAGE_NAME) 2>/dev/null || true
