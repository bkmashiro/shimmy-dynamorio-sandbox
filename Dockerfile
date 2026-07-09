# DynamoRIO Syscall Virtualization Sandbox
# Build: docker build -t dynamorio-sandbox .
# Run:   docker run --rm -e DR_SESSION_ID=my-session dynamorio-sandbox \
#            /opt/dynamorio/bin64/drrun -c /opt/sandbox/syscall_filter.so \
#            -- /opt/sandbox/test_open

FROM --platform=linux/amd64 ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        wget \
        ca-certificates \
        libunwind-dev \
        && rm -rf /var/lib/apt/lists/*

# Download and install DynamoRIO
ENV DYNAMORIO_VERSION=11.91.20545
ENV DYNAMORIO_HOME=/opt/dynamorio

RUN wget -q "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-${DYNAMORIO_VERSION}/DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz" \
        -O /tmp/dynamorio.tar.gz && \
    mkdir -p ${DYNAMORIO_HOME} && \
    tar -xzf /tmp/dynamorio.tar.gz -C ${DYNAMORIO_HOME} --strip-components=1 && \
    rm /tmp/dynamorio.tar.gz

WORKDIR /build
COPY syscall_filter.c test_open.c test_tmp_write.c test_runtime_controls.c Makefile ./

# Build client + test binaries.
# DynamoRIO v11: libdrcontainers moved to ext/lib64/release; requires -DLINUX -DX86_64.
RUN DR=${DYNAMORIO_HOME} && \
    gcc -shared -fPIC -O2 -Wall -Wextra \
        -DLINUX -DX86_64 -include stdint.h \
        -I${DR}/include -I${DR}/ext/include \
        -Wl,-rpath,${DR}/lib64 \
        -o syscall_filter.so syscall_filter.c \
        -L${DR}/lib64/release -ldynamorio \
        -L${DR}/ext/lib64/release -ldrcontainers && \
    gcc -static -O2 -o test_open test_open.c && \
    gcc -static -O2 -o test_tmp_write test_tmp_write.c && \
    gcc -static -O2 -o test_runtime_controls test_runtime_controls.c

# ── Runtime image ──────────────────────────────────────────────
FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libunwind8 \
        && rm -rf /var/lib/apt/lists/*

ENV DYNAMORIO_HOME=/opt/dynamorio

# Copy DynamoRIO runtime
COPY --from=builder /opt/dynamorio /opt/dynamorio

# Copy our built artifacts
COPY --from=builder /build/syscall_filter.so /opt/sandbox/syscall_filter.so
COPY --from=builder /build/test_open         /opt/sandbox/test_open
COPY --from=builder /build/test_tmp_write    /opt/sandbox/test_tmp_write
COPY --from=builder /build/test_runtime_controls /opt/sandbox/test_runtime_controls

# Ensure sandbox base dir exists
RUN mkdir -p /tmp/dr-sandbox

# Default: show usage
CMD ["bash", "-c", \
     "echo 'Usage: docker run --rm -e DR_SESSION_ID=<id> dynamorio-sandbox \\'; \
      echo '           /opt/dynamorio/bin64/drrun -c /opt/sandbox/syscall_filter.so -- <program>'"]
