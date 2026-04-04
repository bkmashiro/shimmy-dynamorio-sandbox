FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    wget \
    cmake \
    build-essential \
    gcc \
    g++ \
    make \
    libelf-dev \
    libunwind-dev \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install DynamoRIO
RUN wget -q https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-10.92.19975/DynamoRIO-Linux-10.92.19975.tar.gz \
    -O /tmp/dynamorio.tar.gz && \
    tar -xzf /tmp/dynamorio.tar.gz -C /opt && \
    mv /opt/DynamoRIO-Linux-10.92.19975 /opt/dynamorio && \
    rm /tmp/dynamorio.tar.gz

ENV DYNAMORIO_HOME=/opt/dynamorio
ENV PATH=$DYNAMORIO_HOME/bin64:$PATH

WORKDIR /sandbox

COPY . /sandbox/

RUN make client
