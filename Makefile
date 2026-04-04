# DynamoRIO Syscall Filter Client Makefile
DYNAMORIO_HOME ?= /opt/dynamorio

CC = gcc
CFLAGS = -fPIC -shared -O2 -Wall \
    -I$(DYNAMORIO_HOME)/include \
    -I$(DYNAMORIO_HOME)/ext/include

LDFLAGS = -L$(DYNAMORIO_HOME)/lib64/release \
    -ldynamorio \
    -Wl,-rpath,$(DYNAMORIO_HOME)/lib64/release

TARGET = syscall_filter.so

.PHONY: all client clean test-prog

all: client test-prog

client: $(TARGET)

$(TARGET): syscall_filter.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build a simple test program that tries to open() a file
test-prog: test_open.c
	$(CC) -static -o test_open test_open.c

clean:
	rm -f $(TARGET) test_open
