#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static int expect_read_cap(void) {
    int fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/zero");
        return 1;
    }
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n == 4) {
        puts("read cap ok");
        return 0;
    }
    fprintf(stderr, "read cap failed: got %zd bytes\n", n);
    return 1;
}

static int expect_socket_block(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 && errno == ENETDOWN) {
        puts("socket block ok");
        return 0;
    }
    if (fd >= 0)
        close(fd);
    fprintf(stderr, "socket block failed: fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
    return 1;
}

static int expect_prot_exec_block(void) {
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    int rc = mprotect(p, 4096, PROT_READ | PROT_EXEC);
    int saved = errno;
    munmap(p, 4096);
    if (rc < 0 && saved == EPERM) {
        puts("prot_exec block ok");
        return 0;
    }
    fprintf(stderr, "prot_exec block failed: rc=%d errno=%d (%s)\n", rc, saved, strerror(saved));
    return 1;
}

static int expect_mmap_alloc_block(void) {
    size_t len = 2 * 1024 * 1024;
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int saved = errno;
    if (p == MAP_FAILED && saved == ENOMEM) {
        puts("mmap alloc block ok");
        return 0;
    }
    if (p != MAP_FAILED)
        munmap(p, len);
    fprintf(stderr, "mmap alloc block failed: p=%p errno=%d (%s)\n", p, saved, strerror(saved));
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s readcap|socket|prot_exec|mmap_alloc\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "readcap") == 0) return expect_read_cap();
    if (strcmp(argv[1], "socket") == 0) return expect_socket_block();
    if (strcmp(argv[1], "prot_exec") == 0) return expect_prot_exec_block();
    if (strcmp(argv[1], "mmap_alloc") == 0) return expect_mmap_alloc_block();
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
