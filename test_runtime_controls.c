#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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

static int expect_fd_write_policy(void) {
    const char *path = "/tmp/dr-fd-shadow-policy.txt";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open fd policy path");
        return 1;
    }
    ssize_t n = write(fd, "x", 1);
    int saved = errno;
    close(fd);
    unlink(path);
    if (n < 0 && saved == EPERM) {
        puts("fd write policy ok");
        return 0;
    }
    fprintf(stderr, "fd write policy failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

static int expect_fd_dup_write_policy(void) {
    const char *path = "/tmp/dr-fd-shadow-policy.txt";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open fd policy path");
        return 1;
    }
    int dupfd = dup(fd);
    if (dupfd < 0) {
        perror("dup fd policy path");
        close(fd);
        return 1;
    }
    ssize_t n = write(dupfd, "x", 1);
    int saved = errno;
    close(dupfd);
    close(fd);
    unlink(path);
    if (n < 0 && saved == EPERM) {
        puts("fd dup write policy ok");
        return 0;
    }
    fprintf(stderr, "fd dup write policy failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

static int expect_proc_fd_write_policy(void) {
    const char *path = "/tmp/dr-fd-shadow-policy.txt";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open fd policy path");
        return 1;
    }
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    int procfd = open(proc_path, O_WRONLY);
    if (procfd < 0) {
        perror("open /proc/self/fd/N");
        close(fd);
        unlink(path);
        return 1;
    }
    ssize_t n = write(procfd, "x", 1);
    int saved = errno;
    close(procfd);
    close(fd);
    unlink(path);
    if (n < 0 && saved == EPERM) {
        puts("proc fd write policy ok");
        return 0;
    }
    fprintf(stderr, "proc fd write policy failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

static int connect_to_ipv4(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 2;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return 2;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}

static int expect_network_policy(void) {
    int rc = connect_to_ipv4("1.1.1.1", 80);
    int saved = errno;
    if (!(rc < 0 && saved == ENETDOWN)) {
        fprintf(stderr, "network policy block failed: rc=%d errno=%d (%s)\n", rc, saved, strerror(saved));
        return 1;
    }

    rc = connect_to_ipv4("127.0.0.1", 9);
    saved = errno;
    if (rc < 0 && saved == ENETDOWN) {
        fprintf(stderr, "network policy allow failed: localhost was blocked\n");
        return 1;
    }
    puts("network policy ok");
    return 0;
}

static int expect_network_ipv6_policy(void) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket6");
        return 1;
    }
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(9);
    if (inet_pton(AF_INET6, "::1", &addr.sin6_addr) != 1) {
        close(fd);
        return 1;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    close(fd);
    if (rc < 0 && saved == ENETDOWN) {
        puts("network ipv6 policy ok");
        return 0;
    }
    fprintf(stderr, "network ipv6 policy failed: rc=%d errno=%d (%s)\n", rc, saved, strerror(saved));
    return 1;
}

static int expect_network_udp_policy(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("udp socket");
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);
    ssize_t n = sendto(fd, "x", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    close(fd);
    if (n < 0 && saved == ENETDOWN) {
        puts("network udp policy ok");
        return 0;
    }
    fprintf(stderr, "network udp policy failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

static int expect_stdout_limit(void) {
    ssize_t n = write(STDOUT_FILENO, "12345678", 8);
    int saved = errno;
    if (n < 0 && saved == EFBIG)
        return 0;
    fprintf(stderr, "stdout limit failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

static int expect_stderr_limit(void) {
    ssize_t n = write(STDERR_FILENO, "12345678", 8);
    int saved = errno;
    if (n < 0 && saved == EFBIG) {
        puts("stderr limit ok");
        return 0;
    }
    fprintf(stderr, "stderr limit failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

static int expect_cpu_timeout(void) {
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/null");
        return 1;
    }
    usleep(50000);
    char buf[1];
    ssize_t n = read(fd, buf, sizeof(buf));
    int saved = errno;
    close(fd);
    if (n < 0 && saved == ETIMEDOUT) {
        puts("cpu timeout ok");
        return 0;
    }
    fprintf(stderr, "cpu timeout failed: n=%zd errno=%d (%s)\n", n, saved, strerror(saved));
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s readcap|socket|prot_exec|mmap_alloc|fd_write_policy|fd_dup_write_policy|proc_fd_write_policy|network_policy|network_ipv6_policy|network_udp_policy|stdout_limit|stderr_limit|cpu_timeout\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "readcap") == 0) return expect_read_cap();
    if (strcmp(argv[1], "socket") == 0) return expect_socket_block();
    if (strcmp(argv[1], "prot_exec") == 0) return expect_prot_exec_block();
    if (strcmp(argv[1], "mmap_alloc") == 0) return expect_mmap_alloc_block();
    if (strcmp(argv[1], "fd_write_policy") == 0) return expect_fd_write_policy();
    if (strcmp(argv[1], "fd_dup_write_policy") == 0) return expect_fd_dup_write_policy();
    if (strcmp(argv[1], "proc_fd_write_policy") == 0) return expect_proc_fd_write_policy();
    if (strcmp(argv[1], "network_policy") == 0) return expect_network_policy();
    if (strcmp(argv[1], "network_ipv6_policy") == 0) return expect_network_ipv6_policy();
    if (strcmp(argv[1], "network_udp_policy") == 0) return expect_network_udp_policy();
    if (strcmp(argv[1], "stdout_limit") == 0) return expect_stdout_limit();
    if (strcmp(argv[1], "stderr_limit") == 0) return expect_stderr_limit();
    if (strcmp(argv[1], "cpu_timeout") == 0) return expect_cpu_timeout();
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
