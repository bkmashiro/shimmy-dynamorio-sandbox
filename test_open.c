/*
 * Test program: attempts to open() a file.
 * When run under syscall_filter, the open() call should be blocked
 * with EPERM since open (sysnum=2) is not in the allowlist.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    printf("test_open: attempting open(\"/etc/passwd\", O_RDONLY)...\n");
    fflush(stdout);

    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        if (errno == EPERM) {
            printf("test_open: open() returned EPERM (errno=1) - correctly blocked!\n");
            return 0;
        } else {
            printf("test_open: open() failed with errno=%d (%s)\n", errno, strerror(errno));
            return 1;
        }
    }

    printf("test_open: open() SUCCEEDED with fd=%d - NOT blocked (unexpected)\n", fd);
    close(fd);
    return 0;
}
