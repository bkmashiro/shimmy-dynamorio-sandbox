/*
 * Test program: exercises a small private /tmp VFS lifecycle.
 * A host/container-side smoke also verifies that no original /tmp side effect
 * remains and that the redirected scratch file exists.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#define TMP_DIR      "/tmp/shimmy-dr-vfs"
#define TMP_PATH     "/tmp/shimmy-dr-vfs/side-effect.txt"
#define TMP_RENAMED  "/tmp/shimmy-dr-vfs/renamed.txt"

static int fail(const char *step)
{
    printf("test_tmp_write: %s failed errno=%d (%s)\n", step, errno, strerror(errno));
    return 1;
}

int main(void)
{
    const char *payload = "shimmy-dynamorio-private-tmp\n";
    char buf[128];

    if (mkdir(TMP_DIR, 0700) != 0 && errno != EEXIST)
        return fail("mkdir");

    int fd = open(TMP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return fail("open-write");
    ssize_t n = write(fd, payload, strlen(payload));
    if (n != (ssize_t)strlen(payload)) {
        close(fd);
        return fail("write");
    }
    if (close(fd) != 0)
        return fail("close-write");

    if (access(TMP_PATH, F_OK) != 0)
        return fail("access");

    fd = open(TMP_PATH, O_RDONLY);
    if (fd < 0)
        return fail("open-read");
    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        close(fd);
        return fail("read");
    }
    if (close(fd) != 0)
        return fail("close-read");
    if (strcmp(buf, payload) != 0) {
        printf("test_tmp_write: payload mismatch got=%s\n", buf);
        return 2;
    }

    if (rename(TMP_PATH, TMP_RENAMED) != 0)
        return fail("rename");
    if (unlink(TMP_RENAMED) != 0)
        return fail("unlink");
    if (rmdir(TMP_DIR) != 0)
        return fail("rmdir");

    printf("test_tmp_write: private tmp VFS lifecycle passed\n");
    return 0;
}
